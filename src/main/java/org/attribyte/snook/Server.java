/*
 * Copyright 2018 Attribyte, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

package org.attribyte.snook;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.health.HealthCheckRegistry;
import com.codahale.metrics.servlets.HealthCheckServlet;
import com.codahale.metrics.servlets.MetricsServlet;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.PropertyConfigurator;
import org.attribyte.api.InitializationException;
import org.attribyte.api.Logger;
import org.attribyte.util.InitUtil;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.NCSARequestLog;
import org.eclipse.jetty.server.RequestLog;
import org.eclipse.jetty.server.Slf4jRequestLog;
import org.eclipse.jetty.server.handler.AllowSymLinkAliasChecker;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.SecuredRedirectHandler;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.eclipse.jetty.servlet.DefaultServlet;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.component.LifeCycle;
import org.eclipse.jetty.util.resource.Resource;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.attribyte.snook.Util.commandLineParameters;

public abstract class Server {

   /**
    * Creates the server.
    * @param args The command line arguments.
    * @param propsResourceName The name of a resource that contains default properties.
    * @param loggerName The name of a logger.
    * @param withGzip Should auto-gzip handling be configured?
    * @throws Exception on configuration error.
    */
   protected Server(String[] args,
                    final String propsResourceName,
                    final String loggerName,
                    final boolean withGzip) throws Exception {

      Map<String, String> parameterMap = Maps.newHashMap();
      args = commandLineParameters(args, parameterMap);
      this.props = loadProperties(propsResourceName, args, parameterMap);
      PropertyConfigurator.configure(new InitUtil("log.", this.props).getProperties());
      final org.apache.log4j.Logger log4jLogger = org.apache.log4j.Logger.getLogger(loggerName);

      this.logger = new Logger() {

         public void debug(String msg) {
            log4jLogger.debug(msg);
         }

         public void info(String msg) {
            log4jLogger.info(msg);
         }

         public void warn(String msg) {
            log4jLogger.warn(msg);
         }

         public void warn(String msg, Throwable t) {
            log4jLogger.warn(msg, t);
         }

         public void error(String msg) {
            log4jLogger.error(msg);
         }

         public void error(String msg, Throwable t) {
            log4jLogger.error(msg, t);
         }
      };
      this.serverConfiguration = new ServerConfiguration("server.", props);
      this.debug = debug(this.serverConfiguration.debug);
      if(this.debug) {
         LogManager.getRootLogger().setLevel(Level.DEBUG);
         log4jLogger.setLevel(Level.DEBUG);
         System.out.println("Configuration...");
         System.out.println(this.serverConfiguration.toString());
      }
      this.httpServer = httpServer();
      this.rootContext = rootContext(withGzip);
      if(this.serverConfiguration.allowSymlinks) {
         this.rootContext.addAliasCheck(new AllowSymLinkAliasChecker());
      }

      initAssets();
   }

   /**
    * Loads the default properties from a resource.
    * @param resourceName The resource name. May be {@code null} or empty.
    * @return The default properties.
    * @throws IOException on load error.
    */
   private Properties loadDefaultProperties(final String resourceName) throws IOException {
      Properties props = new Properties();
      if(!Strings.isNullOrEmpty(resourceName)) {
         props.load(getClass().getResourceAsStream(resourceName));
      }
      return props;
   }

   /**
    * Loads properties from the specified files in sequence,
    * with properties in later files overriding those set previously.
    * All properties have defaults loaded from a resource in the classpath.
    * @param resourceName The name of a resource the holds property defaults.
    * @param filenames The filenames.
    * @param parameterMap A map of command line parameters that override properties loaded from files.
    * @return The loaded properties.
    * @throws IOException on load error or missing configuration file.
    */
   private Properties loadProperties(final String resourceName, final String[] filenames,
                                     final Map<String, String> parameterMap) throws IOException {

      Properties props = loadDefaultProperties(resourceName);

      for(String filename : filenames) {

         File f = new File(filename);

         if(!f.exists()) {
            throw new IOException(String.format("Start-up error: The configuration file, '%s' does not exist", f.getAbsolutePath()));
         }

         if(!f.canRead()) {
            throw new IOException(String.format("Start-up error: The configuration file, '%s' can't be read", f.getAbsolutePath()));
         }

         try(FileInputStream fis = new FileInputStream(f)) {
            Properties currProps = new Properties();
            currProps.load(fis);
            props.putAll(currProps);
         }
      }

      props.putAll(parameterMap);
      props = resolveEnvironmentVariables(props);
      return resolveRelativeFiles(props);
   }

   /**
    * Examines configuration keys for those that represent files/directories to add
    * system install path if not absolute. Keys that end with {@code .File} or {@code .Dir}
    * are treated as files/directories for this purpose.
    * @param props The properties.
    * @return The properties with modified values.
    * @throws IOException on filesystem error.
    */
   private Properties resolveRelativeFiles(final Properties props) throws IOException {

      Properties filteredProps = new Properties();
      File systemInstallDir = systemInstallDir();

      for(String key : props.stringPropertyNames()) {
         if(key.endsWith(".File") || key.endsWith(".Dir")) {
            String filename = props.getProperty(key).trim();
            if(filename.isEmpty() || filename.startsWith("/")) {
               filteredProps.put(key, filename);
            } else {
               filteredProps.put(key, new File(systemInstallDir, filename).getCanonicalPath());
            }
         } else {
            filteredProps.put(key, props.getProperty(key));
         }
      }
      return filteredProps;
   }

   /**
    * Examines configuration values for possible environment variables.
    * If a value starts with {@code $} and there is a matching variable
    * with that name in the environment, the value will be replaced by
    * the value from the environment. A default value to be used if
    * the environment variable is not set, e.g. {@code $DB_HOST||127.0.0.1}.
    * @param props The properties.
    * @return The properties with modified values.
    */
   private Properties resolveEnvironmentVariables(final Properties props) {
      Map<String, String> envVariables = System.getenv();
      Properties filteredProps = new Properties();
      props.forEach((key, origVal) -> {
         if(origVal.toString().startsWith("$")) {
            String envName = origVal.toString().substring(1).trim();
            List<String> envNameDefault = ENV_DEFAULT_VALUE_SPLITTER.splitToList(envName);
            String defaultValue = envNameDefault.size() > 1 ? envNameDefault.get(1) : origVal.toString();
            String val = envVariables.getOrDefault(envName, defaultValue);
            filteredProps.setProperty(key.toString(), val);
         } else {
            filteredProps.setProperty(key.toString(), origVal.toString());
         }
      });

      return filteredProps;
   }

   /**
    * Split default values specified with environment variables.
    */
   static final Splitter ENV_DEFAULT_VALUE_SPLITTER = Splitter.on("||").trimResults().limit(2);

   /**
    * The system property name that holds the install directory ({@value}).
    */
   public static final String INSTALL_DIR_SYSTEM_PROP = "server.install.dir";

   /**
    * Gets the system install directory.
    * @return The directory.
    */
   private static File systemInstallDir() {
      String systemInstallDir = System.getProperty(INSTALL_DIR_SYSTEM_PROP, "../config").trim();
      return new File(systemInstallDir);
   }

   /**
    * The system property name that holds the debug flag ({@value}).
    */
   public static final String DEBUG_SYSTEM_PROP = "server.debug";

   /**
    * Gets the debug mode.
    * @param defaultValue The default value.
    * @return The debug mode.
    */
   private static boolean debug(final boolean defaultValue) {
      return System.getProperty(DEBUG_SYSTEM_PROP, Boolean.toString(defaultValue)).equalsIgnoreCase("true");
   }


   /**
    * Logs an informational message to {@code System.out} and the logger, if configured.
    * @param message The message.
    */
   protected void logInfo(final String message) {
      System.out.println(message);
      if(logger != null) {
         logger.info(message);
      }
   }

   /**
    * Logs an error message to {@code System.err} and the logger, if configured.
    * @param message The message.
    */
   protected void logError(final String message) {
      System.err.println(message);
      if(logger != null) {
         logger.error(message);
      }
   }

   /**
    * Logs an error to {@code System.err} and the logger, if configured and prints the stack trace.
    * @param message The message.
    * @param t A throwable.
    */
   protected void logError(final String message, final Throwable t) {
      System.err.println(message);
      t.printStackTrace();
      if(logger != null) {
         logger.error(message, t);
      }
   }

   /**
    * Called on server shutdown.
    */
   protected abstract void shutdown();

   /**
    * Creates the configured HTTP server.
    * @return The server.
    */
   private org.eclipse.jetty.server.Server httpServer() {

      org.eclipse.jetty.server.Server httpServer = serverConfiguration.buildServer();

      httpServer.addLifeCycleListener(new LifeCycle.Listener() {
         public void lifeCycleFailure(LifeCycle event, Throwable cause) {
            logError("Failure", cause);
         }

         public void lifeCycleStarted(LifeCycle event) {
            logInfo("Started...");
         }

         public void lifeCycleStarting(LifeCycle event) {
            logInfo("Server Starting...");
         }

         public void lifeCycleStopped(LifeCycle event) {
            logInfo("Server Stopped...");
         }

         public void lifeCycleStopping(LifeCycle event) {
            logInfo("Stopping...");
            keyStoreMonitor.shutdown();
            shutdown();
         }
      });

      this.keyStoreMonitor.start(serverConfiguration, logger);

      RequestLog requestLog = initRequestLog();
      if(requestLog != null) {
         httpServer.setRequestLog(requestLog);
      }
      if(debug) {
         httpServer.setDumpAfterStart(true);
         httpServer.setDumpBeforeStop(true);
      }
      httpServer.setStopAtShutdown(true);
      return httpServer;
   }

   private ServletContextHandler rootContext(boolean withGzip) throws IOException {
      ServletContextHandler rootContext = new ServletContextHandler(ServletContextHandler.NO_SECURITY);
      rootContext.setContextPath("/");
      rootContext.setBaseResource(Resource.newResource("/"));
      rootContext.addAliasCheck(new ContextHandler.ApproveAliases());
      rootContext.setMaxFormContentSize(serverConfiguration.maxFormContentSize);
      boolean withSecureRedirect = serverConfiguration.connectionSecurity == ServerConfiguration.ConnectionSecurity.REDIRECT;
      if(withGzip) {
         GzipHandler gzip = new GzipHandler();
         if(withSecureRedirect) {
            HandlerList handlers = new HandlerList();
            handlers.setHandlers(new Handler[]{new SecuredRedirectHandler(), gzip});
            this.httpServer.setHandler(handlers);
         } else {
            this.httpServer.setHandler(gzip);
         }
         HandlerList handlers = new HandlerList();
         handlers.setHandlers(new Handler[]{rootContext});
         gzip.setHandler(handlers);
      } else if(withSecureRedirect) {
         HandlerList handlers = new HandlerList();
         handlers.setHandlers(new Handler[]{new SecuredRedirectHandler(), rootContext});
         this.httpServer.setHandler(handlers);
      } else {
         this.httpServer.setHandler(rootContext);
      }
      return rootContext;
   }

   /**
    * Initializes the server request logger.
    * @return The logger or {@code null} if none.
    */
   private RequestLog initRequestLog() {

      String requestLogPath = props.getProperty(REQUEST_LOG_DIRECTORY_PROPERTY, "").trim();
      if(requestLogPath.isEmpty()) {
         return null;
      }

      if(requestLogPath.equalsIgnoreCase("slf4j")) {
         return new Slf4jRequestLog();
      }

      if(!requestLogPath.endsWith("/")) {
         requestLogPath = requestLogPath + "/";
      }

      String requestLogBase = props.getProperty(REQUEST_LOG_BASE_PROPERTY, REQUEST_LOG_BASE_DEFAULT);

      int requestLogRetainDays = Integer.parseInt(props.getProperty(REQUEST_LOG_RETAIN_DAYS_PROPERTY, Integer.toString(REQUEST_LOG_RETAIN_DAYS_DEFAULT)));
      boolean requestLogExtendedFormat = props.getProperty(REQUEST_LOG_EXTENDED_PROPERTY, Boolean.toString(REQUEST_LOG_EXTENDED_DEFAULT)).equalsIgnoreCase("true");

      String requestLogTimeZone = props.getProperty(REQUEST_LOG_TIMEZONE_PROPERTY, TimeZone.getDefault().getID());

      NCSARequestLog requestLog = new NCSARequestLog(requestLogPath + requestLogBase + "-yyyy_mm_dd.request.log");
      requestLog.setRetainDays(requestLogRetainDays);
      requestLog.setAppend(true);
      requestLog.setExtended(requestLogExtendedFormat);
      requestLog.setLogTimeZone(requestLogTimeZone);
      requestLog.setLogCookies(false);
      requestLog.setPreferProxiedForAddress(true);
      return requestLog;
   }

   private void initAssets() throws InitializationException {
      InitUtil init = new InitUtil("assets.", props, false);
      Map<String, Properties> configProps = init.split();
      for(Map.Entry<String, Properties> entry : configProps.entrySet()) {

         System.out.println(entry.getValue().toString());

         String resourceDir = entry.getValue().getProperty("resource.Dir", "").trim();
         if(resourceDir.isEmpty()) {
            throw new InitializationException(String.format("A 'resource.Dir' must be specified for asset config, '%s'", entry.getKey()));
         }
         entry.getValue().setProperty(StaticAssetsConfig.RESOURCE_DIRECTORY_PROPERTY, resourceDir);

         String paths = entry.getValue().getProperty("paths", "").trim();
         if(paths.isEmpty()) {
            throw new InitializationException(String.format("The 'paths' must be specified for asset config, '%s'", entry.getKey()));
         }

         List<String> pathExpressionList = Splitter.on(',').omitEmptyStrings().trimResults().splitToList(paths);
         if(pathExpressionList.isEmpty()) {
            throw new InitializationException(String.format("The 'paths' must be specified for asset config, '%s'", entry.getKey()));
         }

         StaticAssetsConfig config = new StaticAssetsConfig("", entry.getValue());
         addStaticAssets(config, pathExpressionList);
      }
   }

   /**
    * The request log directory property name ({@value}).
    */
   public static final String REQUEST_LOG_DIRECTORY_PROPERTY = "requestLog.Dir";

   /**
    * The request log base name property name ({@value}).
    */
   public static final String REQUEST_LOG_BASE_PROPERTY = "requestLogBase";

   /**
    * The request log base default value ({@value}).
    */
   public static final String REQUEST_LOG_BASE_DEFAULT = "server";

   /**
    * The request log retain days property name ({@value}).
    */
   public static final String REQUEST_LOG_RETAIN_DAYS_PROPERTY = "requestLogRetainDays";

   /**
    * The default request log retain days ({@value}).
    */
   public static final int REQUEST_LOG_RETAIN_DAYS_DEFAULT = 180;

   /**
    * The request log extended option property ({@value}).
    */
   public static final String REQUEST_LOG_EXTENDED_PROPERTY = "requestLogExtended";

   /**
    * The request log extended option default value ({@value}).
    */
   public static final boolean REQUEST_LOG_EXTENDED_DEFAULT = true;

   /**
    * The request log time zone property ({@value}).
    * <p>
    *    Value must be a valid timezone ID. If unspecified, default is the system default.
    * </p>
    */
   public static final String REQUEST_LOG_TIMEZONE_PROPERTY = "requestLogTimeZone";

   /**
    * Adds a metrics reporting servlet at the specified path.
    * @param registry The metric registry.
    * @param path The report path.
    * @return A self-reference.
    */
   protected Server addMetricsServlet(final MetricRegistry registry, final String path) {

      MetricsServlet metricsServlet = new MetricsServlet(registry);
      rootContext.addEventListener(new MetricsServlet.ContextListener() {
         @Override
         protected MetricRegistry getMetricRegistry() {
            return registry;
         }

         @Override
         protected TimeUnit getDurationUnit() {
            return TimeUnit.MILLISECONDS;
         }

         @Override
         protected TimeUnit getRateUnit() {
            return TimeUnit.MINUTES;
         }
      });
      rootContext.addServlet(new ServletHolder(metricsServlet), path);
      return this;
   }

   /**
    * Adds a health check servlet to the server.
    * @param registry The health check registry.
    * @param path The report path.
    * @return A self-reference.
    */
   protected Server addHealthCheckServlet(final HealthCheckRegistry registry, final String path) {
      HealthCheckServlet healthCheckServlet = new HealthCheckServlet(registry);
      rootContext.addServlet(new ServletHolder(healthCheckServlet), path);
      return this;
   }

   /**
    * Adds configuration to serve static assets for a path.
    * @param config  The configuration.
    * @param path The path.
    * @return A self-reference.
    */
   protected Server addStaticAssets(final StaticAssetsConfig config, final String path) {
      return addStaticAssets(config, ImmutableList.of(path));
   }

   /**
    * Adds configuration to serve static assets for a list of paths.
    * @param config  The configuration.
    * @param paths The path list.
    * @return A self-reference.
    */
   protected Server addStaticAssets(final StaticAssetsConfig config, final List<String> paths) {
      ServletHolder holder = new ServletHolder();
      holder.setInitParameter("resourceBase", config.resourceDirectory);
      holder.setInitParameter("dirAllowed", config.directoryAllowed ? "true" : "false");
      holder.setInitParameter("gzip", config.gzip ? "true" : "false");
      holder.setInitParameter("etags", config.etags ? "true" : "false");
      holder.setInitParameter("precompressed", "true");
      if(!config.cacheControl.isEmpty()) {
         holder.setInitParameter("cacheControl", config.cacheControl);
      }
      holder.setServlet(new DefaultServlet());
      paths.forEach(path -> rootContext.addServlet(holder, path));
      return this;
   }

   /**
    * The configured logger.
    */
   protected final Logger logger;

   /**
    * The resolved properties.
    */
   protected final Properties props;

   /**
    * The server configuration.
    */
   protected final ServerConfiguration serverConfiguration;

   /**
    * The HTTP server.
    */
   protected final org.eclipse.jetty.server.Server httpServer;

   /**
    * The root context.
    */
   protected final ServletContextHandler rootContext;

   /**
    * Is the server running in "debug" mode?
    */
   protected final boolean debug;

   /**
    * The last time the keystore was modified.
    */
   private AtomicLong lastKeystoreModTime = new AtomicLong(0L);

   /**
    * The key store monitor.
    */
   private KeyStoreMonitor keyStoreMonitor = new KeyStoreMonitor();
}