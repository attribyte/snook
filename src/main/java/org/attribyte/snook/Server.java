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
import io.dropwizard.metrics.servlets.HealthCheckServlet;
import io.dropwizard.metrics.servlets.MetricsServlet;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import org.apache.logging.log4j.Level;
import org.attribyte.api.InitializationException;
import org.attribyte.api.Logger;
import org.attribyte.snook.log.Log4jLogger;
import org.attribyte.util.InitUtil;
import org.eclipse.jetty.server.CustomRequestLog;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.RequestLog;
import org.eclipse.jetty.server.RequestLogWriter;
import org.eclipse.jetty.server.Slf4jRequestLogWriter;
import org.eclipse.jetty.server.handler.SecuredRedirectHandler;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.eclipse.jetty.ee10.servlet.DefaultServlet;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.util.component.LifeCycle;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

import static org.attribyte.snook.Util.commandLineParameters;
import static org.attribyte.snook.Util.resolveEnvironmentVariables;
import static org.attribyte.snook.Util.resolveRelativeFiles;

public abstract class Server {

   /**
    * Creates the server with properties from a resource and a named logger.
    * @param args The command line arguments.
    * @param propsResourceName The name of a resource that contains default properties.
    * @param loggerName The name of a logger.
    * @param withGzip Should auto-gzip handling be configured?
    * @throws Exception on configuration error.
    * @deprecated Use {@link #builder(String[])} instead.
    */
   @Deprecated
   protected Server(String[] args,
                    final String propsResourceName,
                    final String loggerName,
                    final boolean withGzip) throws Exception {
      this(args, propsResourceName, loggerName, withGzip, null);
   }

   /**
    * Creates the server with properties from a resource, a named logger and a custom error handler.
    * @param args The command line arguments.
    * @param propsResourceName The name of a resource that contains default properties.
    * @param loggerName The name of a logger.
    * @param withGzip Should auto-gzip handling be configured?
    * @param errorHandler A custom error handler.
    * @throws Exception on configuration error.
    * @deprecated Use {@link #builder(String[])} instead.
    */
   @Deprecated
   protected Server(String[] args,
                    final String propsResourceName,
                    final String loggerName,
                    final boolean withGzip,
                    final ErrorHandler errorHandler) throws Exception {
      this.props = props(propsResourceName, args);
      this.serverConfiguration = new ServerConfiguration("server.", props);
      this.debug = debug(this.serverConfiguration.debug);
      this.logger = log4jLogger(loggerName, debug ? Level.DEBUG : Level.INFO);
      if(debug) {
         System.out.println("Configuration...");
         System.out.println(this.serverConfiguration.toString());
      }
      this.httpServer = httpServer();
      if(errorHandler != null) {
         if(errorHandler.logger == null) {
            this.httpServer.setErrorHandler(errorHandler.withLogger(logger));
         } else {
            this.httpServer.setErrorHandler(errorHandler);
         }
      } else if(this.serverConfiguration.customErrorHandler != null) {
         this.httpServer.setErrorHandler(this.serverConfiguration.customErrorHandler.withLogger(this.logger));
      }
      this.rootContext = rootContext(withGzip);
      initAssets();
   }

   /**
    * Creates the server with properties from a resource and a specified logger.
    * @param args The command line arguments.
    * @param propsResourceName The name of a resource that contains default properties.
    * @param logger The logger.
    * @param withGzip Should auto-gzip handling be configured?
    * @throws Exception on configuration error.
    * @deprecated Use {@link #builder(String[])} instead.
    */
   @Deprecated
   protected Server(String[] args,
                    final String propsResourceName,
                    final Logger logger,
                    final boolean withGzip) throws Exception {
      this(args, propsResourceName, logger, withGzip, null);
   }

   /**
    * Creates the server with properties from a resource, a specified logger and a custom error handler.
    * @param args The command line arguments.
    * @param propsResourceName The name of a resource that contains default properties.
    * @param logger The logger.
    * @param withGzip Should auto-gzip handling be configured?
    * @param errorHandler A custom error handler.
    * @throws Exception on configuration error.
    * @deprecated Use {@link #builder(String[])} instead.
    */
   @Deprecated
   protected Server(String[] args,
                    final String propsResourceName,
                    final Logger logger,
                    final boolean withGzip,
                    final ErrorHandler errorHandler) throws Exception {
      this.props = props(propsResourceName, args);
      this.logger = logger;
      this.serverConfiguration = new ServerConfiguration("server.", props);
      this.debug = debug(this.serverConfiguration.debug);
      if(this.debug) {
         System.out.println("Configuration...");
         System.out.println(this.serverConfiguration.toString());
      }
      this.httpServer = httpServer();
      if(errorHandler != null) {
         if(errorHandler.logger == null) {
            this.httpServer.setErrorHandler(errorHandler.withLogger(logger));
         } else {
            this.httpServer.setErrorHandler(errorHandler);
         }
      } else if(this.serverConfiguration.customErrorHandler != null) {
         this.httpServer.setErrorHandler(this.serverConfiguration.customErrorHandler.withLogger(logger));
      }
      this.rootContext = rootContext(withGzip);
      initAssets();
   }

   private final Properties props(final String propsResourceName, final String[] args) throws IOException {
      Map<String, String> parameterMap = Maps.newHashMap();
      String[] useArgs = commandLineParameters(args, parameterMap);
      if(parameterMap.containsKey("help")) {
         System.out.println(ServerConfiguration.propertyDocumentation());
         System.exit(0);
      }
      return loadProperties(propsResourceName, useArgs, parameterMap);
   }

   /**
    * Create a log4j-based logger.
    * @param loggerName The name of the log4j logger.
    * @param minimumLevel The minimum level.
    * @return The API logger.
    */
   public static Logger log4jLogger(final String loggerName,
                                    final Level minimumLevel) {
      return new Log4jLogger(loggerName, minimumLevel);
   }

   /**
    * Creates the server from properties and a logger.
    * @param props The properties.
    * @param logger The logger.
    * @param withGzip Should auto-gzip handling be configured?
    * @throws Exception on configuration error.
    * @deprecated Use {@link #builder(Properties)} instead.
    */
   @Deprecated
   protected Server(final Properties props,
                    final Logger logger,
                    final boolean withGzip) throws Exception {
      this.props = props;
      this.logger = logger;
      this.serverConfiguration = new ServerConfiguration("server.", props);
      this.debug = debug(this.serverConfiguration.debug);
      if(this.debug) {
         System.out.println("Configuration...");
         System.out.println(this.serverConfiguration.toString());
      }
      this.httpServer = httpServer();
      this.rootContext = rootContext(withGzip);
      if(this.serverConfiguration.customErrorHandler != null) {
         this.httpServer.setErrorHandler(this.serverConfiguration.customErrorHandler.withLogger(logger));
      }
      initAssets();
   }

   /**
    * Creates a builder that loads properties from command line arguments.
    * @param args The command line arguments.
    * @return A new builder.
    */
   public static Builder builder(String[] args) {
      Builder b = new Builder();
      b.args = args;
      return b;
   }

   /**
    * Creates a builder that uses pre-built properties.
    * @param props The properties.
    * @return A new builder.
    */
   public static Builder builder(Properties props) {
      Builder b = new Builder();
      b.props = props;
      return b;
   }

   /**
    * A builder for configuring server options.
    * <p>
    *    Use {@link Server#builder(String[])} or {@link Server#builder(Properties)}
    *    to create instances.
    * </p>
    */
   public static class Builder {

      String[] args;
      Properties props;
      String propsResourceName = "";
      String loggerName;
      Logger logger;
      boolean withGzip = true;
      ErrorHandler errorHandler;

      Builder() {}

      /**
       * Sets the default properties resource name.
       * @param name The resource name.
       * @return A self-reference.
       */
      public Builder propsResource(String name) {
         this.propsResourceName = name;
         return this;
      }

      /**
       * Sets the logger name (creates a log4j logger).
       * @param name The logger name.
       * @return A self-reference.
       */
      public Builder loggerName(String name) {
         this.loggerName = name;
         return this;
      }

      /**
       * Sets a pre-built logger.
       * @param logger The logger.
       * @return A self-reference.
       */
      public Builder logger(Logger logger) {
         this.logger = logger;
         return this;
      }

      /**
       * Enables or disables gzip handling.
       * @param withGzip {@code true} to enable gzip.
       * @return A self-reference.
       */
      public Builder withGzip(boolean withGzip) {
         this.withGzip = withGzip;
         return this;
      }

      /**
       * Sets a custom error handler.
       * @param errorHandler The error handler.
       * @return A self-reference.
       */
      public Builder errorHandler(ErrorHandler errorHandler) {
         this.errorHandler = errorHandler;
         return this;
      }
   }

   /**
    * Creates the server from a builder.
    * @param builder The builder.
    * @throws Exception on configuration error.
    */
   protected Server(Builder builder) throws Exception {
      if(builder.args != null) {
         this.props = props(builder.propsResourceName, builder.args);
      } else if(builder.props != null) {
         this.props = builder.props;
      } else {
         throw new IllegalStateException("Builder requires either args or props");
      }

      this.serverConfiguration = new ServerConfiguration("server.", props);
      this.debug = debug(this.serverConfiguration.debug);

      if(builder.logger != null) {
         this.logger = builder.logger;
      } else if(builder.loggerName != null) {
         this.logger = log4jLogger(builder.loggerName, debug ? Level.DEBUG : Level.INFO);
      } else {
         this.logger = log4jLogger(getClass().getName(), debug ? Level.DEBUG : Level.INFO);
      }

      if(debug) {
         System.out.println("Configuration...");
         System.out.println(this.serverConfiguration.toString());
      }

      this.httpServer = httpServer();

      ErrorHandler errorHandler = builder.errorHandler;
      if(errorHandler != null) {
         if(errorHandler.logger == null) {
            this.httpServer.setErrorHandler(errorHandler.withLogger(logger));
         } else {
            this.httpServer.setErrorHandler(errorHandler);
         }
      } else if(this.serverConfiguration.customErrorHandler != null) {
         this.httpServer.setErrorHandler(this.serverConfiguration.customErrorHandler.withLogger(this.logger));
      }

      this.rootContext = rootContext(builder.withGzip);
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
         InputStream is = getClass().getResourceAsStream(resourceName);
         if(is == null) {
            throw new IOException(String.format("The resource, '%s' (%s) does not exist", resourceName, getClass().getName()));
         }

         try {
            props.load(is);
         } finally {
            is.close();
         }
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
    * Starts the server.
    * @throws Exception on start error.
    */
   public void start() throws Exception {
      httpServer.start();
   }


   /**
    * Starts the server with a custom error handler.
    * @param errorHandler The error handler.
    * @throws Exception on start error.
    */
   public void start(final ErrorHandler errorHandler) throws Exception {
      httpServer.setErrorHandler(errorHandler);
      httpServer.start();
   }

   /**
    * Starts the server, then joins.
    * @throws Exception on start error.
    */
   public void startWithJoin() throws Exception {
      httpServer.start();
      httpServer.join();
   }

   /**
    * Starts the server with a custom error handler, then joins.
    * @param errorHandler The error handler.
    * @throws Exception on start error.
    */
   public void startWithJoin(final ErrorHandler errorHandler) throws Exception {
      httpServer.setErrorHandler(errorHandler);
      httpServer.start();
      httpServer.join();
   }

   /**
    * Join with the calling thread.
    * @throws InterruptedException on interrupted.
    */
   public void join() throws InterruptedException {
      httpServer.join();
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

      httpServer.addEventListener(new LifeCycle.Listener() {
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

   private ServletContextHandler rootContext(boolean withGzip) {
      ServletContextHandler rootContext = new ServletContextHandler(ServletContextHandler.NO_SECURITY);
      rootContext.setContextPath("/");
      rootContext.setBaseResourceAsString("/");
      if(serverConfiguration.allowSymlinks) {
         rootContext.addAliasCheck((pathInContext, resource) -> true);
      }

      rootContext.setMaxFormContentSize(serverConfiguration.maxFormContentSize);
      boolean withSecureRedirect = serverConfiguration.connectionSecurity == ServerConfiguration.ConnectionSecurity.REDIRECT;
      if(withGzip) {
         GzipHandler gzip = new GzipHandler();
         gzip.setHandler(rootContext);
         if(withSecureRedirect) {
            this.httpServer.setHandler(new Handler.Sequence(new SecuredRedirectHandler(), gzip));
         } else {
            this.httpServer.setHandler(gzip);
         }
      } else if(withSecureRedirect) {
         this.httpServer.setHandler(new Handler.Sequence(new SecuredRedirectHandler(), rootContext));
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

      boolean requestLogExtendedFormat = props.getProperty(REQUEST_LOG_EXTENDED_PROPERTY, Boolean.toString(REQUEST_LOG_EXTENDED_DEFAULT)).equalsIgnoreCase("true");

      if(props.getProperty(REQUEST_LOG_OUTPUT_PROPERTY, "").trim().equalsIgnoreCase("console")) {
         return new CustomRequestLog(System.out::println, requestLogExtendedFormat ?
                 CustomRequestLog.EXTENDED_NCSA_FORMAT : CustomRequestLog.NCSA_FORMAT);
      } else if(props.getProperty(REQUEST_LOG_OUTPUT_PROPERTY, "").trim().equalsIgnoreCase("slf4j")) {
         Slf4jRequestLogWriter logWriter = new Slf4jRequestLogWriter();
         return new CustomRequestLog(logWriter, requestLogExtendedFormat ? CustomRequestLog.EXTENDED_NCSA_FORMAT
                 : CustomRequestLog.NCSA_FORMAT);
      }

      String requestLogPath = props.getProperty(REQUEST_LOG_DIRECTORY_PROPERTY, "").trim();
      if(requestLogPath.isEmpty()) {
         return null;
      }

      String requestLogTimeZone = props.getProperty(REQUEST_LOG_TIMEZONE_PROPERTY, TimeZone.getDefault().getID());


      if(!requestLogPath.endsWith("/")) {
         requestLogPath = requestLogPath + "/";
      }

      String requestLogBase = props.getProperty(REQUEST_LOG_BASE_PROPERTY, REQUEST_LOG_BASE_DEFAULT);
      int requestLogRetainDays = Integer.parseInt(props.getProperty(REQUEST_LOG_RETAIN_DAYS_PROPERTY, Integer.toString(REQUEST_LOG_RETAIN_DAYS_DEFAULT)));

      RequestLogWriter logWriter = new RequestLogWriter();
      logWriter.setRetainDays(requestLogRetainDays);
      logWriter.setAppend(true);
      logWriter.setTimeZone(requestLogTimeZone);
      logWriter.setFilename(requestLogPath + requestLogBase + "-yyyy_mm_dd.request.log");
      return new CustomRequestLog(logWriter, requestLogExtendedFormat ?
              CustomRequestLog.EXTENDED_NCSA_FORMAT : CustomRequestLog.NCSA_FORMAT);
   }

   private void initAssets() throws InitializationException {
      InitUtil init = new InitUtil("assets.", props, false);
      Map<String, Properties> configProps = init.split();
      for(Map.Entry<String, Properties> entry : configProps.entrySet()) {
         String resourceDir = entry.getValue().getProperty("resource.Dir", "").trim();
         if(resourceDir.isEmpty()) {
            throw new InitializationException(String.format("A 'resource.Dir' must be specified for asset config, '%s'", entry.getKey()));
         }
         entry.getValue().setProperty(StaticAssetsConfig.RESOURCE_DIRECTORY_PROPERTY, resourceDir);

         String paths = entry.getValue().getProperty(StaticAssetsConfig.PATHS_PROPERTY, "").trim();
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
    * The request output format property name ({@value}).
    */
   public static final String REQUEST_LOG_OUTPUT_PROPERTY = "requestLogOutput";

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
   protected final Server addStaticAssets(final StaticAssetsConfig config, final List<String> paths) {
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
    * The key store monitor.
    */
   private final KeyStoreMonitor keyStoreMonitor = new KeyStoreMonitor();
}
