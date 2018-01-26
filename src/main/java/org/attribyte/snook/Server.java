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
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.log4j.PropertyConfigurator;
import org.attribyte.api.Logger;
import org.attribyte.util.InitUtil;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.NCSARequestLog;
import org.eclipse.jetty.server.RequestLog;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.component.LifeCycle;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;

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
      this.logger = new Logger() {
         private final org.apache.log4j.Logger logger = org.apache.log4j.Logger.getLogger(loggerName);

         public void debug(String msg) {
            this.logger.debug(msg);
         }

         public void info(String msg) {
            this.logger.info(msg);
         }

         public void warn(String msg) {
            this.logger.warn(msg);
         }

         public void warn(String msg, Throwable t) {
            this.logger.warn(msg, t);
         }

         public void error(String msg) {
            this.logger.error(msg);
         }

         public void error(String msg, Throwable t) {
            this.logger.error(msg, t);
         }
      };
      this.serverConfiguration = new ServerConfiguration("server.", props);
      this.httpServer = httpServer();
      this.rootContext = rootContext(withGzip);
   }

   /**
    * The default string that starts a parameter ({@value}).
    */
   public static final String DEFAULT_PARAMETER_START = "-";

   /**
    * Removes arguments like -username=test from a command line and adds them to a map.
    * <p>
    *   Adds a version of every key that is all lower-case.
    * </p>
    * @param args The input arguments.
    * @param parameterMap The map to which parameters are added.
    * @return The input array with parameters removed.
    */
   public static String[] commandLineParameters(String[] args, Map<String, String> parameterMap) {
      return commandLineParameters(DEFAULT_PARAMETER_START, args, parameterMap);
   }

   /**
    * Removes arguments like -username=test from a command line and adds them to a map.
    * <p>
    *   Adds a version of every key that is all lower-case.
    *   If a parameter has no value, "true" is added to the map as the value.
    * </p>
    * @param parameterStartPrefix The prefix that starts parameters.
    * @param args The input arguments.
    * @param parameterMap The map to which parameters are added.
    * @return The input array with parameters removed.
    */
   public static String[] commandLineParameters(final String parameterStartPrefix, String[] args, Map<String, String> parameterMap) {

      if(args == null || args.length == 0) {
         return args;
      }

      List<String> argList = Lists.newArrayListWithExpectedSize(8);
      for(String arg : args) {
         if(arg.isEmpty()) {
            continue;
         }

         arg = arg.trim();

         if(arg.startsWith(parameterStartPrefix)) {
            String nameVal = arg.substring(parameterStartPrefix.length());
            int index = nameVal.indexOf('=');
            if(index == -1) {
               parameterMap.put(nameVal, "true");
            } else {
               String name = nameVal.substring(0, index).trim();
               String val = nameVal.substring(index+1).trim();
               parameterMap.put(name, val);
               parameterMap.put(name.toLowerCase(), val);
            }

         } else {
            argList.add(arg);
         }
      }

      return argList.toArray(new String[argList.size()]);
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

   protected void logInfo(final String str) {
      System.out.println(str);
      if(logger != null) {
         logger.info(str);
      }
   }

   protected void logError(final String str) {
      System.err.println(str);
      if(logger != null) {
         logger.error(str);
      }
   }

   protected void logError(final String str, final Throwable t) {
      System.err.println(str);
      t.printStackTrace();
      if(logger != null) {
         logger.error(str, t);
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

      org.eclipse.jetty.server.Server httpServer = new org.eclipse.jetty.server.Server();

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
            shutdown();
         }
      });

      HttpConfiguration httpConfig = new HttpConfiguration();
      httpConfig.setOutputBufferSize(serverConfiguration.outputBufferSize);
      httpConfig.setRequestHeaderSize(serverConfiguration.requestHeaderSize);
      httpConfig.setResponseHeaderSize(serverConfiguration.responseHeaderSize);
      httpConfig.setSendServerVersion(serverConfiguration.sendServerVersion);
      httpConfig.setSendDateHeader(serverConfiguration.sendDateHeader);
      ServerConnector httpConnector = new ServerConnector(httpServer, new HttpConnectionFactory(httpConfig));
      httpConnector.setHost(serverConfiguration.listenIP);
      httpConnector.setPort(serverConfiguration.httpPort);
      httpConnector.setIdleTimeout(serverConfiguration.idleTimeout);
      httpServer.addConnector(httpConnector);
      RequestLog requestLog = initRequestLog();
      if(requestLog != null) {
         httpServer.setRequestLog(requestLog);
      }
      return httpServer;
   }

   private ServletContextHandler rootContext(boolean withGzip) {
      ServletContextHandler rootContext = new ServletContextHandler(ServletContextHandler.NO_SECURITY);
      rootContext.setContextPath("/");
      rootContext.setMaxFormContentSize(serverConfiguration.maxFormContentSize);

      if(withGzip) {
         GzipHandler gzip = new GzipHandler();
         this.httpServer.setHandler(gzip);
         HandlerList handlers = new HandlerList();
         handlers.setHandlers(new Handler[]{rootContext});
         gzip.setHandler(handlers);
      } else {
         this.httpServer.setHandler(rootContext);
      }

      return rootContext;
   }

   /**
    * Initialize the server request logger.
    * @return The logger or {@code null} if none.
    */
   private RequestLog initRequestLog() {

      String requestLogPath = props.getProperty("requestLog.Dir", "").trim();
      if(requestLogPath.isEmpty()) {
         return null;
      }

      if(!requestLogPath.endsWith("/")) {
         requestLogPath = requestLogPath + "/";
      }

      String requestLogBase = props.getProperty("requestLogBase", "server");

      int requestLogRetainDays = Integer.parseInt(props.getProperty("requestLogRetainDays", "180"));
      boolean requestLogExtendedFormat = props.getProperty("requestLogExtended", "true").equalsIgnoreCase("true");

      String requestLogTimeZone = props.getProperty("requestLogTimeZone", TimeZone.getDefault().getID());

      NCSARequestLog requestLog = new NCSARequestLog(requestLogPath + requestLogBase + "-yyyy_mm_dd.request.log");
      requestLog.setRetainDays(requestLogRetainDays);
      requestLog.setAppend(true);
      requestLog.setExtended(requestLogExtendedFormat);
      requestLog.setLogTimeZone(requestLogTimeZone);
      requestLog.setLogCookies(false);
      requestLog.setPreferProxiedForAddress(true);
      return requestLog;
   }

   /**
    * Adds a metrics reporting servlet at the specified path.
    * @param registry The metric registry.
    * @param path The report path.
    */
   protected void addMetricsServlet(final MetricRegistry registry, final String path) {

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
   }

   /**
    * Adds a health check servlet to the server.
    * @param registry The health check registry.
    * @param path The report path.
    */
   protected void addHealthCheckServlet(final HealthCheckRegistry registry, final String path) {
      HealthCheckServlet healthCheckServlet = new HealthCheckServlet(registry);
      rootContext.addServlet(new ServletHolder(healthCheckServlet), path);
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
}