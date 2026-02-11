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

import com.google.common.base.MoreObjects;
import com.google.common.base.Strings;
import org.attribyte.api.InitializationException;
import org.attribyte.util.InitUtil;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.ForwardedRequestCustomizer;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.resource.ResourceFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import java.io.IOException;
import java.net.URI;
import java.util.Optional;
import java.util.Properties;

/**
 * HTTP server configuration.
 */
public class ServerConfiguration {

   /**
    * The connection security option.
    */
   public enum ConnectionSecurity {

      /**
       * No secure connections.
       */
      NONE,

      /**
       * Both secure and insecure connections allowed.
       */
      BOTH,

      /**
       * Only secure connections allowed.
       */
      SECURE_ONLY,

      /**
       * Redirect to a secure connection.
       */
      REDIRECT;


      /**
       * Create connection security from a string.
       * One of: {@code none}, {@code both}, {@code secure_only} or {@code redirect}.
       * @param str The string.
       * @return The connection security.
       * @throws InitializationException if value {@code null}, empty or invalid.
       */
      public static ConnectionSecurity fromString(final String str) throws InitializationException {
         switch(Strings.nullToEmpty(str.toLowerCase())) {
            case "none":
               return NONE;
            case "both":
               return BOTH;
            case "secure_only":
            case "secureonly":
               return SECURE_ONLY;
            case "redirect":
               return REDIRECT;
            default:
               throw new InitializationException(String.format("The 'connectionSecurity', '%s' is invalid", Strings.nullToEmpty(str)));
         }
      }
   }

   /**
    * Creates a server configuration with default values.
    * @throws InitializationException on invalid configuration.
    */
   public ServerConfiguration() throws InitializationException {
      this.listenIP = DEFAULT_LISTEN_IP;
      this.httpPort = DEFAULT_LISTEN_PORT;
      this.httpsPort = DEFAULT_SECURE_LISTEN_PORT;
      this.outputBufferSize = DEFAULT_OUTPUT_BUFFER_SIZE;
      this.requestHeaderSize = DEFAULT_MAX_REQUEST_HEADER_SIZE;
      this.responseHeaderSize = DEFAULT_MAX_RESPONSE_HEADER_SIZE;
      this.sendServerVersion = DEFAULT_SEND_SERVER_VERSION;
      this.sendDateHeader = DEFAULT_SEND_DATE_HEADER;
      this.idleTimeout = InitUtil.millisFromTime(DEFAULT_IDLE_TIMEOUT);
      this.maxFormContentSize = DEFAULT_MAX_FORM_CONTENT_SIZE;
      this.debug = false;
      this.allowSymlinks = DEFAULT_ALLOW_SYMLINKS;
      this.connectionSecurity = ConnectionSecurity.fromString(DEFAULT_CONNECTION_SECURITY);
      this.keyStorePath = "";
      this.keyStoreProvider = "";
      this.keyStoreCheckInterval = "";
      this.keyStoreCheckIntervalMillis = 0L;
      this.keyStorePasswordWasSpecified = false;
      this.trustStorePath = "";
      this.trustStoreResource = "";
      this.trustStorePasswordWasSpecified = false;
      this.sslContextFactory = Optional.empty();
      this.enableForwardedRequestCustomizer = false;
      this.suppressStackTrace = false;
      this.customErrorHandler = new ErrorHandler().enableStackTrace();
   }

   /**
    * Creates a server configuration from properties.
    * @param namePrefix A prefix to be applied to names in the properties {@code server.} for example.
    * @param props The properties.
    * @throws InitializationException on invalid configuration.
    */
   public ServerConfiguration(final String namePrefix, final Properties props) throws InitializationException {
      InitUtil init = new InitUtil(namePrefix, props, true);
      this.listenIP = init.getProperty(LISTEN_IP_PROPERTY, DEFAULT_LISTEN_IP);
      this.httpPort = init.getIntProperty(LISTEN_PORT_PROPERTY, DEFAULT_LISTEN_PORT);
      this.httpsPort = init.getIntProperty(SECURE_LISTEN_PORT_PROPERTY, DEFAULT_SECURE_LISTEN_PORT);
      this.outputBufferSize = init.getIntProperty(OUTPUT_BUFFER_SIZE_PROPERTY, DEFAULT_OUTPUT_BUFFER_SIZE);
      this.requestHeaderSize = init.getIntProperty(MAX_REQUEST_HEADER_PROPERTY, DEFAULT_MAX_REQUEST_HEADER_SIZE);
      this.responseHeaderSize = init.getIntProperty(MAX_RESPONSE_HEADER_PROPERTY, DEFAULT_MAX_RESPONSE_HEADER_SIZE);
      this.sendServerVersion = init.getProperty(SEND_SERVER_VERSION_PROPERTY, Boolean.toString(DEFAULT_SEND_SERVER_VERSION)).equalsIgnoreCase("true");
      this.sendDateHeader = init.getProperty(SEND_DATE_HEADER_PROPERTY, Boolean.toString(DEFAULT_SEND_DATE_HEADER)).equalsIgnoreCase("true");
      this.idleTimeout = InitUtil.millisFromTime(init.getProperty(IDLE_TIMEOUT_PROPERTY, DEFAULT_IDLE_TIMEOUT));
      this.maxFormContentSize = init.getIntProperty(MAX_FORM_CONTENT_SIZE_PROPERTY, DEFAULT_MAX_RESPONSE_HEADER_SIZE);
      this.debug = init.getProperty(DEBUG_PROPERTY, Boolean.toString(DEFAULT_DEBUG_MODE)).equalsIgnoreCase("true");
      this.allowSymlinks = init.getProperty(ALLOW_SYMLINKS_PROPERTY, Boolean.toString(DEFAULT_ALLOW_SYMLINKS)).equalsIgnoreCase("true");
      this.keyStorePath = init.getProperty(KEYSTORE_FILE_PROPERTY, "").trim();
      this.keyStoreProvider = init.getProperty(KEYSTORE_PROVIDER_PROPERTY, "").trim();
      this.keyStoreCheckInterval = init.getProperty(KEYSTORE_CHECK_PROPERTY, "").trim();
      this.keyStoreCheckIntervalMillis = InitUtil.millisFromTime(this.keyStoreCheckInterval);
      String keystorePassword = init.getProperty(KEYSTORE_PASSWORD_PROPERTY, "").trim();
      this.keyStorePasswordWasSpecified = !keystorePassword.isEmpty();
      this.trustStorePath = init.getProperty(TRUSTSTORE_FILE_PROPERTY, "").trim();
      this.trustStoreResource = init.getProperty(TRUSTSTORE_RESOURCE_PROPERTY, "").trim();
      String truststorePassword = init.getProperty(TRUSTSTORE_PASSWORD_PROPERTY, "").trim();
      this.trustStorePasswordWasSpecified = !truststorePassword.isEmpty();
      if(!keyStorePath.isEmpty()) {
         SslContextFactory.Server contextFactory = new SslContextFactory.Server();
         contextFactory.setKeyStorePath(keyStorePath);
         if(!keystorePassword.isEmpty()) {
            contextFactory.setKeyStorePassword(keystorePassword);
         }
         if(!trustStorePath.isEmpty()) {
            contextFactory.setTrustStorePath(trustStorePath);
         }
         if(!trustStoreResource.isEmpty()) {
            contextFactory.setTrustStoreResource(ResourceFactory.root().newResource(URI.create(trustStoreResource)));
         }
         if(!truststorePassword.isEmpty()) {
            contextFactory.setTrustStorePassword(truststorePassword);
         }
         if(!keyStoreProvider.isEmpty()) {
            contextFactory.setKeyStoreProvider(keyStoreProvider);
         }
         this.sslContextFactory = Optional.of(contextFactory);
      } else {
         this.sslContextFactory = Optional.empty();
      }

      this.connectionSecurity = ConnectionSecurity.fromString(init.getProperty(CONNECTION_SECURITY_PROPERTY, DEFAULT_CONNECTION_SECURITY));
      if(connectionSecurity != ConnectionSecurity.NONE && sslContextFactory.isEmpty()) {
         throw new InitializationException(String.format("A '%s' must be specified with 'connectionSecurity', %s", KEYSTORE_FILE_PROPERTY, connectionSecurity));
      }
      this.enableForwardedRequestCustomizer =
              init.getProperty(ENABLE_FORWARDED_REQUEST_CUSTOMIZER_PROPERTY, "false").equalsIgnoreCase("true");
      this.suppressStackTrace = init.getProperty(SUPPRESS_STACK_TRACE_PROPERTY, "false").equalsIgnoreCase("true");
      this.customErrorHandler = suppressStackTrace ? new ErrorHandler().disableStackTrace() : new ErrorHandler().enableStackTrace();
   }

   /**
    * The listen IP property name ({@value}).
    */
   public static final String LISTEN_IP_PROPERTY = "listenIP";

   /**
    * The default value for the listen IP {@value}.
    */
   public static final String DEFAULT_LISTEN_IP = "127.0.0.1";

   /**
    * The listen port property name ({@value}).
    */
   public static final String LISTEN_PORT_PROPERTY = "httpPort";

   /**
    * The default listen port {@value}.
    */
   public static final int DEFAULT_LISTEN_PORT = 8081;

   /**
    * The listen port for secure connections property name ({@value}).
    */
   public static final String SECURE_LISTEN_PORT_PROPERTY = "httpsPort";

   /**
    * The default listen port for secure connections {@value}.
    */
   public static final int DEFAULT_SECURE_LISTEN_PORT = 8443;

   /**
    * The listen output buffer size property name ({@value}).
    */
   public static final String OUTPUT_BUFFER_SIZE_PROPERTY = "outputBufferSize";

   /**
    * The default value for the output buffer size ({@value}).
    */
   public static final int DEFAULT_OUTPUT_BUFFER_SIZE = 32768;

   /**
    * The maximum request header size property name ({@value}).
    */
   public static final String MAX_REQUEST_HEADER_PROPERTY = "maxRequestHeaderSize";

   /**
    * The default value for the maximum request header size ({@value}).
    */
   public static final int DEFAULT_MAX_REQUEST_HEADER_SIZE = 8192;

   /**
    * The maximum response header size property name ({@value}).
    */
   public static final String MAX_RESPONSE_HEADER_PROPERTY = "maxResponseHeaderSize";

   /**
    * The default value for the maximum response header size ({@value}).
    */
   public static final int DEFAULT_MAX_RESPONSE_HEADER_SIZE = 8192;

   /**
    * The send server version property name ({@value}).
    */
   public static final String SEND_SERVER_VERSION_PROPERTY = "sendServerVersion";

   /**
    * The default value for sending the server version ({@value}).
    */
   public static final boolean DEFAULT_SEND_SERVER_VERSION = false;

   /**
    * The send date header property name ({@value}).
    */
   public static final String SEND_DATE_HEADER_PROPERTY = "sendDateHeader";

   /**
    * The default value for sending the date header ({@value}).
    */
   public static final boolean DEFAULT_SEND_DATE_HEADER = false;

   /**
    * The maximum form content size property name ({@value}).
    */
   public static final String MAX_FORM_CONTENT_SIZE_PROPERTY = "maxFormContentSize";

   /**
    * The default value for the maximum form content size ({@value}).
    */
   public static final int DEFAULT_MAX_FORM_CONTENT_SIZE = 10000000;

   /**
    * The idle timeout property name ({@value}).
    */
   public static final String IDLE_TIMEOUT_PROPERTY = "idleTimeout";

   /**
    * The default value for idle timeout ({@value}).
    */
   public static final String DEFAULT_IDLE_TIMEOUT = "30s";

   /**
    * The "debug" mode property name ({@value}).
    */
   public static final String DEBUG_PROPERTY = "debug";

   /**
    * The connection security property name ({@value}).
    */
   public static final String CONNECTION_SECURITY_PROPERTY = "connectionSecurity";

   /**
    * The property to allow symlinks when searching for static assets ({@value}).
    */
   public static final String ALLOW_SYMLINKS_PROPERTY = "allowSymlinks";

   /**
    * The default value for allowing symlinks ({@value}).
    */
   public static final boolean DEFAULT_ALLOW_SYMLINKS = false;

   /**
    * The default value for connection security ({@value}).
    */
   public static final String DEFAULT_CONNECTION_SECURITY = "none";

   /**
    * The default "debug" mode ({@value}).
    */
   public static final boolean DEFAULT_DEBUG_MODE = false;

   /**
    * The property name for the path to the keystore ({@value}).
    */
   public static final String KEYSTORE_FILE_PROPERTY = "keystore.File";

   /**
    * The property name for the keystore password ({@value}).
    */
   public static final String KEYSTORE_PASSWORD_PROPERTY = "keystorePassword";

   /**
    * The property name for the keystore provider, e.g. {@code PKCS12} ({@value}).
    */
   public static final String KEYSTORE_PROVIDER_PROPERTY = "keystoreProvider";

   /**
    * The property name for the keystore check interval ({@value}).
    */
   public static final String KEYSTORE_CHECK_PROPERTY = "keystoreCheckInterval";

   /**
    * The property name for the path to the truststore ({@value}).
    */
   public static final String TRUSTSTORE_FILE_PROPERTY = "truststore.File";

   /**
    * The property name for a truststore resource URL ({@value}).
    */
   public static final String TRUSTSTORE_RESOURCE_PROPERTY = "truststoreResource";

   /**
    * The property name for the truststore password ({@value}).
    */
   public static final String TRUSTSTORE_PASSWORD_PROPERTY = "truststorePassword";

   /**
    * The property name for the enable forwarded request cusomizer flag ({@value}.
    */
   public static final String ENABLE_FORWARDED_REQUEST_CUSTOMIZER_PROPERTY = "enableForwardedRequestCustomizer";

   /**
    * The property name to suppress stack trace output for unhandled exceptions.
    */
   public static final String SUPPRESS_STACK_TRACE_PROPERTY = "suppressStackTrace";

   /**
    * The IP this server is listening on.
    */
   public final String listenIP;

   /**
    * The port this server is listening on.
    */
   public final int httpPort;

   /**
    * The port this server is listening on for secure connections.
    */
   public final int httpsPort;

   /**
    * The size of the buffer into which httpResponse content is aggregated before being sent to the client.
    */
   public final int outputBufferSize;

   /**
    * The maximum size of a request header.
    */
   public final int requestHeaderSize;

   /**
    * The maximum size of a request header.
    */
   public final int responseHeaderSize;

   /**
    * Should the server version be sent with responses?
    */
   public final boolean sendServerVersion;

   /**
    * Should a {@code Date} header be sent with responses?
    */
   public final boolean sendDateHeader;

   /**
    * The maximum idle time in milliseconds.
    */
   public final long idleTimeout;

   /**
    * The maximum size allowed for posted forms.
    */
   public final int maxFormContentSize;

   /**
    * Is "debug" mode configured?
    */
   public final boolean debug;

   /**
    * The configured connection security.
    */
   public final ConnectionSecurity connectionSecurity;

   /**
    * The path to the key store.
    */
   public final String keyStorePath;

   /**
    * The key store provider.
    */
   public final String keyStoreProvider;

   /**
    * Identifies if a password was specified for the key store.
    */
   public final boolean keyStorePasswordWasSpecified;

   /**
    * The time between checks for a key store change.
    */
   public final String keyStoreCheckInterval;

   /**
    * The keystore check interval in milliseconds.
    */
   public final long keyStoreCheckIntervalMillis;

   /**
    * The path to the trust store.
    */
   public final String trustStorePath;

   /**
    * The URL for a trust store resource.
    */
   public final String trustStoreResource;

   /**
    * Identifies if a password was specified for the trust store.
    */
   public final boolean trustStorePasswordWasSpecified;

   /**
    * The SSL context factory, if any.
    */
   final Optional<SslContextFactory.Server> sslContextFactory;

   /**
    * Allow the use of symlinks when resolving static assets.
    */
   public final boolean allowSymlinks;

   /**
    * Is the forwarded request customizer enabled? Default {@code true}.
    * <p>
    *    Alters the request by using headers like {@code X-Forwarded-For} to
    *    make the real endpoint visible.
    * </p>
    */
   public final boolean enableForwardedRequestCustomizer;


   /**
    * Are stack traces for unhandled exceptions suppressed? Default {@code false}.
    */
   public final boolean suppressStackTrace;

   /**
    * A custom error handler, or {@code null}.
    */
   final ErrorHandler customErrorHandler;

   /**
    * Returns formatted documentation of all server configuration properties.
    * @return The property documentation string.
    */
   public static String propertyDocumentation() {
      StringBuilder sb = new StringBuilder();
      sb.append("Usage: <config-file> [<config-file>...] [-property=value ...] [-help]\n\n");
      sb.append("  Configuration files are loaded in order, with later files overriding earlier ones.\n");
      sb.append("  Properties may also be set on the command line with -property=value.\n");
      sb.append("  Property values starting with '$' resolve to environment variables (e.g. $DB_HOST||default).\n");
      sb.append("  Properties ending with .file, .dir, or .path are resolved relative to server.install.dir.\n\n");

      sb.append("Server Properties (prefix: server.)\n");
      sb.append("------------------------------------\n");
      sb.append(String.format("  %-40s Listen IP address (default: %s)%n", LISTEN_IP_PROPERTY, DEFAULT_LISTEN_IP));
      sb.append(String.format("  %-40s HTTP port (default: %d)%n", LISTEN_PORT_PROPERTY, DEFAULT_LISTEN_PORT));
      sb.append(String.format("  %-40s HTTPS port (default: %d)%n", SECURE_LISTEN_PORT_PROPERTY, DEFAULT_SECURE_LISTEN_PORT));
      sb.append(String.format("  %-40s Output buffer size in bytes (default: %d)%n", OUTPUT_BUFFER_SIZE_PROPERTY, DEFAULT_OUTPUT_BUFFER_SIZE));
      sb.append(String.format("  %-40s Max request header size in bytes (default: %d)%n", MAX_REQUEST_HEADER_PROPERTY, DEFAULT_MAX_REQUEST_HEADER_SIZE));
      sb.append(String.format("  %-40s Max response header size in bytes (default: %d)%n", MAX_RESPONSE_HEADER_PROPERTY, DEFAULT_MAX_RESPONSE_HEADER_SIZE));
      sb.append(String.format("  %-40s Send server version header (default: %s)%n", SEND_SERVER_VERSION_PROPERTY, DEFAULT_SEND_SERVER_VERSION));
      sb.append(String.format("  %-40s Send date header (default: %s)%n", SEND_DATE_HEADER_PROPERTY, DEFAULT_SEND_DATE_HEADER));
      sb.append(String.format("  %-40s Idle connection timeout (default: %s)%n", IDLE_TIMEOUT_PROPERTY, DEFAULT_IDLE_TIMEOUT));
      sb.append(String.format("  %-40s Max form content size in bytes (default: %d)%n", MAX_FORM_CONTENT_SIZE_PROPERTY, DEFAULT_MAX_FORM_CONTENT_SIZE));
      sb.append(String.format("  %-40s Enable debug mode (default: %s)%n", DEBUG_PROPERTY, DEFAULT_DEBUG_MODE));
      sb.append(String.format("  %-40s Allow symlinks for static assets (default: %s)%n", ALLOW_SYMLINKS_PROPERTY, DEFAULT_ALLOW_SYMLINKS));
      sb.append(String.format("  %-40s Connection security: none|both|secure_only|redirect (default: %s)%n", CONNECTION_SECURITY_PROPERTY, DEFAULT_CONNECTION_SECURITY));
      sb.append(String.format("  %-40s Enable X-Forwarded-For support (default: false)%n", ENABLE_FORWARDED_REQUEST_CUSTOMIZER_PROPERTY));
      sb.append(String.format("  %-40s Suppress stack traces in error responses (default: false)%n", SUPPRESS_STACK_TRACE_PROPERTY));
      sb.append("\n");

      sb.append("SSL/TLS Properties (prefix: server.)\n");
      sb.append("-------------------------------------\n");
      sb.append(String.format("  %-40s Path to the keystore file%n", KEYSTORE_FILE_PROPERTY));
      sb.append(String.format("  %-40s Keystore password%n", KEYSTORE_PASSWORD_PROPERTY));
      sb.append(String.format("  %-40s Keystore provider (e.g. PKCS12)%n", KEYSTORE_PROVIDER_PROPERTY));
      sb.append(String.format("  %-40s Interval to check keystore for changes (e.g. 30s, 5m)%n", KEYSTORE_CHECK_PROPERTY));
      sb.append(String.format("  %-40s Path to the truststore file%n", TRUSTSTORE_FILE_PROPERTY));
      sb.append(String.format("  %-40s Truststore resource URL%n", TRUSTSTORE_RESOURCE_PROPERTY));
      sb.append(String.format("  %-40s Truststore password%n", TRUSTSTORE_PASSWORD_PROPERTY));
      sb.append("\n");

      sb.append("Request Log Properties\n");
      sb.append("----------------------\n");
      sb.append(String.format("  %-40s Output target: 'console', 'slf4j', or unset for file%n", "requestLogOutput"));
      sb.append(String.format("  %-40s Request log directory%n", "requestLog.Dir"));
      sb.append(String.format("  %-40s Log file base name (default: server)%n", "requestLogBase"));
      sb.append(String.format("  %-40s Days to retain log files (default: 180)%n", "requestLogRetainDays"));
      sb.append(String.format("  %-40s Use extended NCSA format (default: true)%n", "requestLogExtended"));
      sb.append(String.format("  %-40s Time zone for log timestamps%n", "requestLogTimeZone"));
      sb.append("\n");

      sb.append("Logging Properties\n");
      sb.append("------------------\n");
      sb.append("  If any logger.* properties are present, log4j2 is configured programmatically.\n");
      sb.append("  Otherwise, log4j's normal XML/classpath discovery is used.\n\n");
      sb.append("  Global:\n");
      sb.append(String.format("  %-40s Log file directory (resolved relative to server.install.dir)%n", "log.Dir"));
      sb.append(String.format("  %-40s Root logger level (default: ERROR)%n", "log.rootLevel"));
      sb.append(String.format("  %-40s Max file size before rolling (default: 250 MB)%n", "log.maxFileSize"));
      sb.append(String.format("  %-40s Console appender pattern layout%n", "log.consolePattern"));
      sb.append(String.format("  %-40s File appender pattern layout%n", "log.filePattern"));
      sb.append("\n");
      sb.append("  Per-Logger (prefix: logger.<name>.):\n");
      sb.append(String.format("  %-40s Logger name, e.g. 'myapp' or 'org.eclipse.jetty' (required)%n", "name"));
      sb.append(String.format("  %-40s Level: TRACE/DEBUG/INFO/WARN/ERROR/OFF (default: INFO)%n", "level"));
      sb.append(String.format("  %-40s Appender type: console or file (default: file)%n", "appender"));
      sb.append(String.format("  %-40s File name relative to log.Dir (default: <name>.log)%n", "fileName"));
      sb.append("\n");

      sb.append("Static Assets Properties (prefix: assets.<name>.)\n");
      sb.append("--------------------------------------------------\n");
      sb.append(String.format("  %-40s Directory containing static resources (required)%n", "resource.Dir"));
      sb.append(String.format("  %-40s Comma-separated list of URL paths (required)%n", "paths"));
      sb.append(String.format("  %-40s Allow directory listing (default: false)%n", "directoryAllowed"));
      sb.append(String.format("  %-40s Enable gzip (default: true)%n", "gzip"));
      sb.append(String.format("  %-40s Enable weak ETags (default: false)%n", "etags"));
      sb.append(String.format("  %-40s Cache-Control header value%n", "cacheControl"));

      return sb.toString();
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("listenIP", listenIP)
              .add("httpPort", httpPort)
              .add("httpsPort", httpsPort)
              .add("outputBufferSize", outputBufferSize)
              .add("requestHeaderSize", requestHeaderSize)
              .add("responseHeaderSize", responseHeaderSize)
              .add("sendServerVersion", sendServerVersion)
              .add("sendDateHeader", sendDateHeader)
              .add("idleTimeout", idleTimeout)
              .add("maxFormContentSize", maxFormContentSize)
              .add("debug", debug)
              .add("allowSymlinks", allowSymlinks)
              .add("connectionSecurity", connectionSecurity)
              .add("keyStorePath", keyStorePath)
              .add("keyStoreProvider", keyStoreProvider)
              .add("keyStoreCheckInterval", keyStoreCheckInterval)
              .add("keyStorePasswordWasSpecified", keyStorePasswordWasSpecified)
              .add("trustStorePath", trustStorePath)
              .add("trustStoreResource", trustStoreResource)
              .add("trustStorePasswordWasSpecified", trustStorePasswordWasSpecified)
              .add("enableForwardedRequestCustomizer", enableForwardedRequestCustomizer)
              .toString();
   }

   /**
    * Builds a server instance form this configuration.
    * @return The server.
    */
   public org.eclipse.jetty.server.Server buildServer() {
      org.eclipse.jetty.server.Server httpServer = new org.eclipse.jetty.server.Server();
      HttpConfiguration httpConfig = new HttpConfiguration();
      httpConfig.setOutputBufferSize(outputBufferSize);
      httpConfig.setRequestHeaderSize(requestHeaderSize);
      httpConfig.setResponseHeaderSize(responseHeaderSize);
      httpConfig.setSendServerVersion(sendServerVersion);
      httpConfig.setSendDateHeader(sendDateHeader);
      if(enableForwardedRequestCustomizer) {
         httpConfig.addCustomizer(new ForwardedRequestCustomizer());
      }

      ServerConnector httpConnector = new ServerConnector(httpServer, new HttpConnectionFactory(httpConfig));
      httpConnector.setHost(listenIP);
      httpConnector.setPort(httpPort);
      httpConnector.setIdleTimeout(idleTimeout);

      if(sslContextFactory.isPresent()) {
         httpConfig.setSecureScheme("https");
         httpConfig.setSecurePort(httpsPort);
         HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
         httpsConfig.addCustomizer(new SecureRequestCustomizer());
         if(enableForwardedRequestCustomizer) {
            httpsConfig.addCustomizer(new ForwardedRequestCustomizer());
         }


         ServerConnector httpsConnector = new ServerConnector(httpServer,
                 new SslConnectionFactory(sslContextFactory.get(), HttpVersion.HTTP_1_1.asString()),
                 new HttpConnectionFactory(httpsConfig));
         httpsConnector.setPort(httpsPort);
         switch(connectionSecurity) {
            case BOTH:
            case REDIRECT:
               httpServer.setConnectors(new Connector[] {httpConnector, httpsConnector});
               break;
            default:
               httpServer.addConnector(httpsConnector);
               break;
         }
      } else {
         httpServer.addConnector(httpConnector);
      }
      return httpServer;
   }
}
