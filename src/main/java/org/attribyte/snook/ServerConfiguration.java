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
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import java.io.IOException;
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
         SslContextFactory contextFactory = new SslContextFactory(keyStorePath);
         if(!keystorePassword.isEmpty()) {
            contextFactory.setKeyStorePassword(keystorePassword);
         }
         if(!trustStorePath.isEmpty()) {
            contextFactory.setTrustStorePath(trustStorePath);
         }
         if(!trustStoreResource.isEmpty()) {
            try {
               contextFactory.setTrustStoreResource(Resource.newResource(trustStoreResource, true));
            } catch(IOException ioe) {
               throw new InitializationException(String.format("Problem loading 'trustStoreResource' (%s)", trustStoreResource), ioe);
            }
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
      if(connectionSecurity != ConnectionSecurity.NONE && !sslContextFactory.isPresent()) {
         throw new InitializationException(String.format("A 'keystore.File' must be specified for 'connectionSecurity', %s", connectionSecurity));
      }
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
   final Optional<SslContextFactory> sslContextFactory;

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
              .add("connectionSecurity", connectionSecurity)
              .add("keyStorePath", keyStorePath)
              .add("keyStoreProvider", keyStoreProvider)
              .add("keyStoreCheckInterval", keyStoreCheckInterval)
              .add("keyStorePasswordWasSpecified", keyStorePasswordWasSpecified)
              .add("trustStorePath", trustStorePath)
              .add("trustStoreResource", trustStoreResource)
              .add("trustStorePasswordWasSpecified", trustStorePasswordWasSpecified)
              .toString();
   }
}
