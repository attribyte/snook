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

import org.attribyte.api.InitializationException;
import org.attribyte.util.InitUtil;

import java.util.Properties;

/**
 * HTTP server configuration.
 */
public class ServerConfiguration {

   /**
    * Creates a server configuration with default values.
    * @throws InitializationException on invalid configuration.
    */
   public ServerConfiguration() throws InitializationException {
      this.listenIP = DEFAULT_LISTEN_IP;
      this.httpPort = DEFAULT_LISTEN_PORT;
      this.outputBufferSize = DEFAULT_OUTPUT_BUFFER_SIZE;
      this.requestHeaderSize = DEFAULT_MAX_REQUEST_HEADER_SIZE;
      this.responseHeaderSize = DEFAULT_MAX_RESPONSE_HEADER_SIZE;
      this.sendServerVersion = DEFAULT_SEND_SERVER_VERSION;
      this.sendDateHeader = DEFAULT_SEND_DATE_HEADER;
      this.idleTimeout = InitUtil.millisFromTime(DEFAULT_IDLE_TIMEOUT);
      this.maxFormContentSize = DEFAULT_MAX_FORM_CONTENT_SIZE;
   }

   /**
    * Creates a server configuration from properties.
    * @param namePrefix A prefix to be applied to names in the properties {@code server.} for example.
    * @param props The properties.
    * @throws InitializationException on invalid configuration.
    */
   public ServerConfiguration(final String namePrefix, final Properties props) throws InitializationException {
      InitUtil init = new InitUtil(namePrefix, props, true);
      this.listenIP = init.getProperty("listenIP", DEFAULT_LISTEN_IP);
      this.httpPort = init.getIntProperty("httpPort", DEFAULT_LISTEN_PORT);
      this.outputBufferSize = init.getIntProperty("outputBufferSize", DEFAULT_OUTPUT_BUFFER_SIZE);
      this.requestHeaderSize = init.getIntProperty("requestHeaderSize", DEFAULT_MAX_REQUEST_HEADER_SIZE);
      this.responseHeaderSize = init.getIntProperty("responseHeaderSize", DEFAULT_MAX_RESPONSE_HEADER_SIZE);
      this.sendServerVersion = init.getProperty("sendServerVersion", Boolean.toString(DEFAULT_SEND_SERVER_VERSION)).equalsIgnoreCase("true");
      this.sendDateHeader = init.getProperty("sendDateHeader", Boolean.toString(DEFAULT_SEND_DATE_HEADER)).equalsIgnoreCase("true");
      this.idleTimeout = InitUtil.millisFromTime(init.getProperty("idleTimeout", DEFAULT_IDLE_TIMEOUT));
      this.maxFormContentSize = init.getIntProperty("maxFormContentSize", DEFAULT_MAX_RESPONSE_HEADER_SIZE);
   }

   /**
    * The default value for the listen IP {@value}.
    */
   public static final String DEFAULT_LISTEN_IP = "127.0.0.1";

   /**
    * The default listen port {@value}.
    */
   public static final int DEFAULT_LISTEN_PORT = 8081;

   /**
    * The default value for the output buffer size {@value}.
    */
   public static final int DEFAULT_OUTPUT_BUFFER_SIZE = 32768;

   /**
    * The default value for the maximum request header size {@value}.
    */
   public static final int DEFAULT_MAX_REQUEST_HEADER_SIZE = 8192;

   /**
    * The default value for the maximum response header size {@value}.
    */
   public static final int DEFAULT_MAX_RESPONSE_HEADER_SIZE = 8192;

   /**
    * The default value for sending the server version {@value}.
    */
   public static final boolean DEFAULT_SEND_SERVER_VERSION = false;

   /**
    * The default value for sending the date header {@value}.
    */
   public static final boolean DEFAULT_SEND_DATE_HEADER = false;

   /**
    * The default valud for the maximum form content size {@value}.
    */
   public static final int DEFAULT_MAX_FORM_CONTENT_SIZE = 10000000;


   /**
    * The default value for idle timeout {@value}.
    */
   public static final String DEFAULT_IDLE_TIMEOUT = "30s";

   /**
    * The IP this server is listening on.
    */
   public final String listenIP;

   /**
    * The port this server is listening on.
    */
   public final int httpPort;

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

}
