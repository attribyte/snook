/*
 * Copyright 2020 Attribyte, LLC
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

import com.google.common.base.Charsets;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.net.HttpHeaders;
import org.attribyte.api.Logger;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.http.MimeTypes;
import org.eclipse.jetty.http.QuotedQualityCSV;
import org.eclipse.jetty.io.ByteBufferOutputStream;
import org.eclipse.jetty.server.Dispatcher;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.util.StringUtil;
import org.joda.time.format.ISODateTimeFormat;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.List;

import static org.attribyte.util.StringUtil.randomString;

/**
 * An error handler that enables custom responses with any content type.
 */
public class ErrorHandler extends org.eclipse.jetty.server.handler.ErrorHandler {

   /**
    * Writes an error message.
    */
   public interface Writer {

      /**
       * Write the message.
       * @param request The request.
       * @param writer The output writer.
       * @param code The error code.
       * @param message The message.
       * @param withStackTrace Should the stack trace be included?
       * @param logger A logger. May be {@code null};
       */
      public void write(HttpServletRequest request, PrintWriter writer, int code, String message,
                        boolean withStackTrace, Logger logger);

      /**
       * The content type for this writer.
       * @return The content type.
       */
      public String contentType();

      /**
       * The name of the writer.
       * @return The name.
       */
      public String name();
   }

   /**
    * Creates an error handler.
    * @param cacheControlHeader The cache control header value.
    * @param defaultWriter The default writer.
    * @param withStackTrace Should stack traces be sent to the client?
    * @param logger A logger.
    */
   public ErrorHandler(final String cacheControlHeader,
                       final Writer defaultWriter,
                       final boolean withStackTrace,
                       final Logger logger) {
      this.cacheControlHeader = cacheControlHeader;
      this.defaultWriter = defaultWriter;
      this.withStackTrace = withStackTrace;
      this.logger = logger;
   }
   /**
    * Creates an error handler with default values.
    */
   public ErrorHandler() {
      this(DEFAULT_CACHE_CONTROL_HEADER, TEXT_WRITER, true, null);
   }

   /**
    * Creates an error handler with stack trace enabled.
    * @return The error handler.
    */
   public ErrorHandler enableStackTrace() {
      return new ErrorHandler(cacheControlHeader, defaultWriter, true, logger);
   }

   /**
    * Creates an error handler with stack trace disabled.
    * @return The new error handler.
    */
   public ErrorHandler disableStackTrace() {
      return new ErrorHandler(cacheControlHeader, defaultWriter, false, logger);
   }

   /**
    * Creates an error handler with a logger.
    * @param logger The logger.
    * @return The new error handler.
    */
   public ErrorHandler withLogger(final Logger logger) {
      return new ErrorHandler(cacheControlHeader, defaultWriter, withStackTrace, logger);
   }

   @Override
   public void handle(String target, Request baseRequest,
                      HttpServletRequest request,
                      HttpServletResponse response) throws IOException {

      if(cacheControlHeader != null) {
         response.setHeader(HttpHeaders.CACHE_CONTROL, cacheControlHeader);
      }

      try {

         String message = (String)request.getAttribute(Dispatcher.ERROR_MESSAGE);
         if(message == null) {
            message = baseRequest.getResponse().getReason();
         }

         List<String> acceptableMimeTypes = baseRequest.getHttpFields().getQualityCSV(HttpHeader.ACCEPT,
                 QuotedQualityCSV.MOST_SPECIFIC_MIME_ORDERING);

         Writer writer = null;

         if(acceptableMimeTypes.isEmpty()) {
            writer = defaultWriter;
         } else {
            for(String contentType : acceptableMimeTypes) {
               Writer maybeWriter = selectWriter(contentType);
               if(maybeWriter != null) {
                  writer = maybeWriter;
                  break;
               }
            }
         }

         if(writer == null) {
            writer = defaultWriter;
         }

         boolean useStackTrace = withStackTrace;

         //See: https://www.eclipse.org/jetty/javadoc/9.4.26.v20200117/org/eclipse/jetty/server/handler/ErrorHandler.html

         while(true) {
            try {
               ByteBuffer buffer = baseRequest.getResponse().getHttpOutput().acquireBuffer();
               ByteBufferOutputStream out = new ByteBufferOutputStream(buffer);
               PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(out, useCharset(baseRequest, writer.contentType())));
               writer.write(request, printWriter, response.getStatus(), message, useStackTrace, logger);
               printWriter.flush();
               break;
            } catch(BufferOverflowException e) {
               baseRequest.getResponse().resetContent();
               if(useStackTrace) {
                  useStackTrace = false;
                  continue;
               }
               break;
            }
         }
         baseRequest.getHttpChannel().sendResponseAndComplete();
      } finally {
         baseRequest.setHandled(true);
      }
   }


   /**
    * Selects the writer based on content type.
    * @param contentType The content type.
    * @return The writer or {@code null} if none mapped to the content type.
    */
   protected Writer selectWriter(final String contentType) {
      switch(Strings.nullToEmpty(contentType).trim().toLowerCase()) {
         case "text/html":
         case "text/*":
         case "*/*":
            return HTML_WRITER;
         case "text/plain":
            return TEXT_WRITER;
         default:
            return defaultWriter;
      }
   }

   /**
    * Determine the charset for the response.
    *
    * @param baseRequest The base request.
    * @param contentType The output content type.
    * @return The charset or the default charset for the content type.
    */
   protected static Charset useCharset(final Request baseRequest, final String contentType) {
      List<String> acceptableCharsets = baseRequest.getHttpFields().getQualityCSV(HttpHeader.ACCEPT_CHARSET);
      for(String name : acceptableCharsets) {
         if(name.equals("*")) {
            return Charsets.UTF_8;
         } else {
            try {
               return Charset.forName(name);
            } catch(Exception e) {
               //Ignore...
            }
         }
      }

      return defaultCharset(contentType);
   }


   /**
    * Gets the default charset for a content type.
    *
    * @param contentType The content type.
    * @return The charset.
    */
   protected static Charset defaultCharset(final String contentType) {
      switch(Strings.nullToEmpty(contentType).toLowerCase().trim()) {
         case "text/json":
         case "application/json":
            return Charsets.UTF_8;
         default:
            return DEFAULT_CHARSET;
      }
   }

   /**
    * Writes the stack trace.
    * @param cause The cause.
    * @param request The request.
    * @param writer The output writer.
    */
   protected static void writeStackTrace(final Throwable cause,
                                         final HttpServletRequest request, final PrintWriter writer) {
      if(cause != null) {
         List<Throwable> chain = Throwables.getCausalChain(cause);
         for(Throwable t : chain) {
            writer.println(StringUtil.sanitizeXmlString(Throwables.getStackTraceAsString(t)));
         }
      } else {
         writer.println("Unknown");
      }
   }

   /**
    * Gets the cause, if available.
    * @param request The request.
    * @return The cause or {@code null}.
    */
   protected static Throwable getCause(final HttpServletRequest request) {
      return (Throwable)request.getAttribute(Dispatcher.ERROR_EXCEPTION);
   }

   /**
    * The value sent with the cache control header. If {@code null} or empty, the header will not be sent.
    */
   public final String cacheControlHeader;

   /**
    * The default writer.
    */
   private final Writer defaultWriter;

   /**
    * Should stack traces be included?
    */
   public final boolean withStackTrace;

   /**
    * An optional logger.
    */
   public final Logger logger;

   /**
    * {@value}
    */
   public static final String DEFAULT_CACHE_CONTROL_HEADER = "must-revalidate,no-cache,no-store";

   /**
    * The default charset.
    */
   public static final Charset DEFAULT_CHARSET = Charsets.ISO_8859_1;


   public static final Writer TEXT_WRITER = new Writer() {
      @Override
      public void write(final HttpServletRequest request, final PrintWriter writer, final int code, final String message,
                        final boolean withStackTrace, final Logger logger) {
         Throwable cause = getCause(request);
         if(logger != null && cause != null) {
            String idMessage = String.format("REF ID: %s", randomString(8));
            writer.println(idMessage);
            logger.error(idMessage, cause);
         }
         writer.printf("HTTP ERROR: %d %s%n", code, StringUtil.sanitizeXmlString(message));
         writer.printf("STATUS: %s%n", code);
         writer.printf("MESSAGE: %s%n", message);
         writer.printf("SERVLET: %s%n", request.getAttribute(Dispatcher.ERROR_SERVLET_NAME));
         if(cause != null && withStackTrace) {
            writer.println("CAUSE:");
            writer.println();
            writeStackTrace(cause, request, writer);
         }
         writer.flush();
      }

      @Override
      public String name() {
         return "text";
      }

      @Override
      public String contentType() {
         return MimeTypes.Type.TEXT_PLAIN.asString();
      }
   };

   public static final Writer HTML_WRITER = new Writer() {
      @Override
      public void write(final HttpServletRequest request, final PrintWriter writer, final int code, String message,
                        final boolean withStackTrace, final Logger logger) {

         if(message == null) {
            message = HttpStatus.getMessage(code);
         }

         writer.write("<!DOCTYPE html><html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\"/><title>Error ");
         writer.write("<title>Error ");
         String status = Integer.toString(code);
         writer.write(status);
         if(message != null && !message.equals(status)) {
            writer.write(' ');
            writer.write(StringUtil.sanitizeXmlString(message));
         }
         writer.write("</title></head><body>");
         writer.printf("%n<h2>%d %s</h2>%n", code, StringUtil.sanitizeXmlString(message));
         writer.printf("<h3>%s</h3>%n", ISODateTimeFormat.basicDateTimeNoMillis().print(System.currentTimeMillis()));
         writer.printf("<h3>%s</h3>%n", request.getAttribute(Dispatcher.ERROR_SERVLET_NAME));
         Throwable cause = getCause(request);
         if(logger != null && cause != null) {
            String idMessage = String.format("REF ID: %s", randomString(8));
            writer.printf("<h3>%s</h3>", idMessage);
            logger.error(idMessage, cause);
            writer.write("<pre>");
            writeStackTrace(cause, request, writer);
            writer.write("</pre>");
         }
         writer.write("</body></html>");
         writer.flush();
      }

      @Override
      public String name() {
         return "html";
      }

      @Override
      public String contentType() {
         return MimeTypes.Type.TEXT_HTML.asString();
      }
   };
}
