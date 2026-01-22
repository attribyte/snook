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

import java.nio.charset.StandardCharsets;
import com.google.common.base.Strings;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.net.HttpHeaders;
import org.attribyte.api.Logger;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.http.MimeTypes;
import org.eclipse.jetty.http.QuotedQualityCSV;
import org.eclipse.jetty.io.ByteBufferOutputStream;
import org.eclipse.jetty.server.Dispatcher;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.util.QuotedStringTokenizer;
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
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
       * @param cause The cause. May be {@code null}.
       * @param withStackTrace Should the stack trace be included?
       * @param logger A logger. May be {@code null};
       */
      public void write(HttpServletRequest request, PrintWriter writer, int code, String message,
                        Throwable cause, boolean withStackTrace, boolean withServletName,
                        Logger logger);


      /**
       * Send an error response.
       * @param request The request.
       * @param code The code.
       * @param message The message.
       * @param withStackTrace Should a stack trace be included in the output?
       * @param logger A logger.
       * @param response The response.
       * @throws IOException on write error.
       */
      public default void send(HttpServletRequest request, int code, String message,
                               boolean withStackTrace, Logger logger,
                               final HttpServletResponse response) throws IOException {
         response.setStatus(code);
         response.setContentType(contentType());
         Throwable cause = getCause(request);
         if(withStackTrace && cause == null) {
            cause = new Exception("");
         }
         write(request, response.getWriter(), code, message, cause, withStackTrace, false, logger);
         response.flushBuffer();
      }

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

      /**
       * Adds custom headers to a response.
       * <p>
       *    Default does nothing.
       * </p>
       * @param response The response.
       */
      public default void addCustomHeaders(HttpServletResponse response) {
      }

      /**
       * Sanitize HTML/XML markup.
       * @param str The string.
       * @return The sanitized string.
       */
      public static String sanitizeMarkup(final String str) {
         return StringUtil.sanitizeXmlString(str);
      }
   }

   /**
    * Creates an error handler with a map of overrides.
    * @param cacheControlHeader The cache control header value.
    * @param defaultWriter The default writer.
    * @param withStackTrace Should stack traces be sent to the client?
    * @param logger A logger.
    * @param overrideWriters A map (that should preserve iteration order for entries)
    *                        of writer vs prefix to override output type for paths. May be {@code null}.
    */
   public ErrorHandler(final String cacheControlHeader,
                       final Writer defaultWriter,
                       final boolean withStackTrace,
                       final Logger logger,
                       final Map<String, Writer> overrideWriters) {
      this(cacheControlHeader, defaultWriter, withStackTrace, logger, overrideWriters.entrySet());
   }

   /**
    * Creates an error handler with a list of overrides.
    * @param cacheControlHeader The cache control header value.
    * @param defaultWriter The default writer.
    * @param withStackTrace Should stack traces be sent to the client?
    * @param logger A logger.
    * @param overrideWriters A list of prefix, writers to override output type for paths. May be {@code null}.
    */
   public ErrorHandler(final String cacheControlHeader,
                       final Writer defaultWriter,
                       final boolean withStackTrace,
                       final Logger logger,
                       final Collection<Map.Entry<String, Writer>> overrideWriters) {
      this(cacheControlHeader, defaultWriter, withStackTrace, false, logger, overrideWriters);
   }


   /**
    * Creates an error handler with a list of overrides.
    * @param cacheControlHeader The cache control header value.
    * @param defaultWriter The default writer.
    * @param withStackTrace Should stack traces be sent to the client?
    * @param logger A logger.
    * @param overrideWriters A list of prefix, writers to override output type for paths. May be {@code null}.
    */
   public ErrorHandler(final String cacheControlHeader,
                       final Writer defaultWriter,
                       final boolean withStackTrace,
                       final boolean withServletName,
                       final Logger logger,
                       final Collection<Map.Entry<String, Writer>> overrideWriters) {
      this.cacheControlHeader = cacheControlHeader;
      this.defaultWriter = defaultWriter;
      this.withStackTrace = withStackTrace;
      this.withServletName = withServletName;
      this.logger = logger;
      this.overrideWriters = overrideWriters != null ? ImmutableList.copyOf(overrideWriters) : ImmutableList.of();
   }

   /**
    * Creates an error handler with default values.
    */
   public ErrorHandler() {
      this(DEFAULT_CACHE_CONTROL_HEADER, TEXT_WRITER, true, false, null, ImmutableList.of());
   }

   /**
    * Creates an error handler with stack trace enabled.
    * @return The error handler.
    */
   public ErrorHandler enableStackTrace() {
      return new ErrorHandler(cacheControlHeader, defaultWriter, true, withServletName, logger, overrideWriters);
   }

   /**
    * Creates an error handler with stack trace disabled.
    * @return The new error handler.
    */
   public ErrorHandler disableStackTrace() {
      return new ErrorHandler(cacheControlHeader, defaultWriter, false, withServletName, logger, overrideWriters);
   }

   /**
    * Creates an error handler with servlet name enabled.
    * @return The error handler.
    */
   public ErrorHandler enableServletName() {
      return new ErrorHandler(cacheControlHeader, defaultWriter, withStackTrace, true, logger, overrideWriters);
   }

   /**
    * Creates an error handler with servlet name disabled.
    * @return The new error handler.
    */
   public ErrorHandler disableServletName() {
      return new ErrorHandler(cacheControlHeader, defaultWriter, withStackTrace, false, logger, overrideWriters);
   }

   /**
    * Creates an error handler with a logger.
    * @param logger The logger.
    * @return The new error handler.
    */
   public ErrorHandler withLogger(final Logger logger) {
      return new ErrorHandler(cacheControlHeader, defaultWriter, withStackTrace, logger, overrideWriters);
   }

   /**
    * Adds overrides to this writer from a map.
    * @param overrides The overrides.
    * @return The new error handler with overrides added.
    */
   public ErrorHandler withOverrides(final Map<String, Writer> overrides) {
      return new ErrorHandler(cacheControlHeader, defaultWriter, withStackTrace, logger, overrides);
   }

   /**
    * Adds overrides to this writer from a list of map entries.
    * @param overrides The overrides.
    * @return The new error handler with overrides added.
    */
   public ErrorHandler withOverrides(final List<Map.Entry<String, Writer>> overrides) {
      return new ErrorHandler(cacheControlHeader, defaultWriter, withStackTrace, logger, overrides);
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

         Writer writer = overrideWriter(Strings.nullToEmpty(request.getRequestURI()));
         if(writer == null) {
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
         }

         response.setHeader(HttpHeaders.CONTENT_TYPE, writer.contentType());
         writer.addCustomHeaders(response);

         boolean useStackTrace = withStackTrace;

         //See: https://www.eclipse.org/jetty/javadoc/9.4.26.v20200117/org/eclipse/jetty/server/handler/ErrorHandler.html

         while(true) {
            try {
               ByteBuffer buffer = baseRequest.getResponse().getHttpOutput().getBuffer();
               ByteBufferOutputStream out = new ByteBufferOutputStream(buffer);
               PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(out, useCharset(baseRequest, writer.contentType())));
               writer.write(request, printWriter, response.getStatus(), message,
                       getCause(request), useStackTrace, withServletName, logger);
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
    * Override the writer based on path.
    * @return The writer or {@code null} if none.
    */
   protected Writer overrideWriter(final String requestURI) {
      if(overrideWriters.isEmpty()) {
         return null;
      }
      for(Map.Entry<String, Writer> curr : overrideWriters) {
         if(requestURI.startsWith(curr.getKey())) {
            return curr.getValue();
         }
      }
      return null;
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
            return htmlWriter();
         case "text/plain":
            return textWriter();
         case "text/json":
         case "application/json":
            return jsonWriter();
         default:
            return defaultWriter;
      }
   }

   /**
    * Selects one of the built-in writers for a content type.
    * @param contentType The content type.
    * @return The writer or a text writer if none mapped to the content type.
    */
   public static Writer selectBuiltInWriter(final String contentType) {
      switch(Strings.nullToEmpty(contentType).trim().toLowerCase()) {
         case "text/html":
         case "text/*":
         case "*/*":
            return HTML_WRITER;
         case "text/json":
         case "application/json":
            return JSON_WRITER;
         default:
            return TEXT_WRITER;
      }
   }

   /**
    * Selects the HTML writer.
    * @return The HTML writer.
    */
   protected Writer htmlWriter() {
      return HTML_WRITER;
   }

   /**
    * Selects the JSON writer.
    * @return The JSON writer.
    */
   protected Writer jsonWriter() {
      return JSON_WRITER;
   }

   /**
    * Selects the text writer.
    * @return The text writer.
    */
   protected Writer textWriter() {
      return TEXT_WRITER;
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
            return StandardCharsets.UTF_8;
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
            return StandardCharsets.UTF_8;
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
    * Gets the stack trace as a string.
    * @param cause The cause.
    */
   public static List<String> getStackTrace(final Throwable cause) {
      if(cause != null) {
         List<Throwable> chain = Throwables.getCausalChain(cause);
         List<String> traces = Lists.newArrayListWithExpectedSize(chain.size());
         for(Throwable t : chain) {
            traces.add(Throwables.getStackTraceAsString(t));
         }
         return traces;
      } else {
         return ImmutableList.of("Unknown");
      }
   }

   /**
    * Gets the cause, if available.
    * @param request The request.
    * @return The cause or {@code null}.
    */
   public static Throwable getCause(final HttpServletRequest request) {
      return (Throwable)request.getAttribute(Dispatcher.ERROR_EXCEPTION);
   }

   /**
    * Gets the servlet name.
    * @param request The request.
    * @return The servlet name.
    */
   public static String getServletName(final HttpServletRequest request) {
      Object servlet = request.getAttribute(Dispatcher.ERROR_SERVLET_NAME);
      return servlet != null ? servlet.toString() : "";
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
    * Should the servlet name be included?
    */
   public final boolean withServletName;

   /**
    * An optional logger.
    */
   public final Logger logger;

   /**
    * A list of path prefix, writer pairs - matched in order.
    */
   public final ImmutableList<Map.Entry<String, Writer>> overrideWriters;

   /**
    * {@value}
    */
   public static final String DEFAULT_CACHE_CONTROL_HEADER = "must-revalidate,no-cache,no-store";

   /**
    * The default charset.
    */
   public static final Charset DEFAULT_CHARSET = StandardCharsets.ISO_8859_1;

   public static final Writer TEXT_WRITER = new Writer() {
      @Override
      public void write(final HttpServletRequest request, final PrintWriter writer, final int code, final String message,
                        final Throwable cause, final boolean withStackTrace,
                        final boolean withServletName, final Logger logger) {
         if(logger != null && cause != null) {
            String idMessage = String.format("REF ID: %s", randomString(8));
            writer.println(idMessage);
            logger.error(idMessage, cause);
         }
         writer.printf("HTTP ERROR: %d %s%n", code, StringUtil.sanitizeXmlString(message));
         writer.printf("STATUS: %s%n", code);
         writer.printf("MESSAGE: %s%n", message);
         if(withServletName) {
            writer.printf("SERVLET: %s%n", getServletName(request));
         }
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
                        final Throwable cause, final boolean withStackTrace,
                        final boolean withServletName, final Logger logger) {

         if(message == null) {
            message = HttpStatus.getMessage(code);
         }

         writer.write("<!DOCTYPE html><html><head><meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\"/><title>Error ");
         String status = Integer.toString(code);
         writer.write(status);
         if(message != null && !message.equals(status)) {
            writer.write(' ');
            writer.write(StringUtil.sanitizeXmlString(message));
         }
         writer.write("</title></head><body>");
         writer.printf("%n<h2>%d %s</h2>%n", code, StringUtil.sanitizeXmlString(message));
         writer.printf("<h3>%s</h3>%n", ISODateTimeFormat.basicDateTimeNoMillis().print(System.currentTimeMillis()));
         if(withServletName) {
            writer.printf("<h3>%s</h3>%n", getServletName(request));
         }

         if(logger != null && cause != null) {
            String idMessage = String.format("REF ID: %s", randomString(8));
            writer.printf("<h3>%s</h3>", idMessage);
            logger.error(idMessage, cause);
         }

         if(cause != null && withStackTrace) {
            writer.println("<pre>");
            writeStackTrace(cause, request, writer);
            writer.println("</pre>");
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

   public static final Writer JSON_WRITER = new Writer() {
      @Override
      public void write(final HttpServletRequest request, final PrintWriter writer, final int code, String message,
                        final Throwable cause, final boolean withStackTrace,
                        final boolean withServletName,
                        final Logger logger) {
         Map<String, String> json = Maps.newLinkedHashMap();
         json.put("url", request.getRequestURI());
         json.put("status", Integer.toString(code));
         json.put("message", message);
         if(withServletName) {
            json.put("servlet", getServletName(request));
         }

         if(logger != null && cause != null) {
            String id = randomString(8);
            json.put("ref_id", id);
            logger.error(id, cause);
         }

         if(cause != null && withStackTrace) {
            List<String> stackTraces = getStackTrace(cause);
            for(int i = 0; i < stackTraces.size(); i++) {
               json.put("cause" + i, stackTraces.get(i));
            }
         }

         writer.append(json.entrySet().stream()
                 .map(e -> QuotedStringTokenizer.quote(e.getKey()) +
                         ":" +
                         QuotedStringTokenizer.quote((e.getValue())))
                 .collect(Collectors.joining(",\n", "{\n", "\n}")));
         writer.flush();;
      }

      @Override
      public String name() {
         return "json";
      }

      @Override
      public String contentType() {
         return MimeTypes.Type.APPLICATION_JSON.asString();
      }
   };
}
