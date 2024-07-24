package org.attribyte.snook.auth.webauthn;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.google.common.collect.ImmutableList;
import com.yubico.internal.util.JacksonCodecs;
import org.checkerframework.checker.nullness.qual.Nullable;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Webauthn Operations.
 */
public class Operations {

   Operations(@Nullable final URL baseURL,
              final boolean pretty) {
      this.baseURL = baseURL;
      this.pretty = pretty;
   }

   Operations(@Nullable final URL baseURL) {
      this.baseURL = baseURL;
      this.pretty = false;
   }

   /**
    * Create a JSON string for an object.
    * @param o The object.
    * @param pretty Should the JSON be pretty?
    * @return The JSON string.
    * @throws JsonProcessingException on JSON error.
    */
   protected String toJSON(Object o, final boolean pretty) throws JsonProcessingException {
      return pretty ? jsonMapper.writerWithDefaultPrettyPrinter().writeValueAsString(o) :
              jsonMapper.writeValueAsString(o);
   }

   /**
    * Write a successful response.
    * @param o The object to write as JSON.
    * @param response The HTTP response.
    */
   public void writeResponse(final Object o, final HttpServletResponse response)
           throws IOException {
      response.setContentType(JSON_CONTENT_TYPE);
      response.setStatus(HttpServletResponse.SC_OK);
      response.getOutputStream().write(toJSON(o, pretty).getBytes(StandardCharsets.UTF_8));
      response.flushBuffer();
   }

   /**
    * Write an error response.
    * @param response The response.
    * @param code The error code.
    * @param message The message.
    * @throws IOException on write error.
    */
   public void writeErrorResponse(final HttpServletResponse response,
                                  final int code,
                                  final String message) throws IOException {
      writeErrorResponse(response, code, ImmutableList.of(message));
   }

   /**
    * Write error responses.
    * @param response The response.
    * @param code The error code.
    * @param messages The messages.
    * @throws IOException on write error.
    */
   public void writeErrorResponse(final HttpServletResponse response,
                                  final int code,
                                  final List<String> messages)
           throws IOException {
      response.setContentType(JSON_CONTENT_TYPE);
      response.setStatus(code);
      Object o = jsonFactory
              .objectNode()
              .set("messages", jsonFactory.arrayNode()
                      .addAll(messages.stream().map(jsonFactory::textNode).collect(Collectors.toList()))
              );
      response.getOutputStream().write(toJSON(o, pretty).getBytes(StandardCharsets.UTF_8));
      response.flushBuffer();
   }

   /**
    * {@value}
    */
   private static final String JSON_CONTENT_TYPE = "application/json";

   /**
    * The JSON object mapper.
    */
   protected final ObjectMapper jsonMapper = JacksonCodecs.json();

   /**
    * The JSON factory.
    */
   protected final JsonNodeFactory jsonFactory = JsonNodeFactory.instance;

   /**
    * The base URL.
    */
   protected final URL baseURL;

   /**
    * Write pretty responses?
    */
   protected final boolean pretty;
}