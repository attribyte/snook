package org.attribyte.snook.auth.webauthn;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.yubico.internal.util.JacksonCodecs;
import org.checkerframework.checker.nullness.qual.Nullable;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Webauthn Operations.
 */
public class Operations {

   Operations(@Nullable final URL baseURL) {
      this.baseURL = baseURL;
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
    * @param pretty Should the JSON be pretty?
    * @param response The HTTP response.
    */
   protected void writeResponse(final Object o, final boolean pretty, final HttpServletResponse response)
           throws JsonProcessingException, IOException {
      response.setContentType(JSON_CONTENT_TYPE);
      response.setStatus(HttpServletResponse.SC_OK);
      response.getOutputStream().write(toJSON(o, pretty).getBytes(StandardCharsets.UTF_8));
      response.flushBuffer();
   }

   private final URL baseURL;
}