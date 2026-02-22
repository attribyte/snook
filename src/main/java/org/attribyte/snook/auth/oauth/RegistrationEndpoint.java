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

package org.attribyte.snook.auth.oauth;

import com.google.common.collect.ImmutableList;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.attribyte.snook.auth.oauth.model.OAuthClient;
import org.attribyte.snook.auth.oauth.store.InMemoryClientStore;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * OAuth 2.0 Dynamic Client Registration endpoint (RFC 7591).
 * <p>
 *    Accepts POST requests with client metadata and registers
 *    public clients in an {@link InMemoryClientStore}.
 * </p>
 */
@SuppressWarnings("serial")
public class RegistrationEndpoint extends HttpServlet {

   private static final Gson GSON = new Gson();

   private final InMemoryClientStore clientStore;
   private final Collection<String> defaultScopes;

   /**
    * Creates a registration endpoint.
    * @param clientStore The client store.
    * @param defaultScopes The default scopes for registered clients.
    */
   public RegistrationEndpoint(final InMemoryClientStore clientStore,
                               final Collection<String> defaultScopes) {
      this.clientStore = clientStore;
      this.defaultScopes = ImmutableList.copyOf(defaultScopes);
   }

   @Override
   protected void doPost(final HttpServletRequest request,
                         final HttpServletResponse response) throws IOException {

      String body;
      try {
         body = new String(request.getInputStream().readAllBytes());
      } catch(Exception e) {
         writeError(response, 400, "invalid_client_metadata", "Could not read request body");
         return;
      }

      JsonObject json;
      try {
         json = JsonParser.parseString(body).getAsJsonObject();
      } catch(Exception e) {
         writeError(response, 400, "invalid_client_metadata", "Invalid JSON");
         return;
      }

      // Extract redirect_uris (required)
      List<String> redirectUris = new ArrayList<>();
      JsonElement urisElement = json.get("redirect_uris");
      if(urisElement != null && urisElement.isJsonArray()) {
         JsonArray urisArray = urisElement.getAsJsonArray();
         for(JsonElement uri : urisArray) {
            redirectUris.add(uri.getAsString());
         }
      }

      if(redirectUris.isEmpty()) {
         writeError(response, 400, "invalid_client_metadata", "redirect_uris is required");
         return;
      }

      // Extract client_name
      String clientName = json.has("client_name") ? json.get("client_name").getAsString() : "MCP Client";

      // Generate client_id
      String clientId = UUID.randomUUID().toString();

      // Register as a public client
      OAuthClient client = OAuthClient.publicClient(clientId, clientName, redirectUris, defaultScopes);
      clientStore.register(client);

      // Build response per RFC 7591
      Map<String, Object> result = new LinkedHashMap<>();
      result.put("client_id", clientId);
      result.put("client_name", clientName);
      result.put("redirect_uris", redirectUris);
      result.put("grant_types", ImmutableList.of("authorization_code", "refresh_token"));
      result.put("response_types", ImmutableList.of("code"));
      result.put("token_endpoint_auth_method", "none");

      response.setStatus(201);
      response.setContentType("application/json;charset=UTF-8");
      PrintWriter writer = response.getWriter();
      writer.write(GSON.toJson(result));
      writer.flush();
   }

   private void writeError(final HttpServletResponse response, int status,
                           String error, String description) throws IOException {
      response.setStatus(status);
      response.setContentType("application/json;charset=UTF-8");
      Map<String, String> errorMap = new LinkedHashMap<>();
      errorMap.put("error", error);
      errorMap.put("error_description", description);
      response.getWriter().write(GSON.toJson(errorMap));
   }
}
