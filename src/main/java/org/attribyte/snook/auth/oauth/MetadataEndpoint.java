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

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * OAuth 2.0 Authorization Server Metadata endpoint (RFC 8414).
 * <p>
 *    Mounted at {@code /.well-known/oauth-authorization-server}.
 *    Builds the JSON response once at construction time.
 * </p>
 */
@SuppressWarnings("serial")
public class MetadataEndpoint extends HttpServlet {

   private static final Gson GSON = new Gson();

   /**
    * Creates a metadata endpoint.
    * @param issuer The issuer URL.
    * @param supportedScopes The supported scopes.
    */
   public MetadataEndpoint(final String issuer, final Collection<String> supportedScopes) {
      Map<String, Object> metadata = new LinkedHashMap<>();
      metadata.put("issuer", issuer);
      metadata.put("authorization_endpoint", issuer + "/oauth/authorize");
      metadata.put("token_endpoint", issuer + "/oauth/token");
      metadata.put("revocation_endpoint", issuer + "/oauth/revoke");
      metadata.put("response_types_supported", ImmutableList.of("code"));
      metadata.put("grant_types_supported", ImmutableList.of("authorization_code", "refresh_token"));
      metadata.put("code_challenge_methods_supported", ImmutableList.of("S256"));
      metadata.put("token_endpoint_auth_methods_supported",
              ImmutableList.of("client_secret_basic", "client_secret_post", "none"));
      if(!supportedScopes.isEmpty()) {
         metadata.put("scopes_supported", ImmutableList.copyOf(supportedScopes));
      }
      this.metadataJson = GSON.toJson(metadata);
   }

   @Override
   protected void doGet(final HttpServletRequest request,
                        final HttpServletResponse response) throws IOException {
      response.setStatus(200);
      response.setContentType("application/json;charset=UTF-8");
      PrintWriter writer = response.getWriter();
      writer.write(metadataJson);
      writer.flush();
   }

   private final String metadataJson;
}
