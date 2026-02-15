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

import com.google.gson.Gson;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Standard OAuth 2.0 error codes and JSON response helper.
 */
public final class OAuthError {

   /** The request is missing a required parameter. */
   public static final String INVALID_REQUEST = "invalid_request";

   /** Client authentication failed. */
   public static final String INVALID_CLIENT = "invalid_client";

   /** The provided authorization grant is invalid, expired, or revoked. */
   public static final String INVALID_GRANT = "invalid_grant";

   /** The authenticated client is not authorized to use this grant type. */
   public static final String UNAUTHORIZED_CLIENT = "unauthorized_client";

   /** The authorization grant type is not supported. */
   public static final String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";

   /** The requested scope is invalid, unknown, or malformed. */
   public static final String INVALID_SCOPE = "invalid_scope";

   /** The response type is not supported. */
   public static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";

   /** The authorization server encountered an unexpected condition. */
   public static final String SERVER_ERROR = "server_error";

   /** The authorization server is currently unable to handle the request. */
   public static final String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";

   /** The resource owner denied the request. */
   public static final String ACCESS_DENIED = "access_denied";

   private static final Gson GSON = new Gson();

   private OAuthError() {}

   /**
    * Writes a JSON error response.
    * @param response The HTTP response.
    * @param httpStatus The HTTP status code.
    * @param error The OAuth error code.
    * @param description A human-readable description.
    * @throws IOException on write error.
    */
   public static void writeJsonError(final HttpServletResponse response,
                                     final int httpStatus,
                                     final String error,
                                     final String description) throws IOException {
      response.setStatus(httpStatus);
      response.setContentType("application/json;charset=UTF-8");
      response.setHeader("Cache-Control", "no-store");
      response.setHeader("Pragma", "no-cache");
      Map<String, String> json = new LinkedHashMap<>();
      json.put("error", error);
      if(description != null) {
         json.put("error_description", description);
      }
      PrintWriter writer = response.getWriter();
      writer.write(GSON.toJson(json));
      writer.flush();
   }

   /**
    * Builds an error redirect URL with error parameters in the query string.
    * @param redirectUri The base redirect URI.
    * @param error The OAuth error code.
    * @param description A human-readable description, or {@code null}.
    * @param state The state parameter, or {@code null}.
    * @return The redirect URL with error parameters.
    */
   public static String errorRedirectUrl(final String redirectUri,
                                         final String error,
                                         final String description,
                                         final String state) {
      StringBuilder sb = new StringBuilder(redirectUri);
      sb.append(redirectUri.contains("?") ? "&" : "?");
      sb.append("error=").append(urlEncode(error));
      if(description != null) {
         sb.append("&error_description=").append(urlEncode(description));
      }
      if(state != null) {
         sb.append("&state=").append(urlEncode(state));
      }
      return sb.toString();
   }

   private static String urlEncode(final String value) {
      return URLEncoder.encode(value, StandardCharsets.UTF_8);
   }
}
