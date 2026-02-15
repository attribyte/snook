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

package org.attribyte.snook.auth.oauth.client;

import com.google.common.base.MoreObjects;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.util.Map;
import java.util.Optional;

/**
 * Parsed response from an OAuth token endpoint.
 */
public class TokenResponse {

   private static final Gson GSON = new Gson();

   /**
    * Parses a token response from JSON.
    * @param json The JSON string.
    * @return The parsed response.
    */
   public static TokenResponse fromJson(final String json) {
      Map<String, Object> map = GSON.fromJson(json,
              new TypeToken<Map<String, Object>>(){}.getType());

      String error = map.containsKey("error") ? String.valueOf(map.get("error")) : null;
      if(error != null) {
         String errorDescription = map.containsKey("error_description") ?
                 String.valueOf(map.get("error_description")) : null;
         return new TokenResponse(null, null, 0, Optional.empty(), null,
                 Optional.of(error), Optional.ofNullable(errorDescription));
      }

      String accessToken = String.valueOf(map.get("access_token"));
      String tokenType = map.containsKey("token_type") ? String.valueOf(map.get("token_type")) : "Bearer";
      int expiresIn = map.containsKey("expires_in") ?
              ((Number)map.get("expires_in")).intValue() : 0;
      Optional<String> refreshToken = map.containsKey("refresh_token") ?
              Optional.of(String.valueOf(map.get("refresh_token"))) : Optional.empty();
      String scope = map.containsKey("scope") ? String.valueOf(map.get("scope")) : "";

      return new TokenResponse(accessToken, tokenType, expiresIn, refreshToken, scope,
              Optional.empty(), Optional.empty());
   }

   /**
    * Creates a token response.
    * @param accessToken The access token.
    * @param tokenType The token type.
    * @param expiresIn Expiration time in seconds.
    * @param refreshToken The refresh token.
    * @param scope The granted scope.
    * @param error The error code, if any.
    * @param errorDescription The error description, if any.
    */
   public TokenResponse(final String accessToken,
                        final String tokenType,
                        final int expiresIn,
                        final Optional<String> refreshToken,
                        final String scope,
                        final Optional<String> error,
                        final Optional<String> errorDescription) {
      this.accessToken = accessToken;
      this.tokenType = tokenType;
      this.expiresIn = expiresIn;
      this.refreshToken = refreshToken;
      this.scope = scope;
      this.error = error;
      this.errorDescription = errorDescription;
   }

   /**
    * Is this an error response?
    * @return {@code true} if error is present.
    */
   public boolean isError() {
      return error.isPresent();
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("accessToken", accessToken != null ? "[present]" : null)
              .add("tokenType", tokenType)
              .add("expiresIn", expiresIn)
              .add("refreshToken", refreshToken.isPresent() ? "[present]" : "empty")
              .add("scope", scope)
              .add("error", error.orElse(null))
              .add("errorDescription", errorDescription.orElse(null))
              .omitNullValues()
              .toString();
   }

   /**
    * The access token.
    */
   public final String accessToken;

   /**
    * The token type (always "Bearer").
    */
   public final String tokenType;

   /**
    * The token expiration in seconds.
    */
   public final int expiresIn;

   /**
    * The refresh token, if present.
    */
   public final Optional<String> refreshToken;

   /**
    * The granted scope.
    */
   public final String scope;

   /**
    * The error code, if this is an error response.
    */
   public final Optional<String> error;

   /**
    * The error description, if this is an error response.
    */
   public final Optional<String> errorDescription;
}
