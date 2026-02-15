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

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;

/**
 * Orchestrates the client side of OAuth 2.1 Authorization Code + PKCE flow.
 * <p>
 *    Uses {@code java.net.http.HttpClient} for HTTP — no new dependencies.
 * </p>
 */
public class OAuthClientFlow {

   /**
    * The result of building an authorization request URL.
    */
   public static class AuthorizationRequest {

      /**
       * Creates an authorization request.
       * @param url The full authorization URL to redirect the user to.
       * @param state The state parameter (for CSRF protection).
       * @param pkcePair The PKCE pair (client must save the verifier for step 2).
       */
      public AuthorizationRequest(final String url, final String state, final PKCEPair pkcePair) {
         this.url = url;
         this.state = state;
         this.pkcePair = pkcePair;
      }

      /**
       * The full authorization URL.
       */
      public final String url;

      /**
       * The state parameter.
       */
      public final String state;

      /**
       * The PKCE pair (save the verifier for the code exchange).
       */
      public final PKCEPair pkcePair;
   }

   /**
    * Creates an OAuth client flow.
    * @param clientId The client id.
    * @param clientSecret The client secret, or empty for public clients.
    * @param authorizeUrl The authorization endpoint URL.
    * @param tokenUrl The token endpoint URL.
    */
   public OAuthClientFlow(final String clientId,
                          final Optional<String> clientSecret,
                          final String authorizeUrl,
                          final String tokenUrl) {
      this.clientId = clientId;
      this.clientSecret = clientSecret;
      this.authorizeUrl = authorizeUrl;
      this.tokenUrl = tokenUrl;
      this.httpClient = HttpClient.newHttpClient();
   }

   /**
    * Builds the authorization URL the user should visit (step 1).
    * @param redirectUri The redirect URI to receive the callback.
    * @param scopes The scopes to request.
    * @param state The state parameter for CSRF protection.
    * @return The authorization request with URL, state, and PKCE pair.
    */
   public AuthorizationRequest buildAuthorizationRequest(final String redirectUri,
                                                         final Set<String> scopes,
                                                         final String state) {
      PKCEPair pkcePair = PKCEPair.generate();
      StringBuilder url = new StringBuilder(authorizeUrl);
      url.append("?response_type=code");
      url.append("&client_id=").append(encode(clientId));
      url.append("&redirect_uri=").append(encode(redirectUri));
      url.append("&code_challenge=").append(encode(pkcePair.challenge));
      url.append("&code_challenge_method=S256");
      if(!scopes.isEmpty()) {
         url.append("&scope=").append(encode(String.join(" ", scopes)));
      }
      url.append("&state=").append(encode(state));
      return new AuthorizationRequest(url.toString(), state, pkcePair);
   }

   /**
    * Exchanges an authorization code for tokens (step 2).
    * @param code The authorization code from the callback.
    * @param redirectUri The same redirect URI used in step 1.
    * @param codeVerifier The PKCE code verifier from step 1.
    * @return The token response.
    * @throws IOException on HTTP error.
    */
   public TokenResponse exchangeCode(final String code,
                                     final String redirectUri,
                                     final String codeVerifier) throws IOException {
      StringBuilder body = new StringBuilder();
      body.append("grant_type=authorization_code");
      body.append("&code=").append(encode(code));
      body.append("&redirect_uri=").append(encode(redirectUri));
      body.append("&client_id=").append(encode(clientId));
      body.append("&code_verifier=").append(encode(codeVerifier));

      return postTokenRequest(body.toString());
   }

   /**
    * Refreshes an expired access token (step 3).
    * @param refreshToken The refresh token.
    * @return The token response with new tokens.
    * @throws IOException on HTTP error.
    */
   public TokenResponse refreshToken(final String refreshToken) throws IOException {
      StringBuilder body = new StringBuilder();
      body.append("grant_type=refresh_token");
      body.append("&refresh_token=").append(encode(refreshToken));
      body.append("&client_id=").append(encode(clientId));

      return postTokenRequest(body.toString());
   }

   /**
    * Posts a request to the token endpoint.
    */
   private TokenResponse postTokenRequest(final String formBody) throws IOException {
      HttpRequest.Builder builder = HttpRequest.newBuilder()
              .uri(URI.create(tokenUrl))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .POST(HttpRequest.BodyPublishers.ofString(formBody));

      // Confidential clients include Basic auth
      clientSecret.ifPresent(secret -> {
         String credentials = Base64.getEncoder()
                 .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
         builder.header("Authorization", "Basic " + credentials);
      });

      try {
         HttpResponse<String> response = httpClient.send(
                 builder.build(), HttpResponse.BodyHandlers.ofString());
         return TokenResponse.fromJson(response.body());
      } catch(InterruptedException e) {
         Thread.currentThread().interrupt();
         throw new IOException("Token request interrupted", e);
      }
   }

   private static String encode(final String value) {
      return URLEncoder.encode(value, StandardCharsets.UTF_8);
   }

   private final String clientId;
   private final Optional<String> clientSecret;
   private final String authorizeUrl;
   private final String tokenUrl;
   private final HttpClient httpClient;
}
