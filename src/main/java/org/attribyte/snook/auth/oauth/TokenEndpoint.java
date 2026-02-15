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

import com.google.common.base.Strings;
import com.google.common.hash.HashCode;
import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import org.attribyte.snook.auth.Authenticator;
import org.attribyte.snook.auth.oauth.model.AuthorizationCode;
import org.attribyte.snook.auth.oauth.model.OAuthAccessToken;
import org.attribyte.snook.auth.oauth.model.OAuthClient;
import org.attribyte.snook.auth.oauth.model.OAuthRefreshToken;
import org.attribyte.snook.auth.oauth.store.AuthorizationCodeStore;
import org.attribyte.snook.auth.oauth.store.ClientStore;
import org.attribyte.snook.auth.oauth.store.TokenStore;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * OAuth 2.1 token endpoint.
 * <p>
 *    Handles authorization code exchange and token refresh.
 * </p>
 */
@SuppressWarnings("serial")
public class TokenEndpoint extends HttpServlet {

   private static final Gson GSON = new Gson();

   /**
    * Creates a token endpoint.
    * @param clientStore The client store.
    * @param codeStore The authorization code store.
    * @param tokenStore The token store.
    * @param accessTokenLifetimeSeconds The access token lifetime in seconds.
    * @param refreshTokenLifetimeSeconds The refresh token lifetime in seconds.
    */
   public TokenEndpoint(final ClientStore clientStore,
                        final AuthorizationCodeStore codeStore,
                        final TokenStore tokenStore,
                        final int accessTokenLifetimeSeconds,
                        final int refreshTokenLifetimeSeconds) {
      this.clientStore = clientStore;
      this.codeStore = codeStore;
      this.tokenStore = tokenStore;
      this.accessTokenLifetimeSeconds = accessTokenLifetimeSeconds;
      this.refreshTokenLifetimeSeconds = refreshTokenLifetimeSeconds;
   }

   @Override
   protected void doPost(final HttpServletRequest request,
                         final HttpServletResponse response) throws IOException {

      String grantType = request.getParameter("grant_type");

      if("authorization_code".equals(grantType)) {
         handleAuthorizationCode(request, response);
      } else if("refresh_token".equals(grantType)) {
         handleRefreshToken(request, response);
      } else {
         OAuthError.writeJsonError(response, 400, OAuthError.UNSUPPORTED_GRANT_TYPE,
                 "Supported grant types: authorization_code, refresh_token");
      }
   }

   /**
    * Handles grant_type=authorization_code.
    */
   private void handleAuthorizationCode(final HttpServletRequest request,
                                        final HttpServletResponse response) throws IOException {

      String code = request.getParameter("code");
      String redirectUri = request.getParameter("redirect_uri");
      String clientId = request.getParameter("client_id");
      String codeVerifier = request.getParameter("code_verifier");

      if(Strings.isNullOrEmpty(code) || Strings.isNullOrEmpty(redirectUri) ||
         Strings.isNullOrEmpty(clientId) || Strings.isNullOrEmpty(codeVerifier)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_REQUEST,
                 "Missing required parameter (code, redirect_uri, client_id, code_verifier)");
         return;
      }

      // Authenticate client if confidential
      Optional<OAuthClient> clientOpt = clientStore.getClient(clientId);
      if(clientOpt.isEmpty()) {
         OAuthError.writeJsonError(response, 401, OAuthError.INVALID_CLIENT, "Unknown client");
         return;
      }

      OAuthClient client = clientOpt.get();
      if(client.confidential && !authenticateClient(request, client)) {
         OAuthError.writeJsonError(response, 401, OAuthError.INVALID_CLIENT, "Client authentication failed");
         return;
      }

      // Consume authorization code (one-time use)
      Optional<AuthorizationCode> codeOpt = codeStore.consume(code);
      if(codeOpt.isEmpty()) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_GRANT, "Invalid or already used authorization code");
         return;
      }

      AuthorizationCode authCode = codeOpt.get();

      // Validate code
      if(authCode.isExpired()) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_GRANT, "Authorization code expired");
         return;
      }

      if(!authCode.clientId.equals(clientId)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_GRANT, "Client id mismatch");
         return;
      }

      if(!authCode.redirectUri.equals(redirectUri)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_GRANT, "Redirect URI mismatch");
         return;
      }

      // PKCE validation
      if(!PKCE.validate(codeVerifier, authCode.codeChallenge)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_GRANT, "PKCE validation failed");
         return;
      }

      // Generate tokens
      OAuthRefreshToken refreshToken = OAuthRefreshToken.create(
              clientId, authCode.username, authCode.scopes, refreshTokenLifetimeSeconds);
      tokenStore.storeRefreshToken(refreshToken);

      OAuthAccessToken accessToken = OAuthAccessToken.create(
              clientId, authCode.username, authCode.scopes, accessTokenLifetimeSeconds,
              Optional.of(refreshToken.tokenHash.toString()));
      tokenStore.storeAccessToken(accessToken);

      writeTokenResponse(response, accessToken, refreshToken);
   }

   /**
    * Handles grant_type=refresh_token.
    */
   private void handleRefreshToken(final HttpServletRequest request,
                                   final HttpServletResponse response) throws IOException {

      String refreshTokenStr = request.getParameter("refresh_token");
      String clientId = request.getParameter("client_id");
      String scope = request.getParameter("scope");

      if(Strings.isNullOrEmpty(refreshTokenStr) || Strings.isNullOrEmpty(clientId)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_REQUEST,
                 "Missing required parameter (refresh_token, client_id)");
         return;
      }

      // Authenticate client if confidential
      Optional<OAuthClient> clientOpt = clientStore.getClient(clientId);
      if(clientOpt.isEmpty()) {
         OAuthError.writeJsonError(response, 401, OAuthError.INVALID_CLIENT, "Unknown client");
         return;
      }

      OAuthClient client = clientOpt.get();
      if(client.confidential && !authenticateClient(request, client)) {
         OAuthError.writeJsonError(response, 401, OAuthError.INVALID_CLIENT, "Client authentication failed");
         return;
      }

      // Resolve refresh token
      HashCode refreshHash = Authenticator.hashCredentials(refreshTokenStr);
      Optional<OAuthRefreshToken> refreshOpt = tokenStore.resolveRefreshToken(refreshHash);
      if(refreshOpt.isEmpty()) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_GRANT, "Invalid refresh token");
         return;
      }

      OAuthRefreshToken oldRefresh = refreshOpt.get();

      if(oldRefresh.isExpired()) {
         tokenStore.revokeRefreshToken(refreshHash);
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_GRANT, "Refresh token expired");
         return;
      }

      if(!oldRefresh.clientId.equals(clientId)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_GRANT, "Client id mismatch");
         return;
      }

      // Validate requested scope is a subset of the original
      Set<String> newScopes;
      if(!Strings.isNullOrEmpty(scope)) {
         newScopes = AuthorizationEndpoint.parseScopes(scope);
         if(!oldRefresh.scopes.containsAll(newScopes)) {
            OAuthError.writeJsonError(response, 400, OAuthError.INVALID_SCOPE,
                    "Requested scope exceeds original grant");
            return;
         }
      } else {
         newScopes = oldRefresh.scopes;
      }

      // Revoke old refresh token and issue new tokens (token rotation)
      tokenStore.revokeRefreshToken(refreshHash);

      OAuthRefreshToken newRefresh = OAuthRefreshToken.create(
              clientId, oldRefresh.username, newScopes, refreshTokenLifetimeSeconds);
      tokenStore.storeRefreshToken(newRefresh);

      OAuthAccessToken newAccess = OAuthAccessToken.create(
              clientId, oldRefresh.username, newScopes, accessTokenLifetimeSeconds,
              Optional.of(newRefresh.tokenHash.toString()));
      tokenStore.storeAccessToken(newAccess);

      writeTokenResponse(response, newAccess, newRefresh);
   }

   /**
    * Authenticates a confidential client via Basic auth header or client_secret body param.
    */
   private boolean authenticateClient(final HttpServletRequest request, final OAuthClient client) {
      if(client.clientSecretHash.isEmpty()) {
         return false;
      }
      HashCode expectedHash = client.clientSecretHash.get();

      // Try Authorization: Basic header first
      String authHeader = request.getHeader("Authorization");
      if(!Strings.isNullOrEmpty(authHeader) && authHeader.startsWith("Basic ")) {
         try {
            String decoded = new String(
                    BaseEncoding.base64().decode(authHeader.substring(6)), StandardCharsets.UTF_8);
            int colonPos = decoded.indexOf(':');
            if(colonPos > 0) {
               String secret = decoded.substring(colonPos + 1);
               return Authenticator.hashCredentials(secret).equals(expectedHash);
            }
         } catch(IllegalArgumentException e) {
            // Invalid base64
         }
      }

      // Try client_secret body param
      String clientSecret = request.getParameter("client_secret");
      if(!Strings.isNullOrEmpty(clientSecret)) {
         return Authenticator.hashCredentials(clientSecret).equals(expectedHash);
      }

      return false;
   }

   /**
    * Writes the JSON token response.
    */
   private void writeTokenResponse(final HttpServletResponse response,
                                   final OAuthAccessToken accessToken,
                                   final OAuthRefreshToken refreshToken) throws IOException {
      response.setStatus(200);
      response.setContentType("application/json;charset=UTF-8");
      response.setHeader("Cache-Control", "no-store");
      response.setHeader("Pragma", "no-cache");

      Map<String, Object> json = new LinkedHashMap<>();
      json.put("access_token", accessToken.token);
      json.put("token_type", "Bearer");
      json.put("expires_in", accessTokenLifetimeSeconds);
      json.put("refresh_token", refreshToken.token);
      if(!accessToken.scopes.isEmpty()) {
         json.put("scope", String.join(" ", accessToken.scopes));
      }

      PrintWriter writer = response.getWriter();
      writer.write(GSON.toJson(json));
      writer.flush();
   }

   private final ClientStore clientStore;
   private final AuthorizationCodeStore codeStore;
   private final TokenStore tokenStore;
   private final int accessTokenLifetimeSeconds;
   private final int refreshTokenLifetimeSeconds;
}
