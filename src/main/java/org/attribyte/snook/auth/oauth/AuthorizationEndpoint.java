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
import com.google.common.collect.ImmutableSet;
import org.attribyte.snook.auth.Authenticator;
import org.attribyte.snook.auth.oauth.model.AuthorizationCode;
import org.attribyte.snook.auth.oauth.model.OAuthClient;
import org.attribyte.snook.auth.oauth.store.AuthorizationCodeStore;
import org.attribyte.snook.auth.oauth.store.ClientStore;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * OAuth 2.1 authorization endpoint.
 * <p>
 *    Handles the authorization request flow: validates the client,
 *    checks user authentication, delegates to a consent handler,
 *    and issues authorization codes.
 * </p>
 */
@SuppressWarnings("serial")
public class AuthorizationEndpoint extends HttpServlet {

   /**
    * Creates an authorization endpoint.
    * @param userAuthenticator The authenticator for the resource owner.
    * @param clientStore The client store.
    * @param codeStore The authorization code store.
    * @param consentHandler The consent handler.
    * @param codeLifetimeSeconds The authorization code lifetime in seconds.
    */
   public AuthorizationEndpoint(final Authenticator<?> userAuthenticator,
                                final ClientStore clientStore,
                                final AuthorizationCodeStore codeStore,
                                final ConsentHandler consentHandler,
                                final int codeLifetimeSeconds) {
      this(userAuthenticator, clientStore, codeStore, consentHandler, codeLifetimeSeconds, null);
   }

   /**
    * Creates an authorization endpoint.
    * @param userAuthenticator The authenticator for the resource owner.
    * @param clientStore The client store.
    * @param codeStore The authorization code store.
    * @param consentHandler The consent handler.
    * @param codeLifetimeSeconds The authorization code lifetime in seconds.
    * @param loginUrl The URL to redirect to if the user is not authenticated, or {@code null}.
    */
   public AuthorizationEndpoint(final Authenticator<?> userAuthenticator,
                                final ClientStore clientStore,
                                final AuthorizationCodeStore codeStore,
                                final ConsentHandler consentHandler,
                                final int codeLifetimeSeconds,
                                final String loginUrl) {
      this.userAuthenticator = userAuthenticator;
      this.clientStore = clientStore;
      this.codeStore = codeStore;
      this.consentHandler = consentHandler;
      this.codeLifetimeSeconds = codeLifetimeSeconds;
      this.loginUrl = loginUrl;
   }

   @Override
   protected void doGet(final HttpServletRequest request,
                        final HttpServletResponse response) throws IOException {
      handleAuthorizationRequest(request, response);
   }

   /**
    * Handles the authorization request (GET).
    */
   private void handleAuthorizationRequest(final HttpServletRequest request,
                                           final HttpServletResponse response) throws IOException {

      String responseType = request.getParameter("response_type");
      String clientId = request.getParameter("client_id");
      String redirectUri = request.getParameter("redirect_uri");
      String scope = request.getParameter("scope");
      String state = request.getParameter("state");
      String codeChallenge = request.getParameter("code_challenge");
      String codeChallengeMethod = request.getParameter("code_challenge_method");

      // Validate response_type
      if(!"code".equals(responseType)) {
         if(!Strings.isNullOrEmpty(redirectUri)) {
            response.sendRedirect(OAuthError.errorRedirectUrl(redirectUri,
                    OAuthError.UNSUPPORTED_RESPONSE_TYPE, "Only 'code' response type is supported", state));
         } else {
            OAuthError.writeJsonError(response, 400, OAuthError.UNSUPPORTED_RESPONSE_TYPE,
                    "Only 'code' response type is supported");
         }
         return;
      }

      // Validate client
      if(Strings.isNullOrEmpty(clientId)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_REQUEST, "Missing client_id");
         return;
      }

      Optional<OAuthClient> clientOpt = clientStore.getClient(clientId);
      if(clientOpt.isEmpty()) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_CLIENT, "Unknown client");
         return;
      }

      OAuthClient client = clientOpt.get();

      // Validate redirect_uri
      if(Strings.isNullOrEmpty(redirectUri)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_REQUEST, "Missing redirect_uri");
         return;
      }

      if(!client.validateRedirectUri(redirectUri)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_REQUEST, "Invalid redirect_uri");
         return;
      }

      // Validate PKCE (required per OAuth 2.1)
      if(Strings.isNullOrEmpty(codeChallenge)) {
         response.sendRedirect(OAuthError.errorRedirectUrl(redirectUri,
                 OAuthError.INVALID_REQUEST, "Missing code_challenge (PKCE required)", state));
         return;
      }

      if(!Strings.isNullOrEmpty(codeChallengeMethod) && !"S256".equals(codeChallengeMethod)) {
         response.sendRedirect(OAuthError.errorRedirectUrl(redirectUri,
                 OAuthError.INVALID_REQUEST, "Only S256 code_challenge_method is supported", state));
         return;
      }

      // Parse and validate scopes
      Set<String> requestedScopes = parseScopes(scope);
      if(!client.allowedScopes.containsAll(requestedScopes)) {
         response.sendRedirect(OAuthError.errorRedirectUrl(redirectUri,
                 OAuthError.INVALID_SCOPE, "Requested scope exceeds client's allowed scopes", state));
         return;
      }

      // Check user authentication
      String username = userAuthenticator.authorizedUsername(request);
      if(username == null) {
         if(loginUrl != null) {
            String returnUrl = request.getRequestURL().toString();
            String queryString = request.getQueryString();
            if(queryString != null) {
               returnUrl += "?" + queryString;
            }
            response.sendRedirect(loginUrl + "?return_url=" +
                    URLEncoder.encode(returnUrl, StandardCharsets.UTF_8));
         } else {
            response.sendRedirect(OAuthError.errorRedirectUrl(redirectUri,
                    OAuthError.ACCESS_DENIED, "User not authenticated", state));
         }
         return;
      }

      // Store request parameters in the session/request for the POST handler
      String approveUrl = buildApproveUrl(request, clientId, redirectUri, scope, state, codeChallenge);

      consentHandler.renderConsent(request, response, client, requestedScopes, state, approveUrl);
   }

   @Override
   protected void doPost(final HttpServletRequest request,
                         final HttpServletResponse response) throws IOException {
      handleApproval(request, response);
   }

   /**
    * Handles consent approval (POST).
    */
   private void handleApproval(final HttpServletRequest request,
                               final HttpServletResponse response) throws IOException {

      // Verify user is still authenticated
      String username = userAuthenticator.authorizedUsername(request);
      if(username == null) {
         OAuthError.writeJsonError(response, 401, OAuthError.ACCESS_DENIED, "User not authenticated");
         return;
      }

      String clientId = request.getParameter("client_id");
      String redirectUri = request.getParameter("redirect_uri");
      String scope = request.getParameter("scope");
      String state = request.getParameter("state");
      String codeChallenge = request.getParameter("code_challenge");

      if(Strings.isNullOrEmpty(clientId) || Strings.isNullOrEmpty(redirectUri) || Strings.isNullOrEmpty(codeChallenge)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_REQUEST, "Missing required parameters");
         return;
      }

      // Re-validate client and redirect URI
      Optional<OAuthClient> clientOpt = clientStore.getClient(clientId);
      if(clientOpt.isEmpty() || !clientOpt.get().validateRedirectUri(redirectUri)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_REQUEST, "Invalid client or redirect_uri");
         return;
      }

      Set<String> scopes = parseScopes(scope);

      // Create and store authorization code
      AuthorizationCode authCode = AuthorizationCode.create(
              clientId, username, redirectUri, codeChallenge, scopes, codeLifetimeSeconds);
      codeStore.store(authCode);

      // Redirect with code
      StringBuilder redirectUrl = new StringBuilder(redirectUri);
      redirectUrl.append(redirectUri.contains("?") ? "&" : "?");
      redirectUrl.append("code=").append(URLEncoder.encode(authCode.code, StandardCharsets.UTF_8));
      if(!Strings.isNullOrEmpty(state)) {
         redirectUrl.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
      }
      response.sendRedirect(redirectUrl.toString());
   }

   /**
    * Builds the approval URL with all parameters needed for the POST handler.
    */
   private String buildApproveUrl(final HttpServletRequest request,
                                  final String clientId,
                                  final String redirectUri,
                                  final String scope,
                                  final String state,
                                  final String codeChallenge) {
      StringBuilder url = new StringBuilder(request.getRequestURL().toString());
      url.append("?client_id=").append(URLEncoder.encode(clientId, StandardCharsets.UTF_8));
      url.append("&redirect_uri=").append(URLEncoder.encode(redirectUri, StandardCharsets.UTF_8));
      url.append("&code_challenge=").append(URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8));
      if(!Strings.isNullOrEmpty(scope)) {
         url.append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8));
      }
      if(!Strings.isNullOrEmpty(state)) {
         url.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
      }
      return url.toString();
   }

   /**
    * Parses a space-delimited scope string.
    */
   static Set<String> parseScopes(final String scope) {
      if(Strings.isNullOrEmpty(scope)) {
         return ImmutableSet.of();
      }
      return Arrays.stream(scope.trim().split("\\s+"))
              .filter(s -> !s.isEmpty())
              .collect(Collectors.toUnmodifiableSet());
   }

   private final Authenticator<?> userAuthenticator;
   private final ClientStore clientStore;
   private final AuthorizationCodeStore codeStore;
   private final ConsentHandler consentHandler;
   private final int codeLifetimeSeconds;
   private final String loginUrl;
}
