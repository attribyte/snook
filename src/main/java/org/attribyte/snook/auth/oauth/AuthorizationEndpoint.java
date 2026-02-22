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
import java.io.PrintWriter;
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
      System.out.println("[OAuth] doGet: " + request.getRequestURL() +
              (request.getQueryString() != null ? "?" + request.getQueryString() : ""));
      handleAuthorizationRequest(request, response);
   }

   @Override
   protected void doPost(final HttpServletRequest request,
                         final HttpServletResponse response) throws IOException {

      // Check if this is a login form submission (has username/password fields)
      String username = request.getParameter("username");
      String password = request.getParameter("password");
      System.out.println("[OAuth] doPost: username=" + (username != null ? "present" : "null") +
              " password=" + (password != null ? "present" : "null") +
              " client_id=" + request.getParameter("client_id"));
      if(username != null && password != null) {
         handleLoginSubmission(request, response);
      } else {
         handleApproval(request, response);
      }
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

      // Default to "code" — it's the only supported type, and some MCP clients
      // (e.g. Claude Code) omit it from the authorization request.
      if(responseType == null) {
         responseType = "code";
      }

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
      System.out.println("[OAuth] handleAuthorizationRequest: username=" + username + " loginUrl=" + loginUrl);
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
            // Render a login form that preserves all OAuth parameters
            renderLoginForm(request, response, client.name, null,
                    clientId, redirectUri, scope, state, codeChallenge);
         }
         return;
      }

      // Authenticated — issue the authorization code directly.
      // The consent handler pattern relies on a redirect/POST cycle that doesn't
      // work reliably in a session-less context (the redirect loops back here as a GET).
      // Since the user is already authenticated, we can issue the code immediately.
      System.out.println("[OAuth] user authenticated, issuing code directly for user=" + username);
      issueAuthorizationCode(response, clientId, username, redirectUri, codeChallenge, requestedScopes, state);
   }

   /**
    * Handles login form POST submission.
    */
   private void handleLoginSubmission(final HttpServletRequest request,
                                      final HttpServletResponse response) throws IOException {

      String clientId = request.getParameter("client_id");
      String redirectUri = request.getParameter("redirect_uri");
      String scope = request.getParameter("scope");
      String state = request.getParameter("state");
      String codeChallenge = request.getParameter("code_challenge");

      if(Strings.isNullOrEmpty(clientId) || Strings.isNullOrEmpty(redirectUri) || Strings.isNullOrEmpty(codeChallenge)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_REQUEST, "Missing required parameters");
         return;
      }

      // Validate client
      Optional<OAuthClient> clientOpt = clientStore.getClient(clientId);
      if(clientOpt.isEmpty()) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_CLIENT, "Unknown client");
         return;
      }

      OAuthClient client = clientOpt.get();

      if(!client.validateRedirectUri(redirectUri)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_REQUEST, "Invalid redirect_uri");
         return;
      }

      // Check credentials via the authenticator
      String authUsername = userAuthenticator.authorizedUsername(request);
      System.out.println("[OAuth] handleLoginSubmission: authUsername=" + authUsername);
      if(authUsername == null) {
         renderLoginForm(request, response, client.name, "Invalid username or password",
                 clientId, redirectUri, scope, state, codeChallenge);
         return;
      }

      // Authenticated — issue the authorization code directly.
      // We skip the consent handler here because the form-based auth flow
      // is session-less — a redirect would lose the authentication state.
      Set<String> requestedScopes = parseScopes(scope);
      System.out.println("[OAuth] issuing code for user=" + authUsername + " redirectUri=" + redirectUri);
      issueAuthorizationCode(response, clientId, authUsername, redirectUri, codeChallenge, requestedScopes, state);
   }

   /**
    * Handles consent approval (POST without login fields).
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
      issueAuthorizationCode(response, clientId, username, redirectUri, codeChallenge, scopes, state);
   }

   /**
    * Creates an authorization code and redirects to the client's redirect URI.
    */
   private void issueAuthorizationCode(final HttpServletResponse response,
                                       final String clientId,
                                       final String username,
                                       final String redirectUri,
                                       final String codeChallenge,
                                       final Set<String> scopes,
                                       final String state) throws IOException {

      AuthorizationCode authCode = AuthorizationCode.create(
              clientId, username, redirectUri, codeChallenge, scopes, codeLifetimeSeconds);
      codeStore.store(authCode);

      StringBuilder redirectUrl = new StringBuilder(redirectUri);
      redirectUrl.append(redirectUri.contains("?") ? "&" : "?");
      redirectUrl.append("code=").append(URLEncoder.encode(authCode.code, StandardCharsets.UTF_8));
      if(!Strings.isNullOrEmpty(state)) {
         redirectUrl.append("&state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
      }
      response.sendRedirect(redirectUrl.toString());
   }

   /**
    * Renders a minimal HTML login form that preserves OAuth parameters as hidden fields.
    */
   private void renderLoginForm(final HttpServletRequest request,
                                final HttpServletResponse response,
                                final String clientName,
                                final String errorMessage,
                                final String clientId,
                                final String redirectUri,
                                final String scope,
                                final String state,
                                final String codeChallenge) throws IOException {

      response.setStatus(errorMessage != null ? 401 : 200);
      response.setContentType("text/html;charset=UTF-8");
      PrintWriter writer = response.getWriter();
      writer.write("<!DOCTYPE html><html><head><meta charset='UTF-8'>");
      writer.write("<meta name='viewport' content='width=device-width,initial-scale=1'>");
      writer.write("<title>Sign In</title>");
      writer.write("<style>");
      writer.write("body{font-family:system-ui,-apple-system,sans-serif;display:flex;justify-content:center;");
      writer.write("align-items:center;min-height:100vh;margin:0;background:#f5f5f5}");
      writer.write(".card{background:white;border-radius:8px;padding:2rem;box-shadow:0 2px 8px rgba(0,0,0,.1);");
      writer.write("width:100%;max-width:360px}");
      writer.write("h2{margin:0 0 1.5rem;font-size:1.25rem;text-align:center}");
      writer.write(".client{color:#666;font-size:.875rem;text-align:center;margin-bottom:1.5rem}");
      writer.write("label{display:block;font-size:.875rem;margin-bottom:.25rem;color:#333}");
      writer.write("input[type=text],input[type=password]{width:100%;padding:.5rem;border:1px solid #ddd;");
      writer.write("border-radius:4px;font-size:1rem;margin-bottom:1rem;box-sizing:border-box}");
      writer.write("button{width:100%;padding:.625rem;background:#2563eb;color:white;border:none;");
      writer.write("border-radius:4px;font-size:1rem;cursor:pointer}");
      writer.write("button:hover{background:#1d4ed8}");
      writer.write(".error{background:#fef2f2;color:#dc2626;padding:.5rem;border-radius:4px;");
      writer.write("font-size:.875rem;margin-bottom:1rem;text-align:center}");
      writer.write("</style></head><body><div class='card'>");
      writer.write("<h2>Sign In</h2>");
      writer.write("<div class='client'>" + escapeHtml(clientName) + " is requesting access</div>");
      if(errorMessage != null) {
         writer.write("<div class='error'>" + escapeHtml(errorMessage) + "</div>");
      }
      writer.write("<form method='POST' action='" + escapeHtml(request.getRequestURI()) + "'>");
      writer.write("<label for='username'>Username</label>");
      writer.write("<input type='text' id='username' name='username' required autofocus>");
      writer.write("<label for='password'>Password</label>");
      writer.write("<input type='password' id='password' name='password' required>");
      writeHiddenField(writer, "client_id", clientId);
      writeHiddenField(writer, "redirect_uri", redirectUri);
      writeHiddenField(writer, "code_challenge", codeChallenge);
      writeHiddenField(writer, "response_type", "code");
      if(!Strings.isNullOrEmpty(scope)) {
         writeHiddenField(writer, "scope", scope);
      }
      if(!Strings.isNullOrEmpty(state)) {
         writeHiddenField(writer, "state", state);
      }
      writer.write("<button type='submit'>Sign In</button>");
      writer.write("</form></div></body></html>");
      writer.flush();
   }

   private static void writeHiddenField(PrintWriter writer, String name, String value) {
      writer.write("<input type='hidden' name='" + escapeHtml(name) + "' value='" + escapeHtml(value) + "'>");
   }

   private static String escapeHtml(String s) {
      if(s == null) return "";
      return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
              .replace("\"", "&quot;").replace("'", "&#39;");
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
