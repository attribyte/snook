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
import org.attribyte.snook.auth.Authenticator;
import org.attribyte.snook.auth.oauth.store.TokenStore;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * OAuth 2.0 token revocation endpoint (RFC 7009).
 * <p>
 *    Always returns 200 OK, even if the token is not found,
 *    to prevent token probing.
 * </p>
 */
@SuppressWarnings("serial")
public class RevocationEndpoint extends HttpServlet {

   /**
    * Creates a revocation endpoint.
    * @param tokenStore The token store.
    */
   public RevocationEndpoint(final TokenStore tokenStore) {
      this.tokenStore = tokenStore;
   }

   @Override
   protected void doPost(final HttpServletRequest request,
                         final HttpServletResponse response) throws IOException {

      String token = request.getParameter("token");
      String tokenTypeHint = request.getParameter("token_type_hint");

      if(Strings.isNullOrEmpty(token)) {
         OAuthError.writeJsonError(response, 400, OAuthError.INVALID_REQUEST, "Missing token parameter");
         return;
      }

      HashCode tokenHash = Authenticator.hashCredentials(token);

      if("refresh_token".equals(tokenTypeHint)) {
         tokenStore.revokeRefreshToken(tokenHash);
         tokenStore.revokeAccessToken(tokenHash);
      } else {
         // Default: try both, access token first
         tokenStore.revokeAccessToken(tokenHash);
         tokenStore.revokeRefreshToken(tokenHash);
      }

      // Always 200 OK per RFC 7009
      response.setStatus(200);
   }

   private final TokenStore tokenStore;
}
