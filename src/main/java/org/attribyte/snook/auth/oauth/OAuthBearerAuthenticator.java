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

import com.google.common.hash.HashCode;
import org.attribyte.snook.auth.Authenticator;
import org.attribyte.snook.auth.BearerAuthenticator;
import org.attribyte.snook.auth.oauth.model.OAuthAccessToken;
import org.attribyte.snook.auth.oauth.store.TokenStore;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * Bridges OAuth access tokens into snook's {@link BearerAuthenticator} system.
 * <p>
 *    Validates Bearer tokens by resolving them from a {@link TokenStore}.
 *    Checks for expiry. Returns the username of the token owner.
 * </p>
 * <p>
 *    Can be composed via {@code AnyAuthenticator} with existing API key auth.
 * </p>
 */
public class OAuthBearerAuthenticator extends BearerAuthenticator<Boolean> {

   /**
    * Creates an OAuth bearer authenticator.
    * @param tokenStore The token store.
    */
   public OAuthBearerAuthenticator(final TokenStore tokenStore) {
      super(tokenHash -> {
         Optional<OAuthAccessToken> token = tokenStore.resolveAccessToken(tokenHash);
         return token.filter(t -> !t.isExpired()).map(t -> t.username).orElse(null);
      });
      this.tokenStore = tokenStore;
   }

   @Override
   public Boolean authorized(final HttpServletRequest request) {
      return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
   }

   /**
    * Resolves the full access token from a request.
    * <p>
    *    Use this when you need scope information beyond just the username.
    * </p>
    * @param request The HTTP request.
    * @return The access token, or empty if not valid.
    */
   public Optional<OAuthAccessToken> resolveToken(final HttpServletRequest request) {
      String credentials = credentials(request);
      if(credentials == null) {
         return Optional.empty();
      }
      HashCode tokenHash = Authenticator.hashCredentials(credentials);
      return tokenStore.resolveAccessToken(tokenHash)
              .filter(t -> !t.isExpired());
   }

   private final TokenStore tokenStore;
}
