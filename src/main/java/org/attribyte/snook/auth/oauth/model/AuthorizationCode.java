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

package org.attribyte.snook.auth.oauth.model;

import com.google.common.collect.ImmutableSet;
import org.attribyte.snook.auth.AuthenticationToken;

import java.time.Instant;
import java.util.Collection;

/**
 * An OAuth 2.1 authorization code with PKCE challenge.
 */
public class AuthorizationCode {

   /**
    * Creates an authorization code with a random code value.
    * @param clientId The client id.
    * @param username The authenticated user who approved.
    * @param redirectUri The redirect URI used in the request.
    * @param codeChallenge The PKCE S256 challenge.
    * @param scopes The approved scopes.
    * @param lifetimeSeconds The code lifetime in seconds.
    * @return The authorization code.
    */
   public static AuthorizationCode create(final String clientId,
                                          final String username,
                                          final String redirectUri,
                                          final String codeChallenge,
                                          final Collection<String> scopes,
                                          final int lifetimeSeconds) {
      return new AuthorizationCode(
              AuthenticationToken.randomToken().toString(),
              clientId, username, redirectUri, codeChallenge,
              scopes, Instant.now().plusSeconds(lifetimeSeconds)
      );
   }

   /**
    * Creates an authorization code.
    * @param code The code value.
    * @param clientId The client id.
    * @param username The authenticated user.
    * @param redirectUri The redirect URI.
    * @param codeChallenge The PKCE challenge.
    * @param scopes The approved scopes.
    * @param expiresAt The expiration time.
    */
   public AuthorizationCode(final String code,
                            final String clientId,
                            final String username,
                            final String redirectUri,
                            final String codeChallenge,
                            final Collection<String> scopes,
                            final Instant expiresAt) {
      this.code = code;
      this.clientId = clientId;
      this.username = username;
      this.redirectUri = redirectUri;
      this.codeChallenge = codeChallenge;
      this.scopes = ImmutableSet.copyOf(scopes);
      this.expiresAt = expiresAt;
   }

   /**
    * Is this code expired?
    * @return {@code true} if expired.
    */
   public boolean isExpired() {
      return Instant.now().isAfter(expiresAt);
   }

   /**
    * The random opaque code string.
    */
   public final String code;

   /**
    * The client id.
    */
   public final String clientId;

   /**
    * The authenticated user who approved.
    */
   public final String username;

   /**
    * The redirect URI used in the request.
    */
   public final String redirectUri;

   /**
    * The PKCE S256 challenge.
    */
   public final String codeChallenge;

   /**
    * The approved scopes.
    */
   public final ImmutableSet<String> scopes;

   /**
    * The expiration time.
    */
   public final Instant expiresAt;
}
