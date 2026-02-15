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
import com.google.common.hash.HashCode;
import org.attribyte.snook.auth.AuthenticationToken;
import org.attribyte.snook.auth.Authenticator;

import java.time.Instant;
import java.util.Collection;
import java.util.Optional;

/**
 * An OAuth 2.1 access token.
 */
public class OAuthAccessToken {

   /**
    * Creates an access token with a random token value.
    * @param clientId The client id.
    * @param username The username.
    * @param scopes The granted scopes.
    * @param lifetimeSeconds The token lifetime in seconds.
    * @return The access token.
    */
   public static OAuthAccessToken create(final String clientId,
                                         final String username,
                                         final Collection<String> scopes,
                                         final int lifetimeSeconds) {
      return create(clientId, username, scopes, lifetimeSeconds, Optional.empty());
   }

   /**
    * Creates an access token with a random token value.
    * @param clientId The client id.
    * @param username The username.
    * @param scopes The granted scopes.
    * @param lifetimeSeconds The token lifetime in seconds.
    * @param refreshTokenId The associated refresh token id.
    * @return The access token.
    */
   public static OAuthAccessToken create(final String clientId,
                                         final String username,
                                         final Collection<String> scopes,
                                         final int lifetimeSeconds,
                                         final Optional<String> refreshTokenId) {
      String token = AuthenticationToken.randomToken().toString();
      HashCode tokenHash = Authenticator.hashCredentials(token);
      return new OAuthAccessToken(token, tokenHash, clientId, username, scopes,
              Instant.now().plusSeconds(lifetimeSeconds), refreshTokenId);
   }

   /**
    * Creates an access token.
    * @param token The opaque token string.
    * @param tokenHash The SHA-256 hash for secure storage/lookup.
    * @param clientId The client id.
    * @param username The username.
    * @param scopes The granted scopes.
    * @param expiresAt The expiration time.
    * @param refreshTokenId The associated refresh token id.
    */
   public OAuthAccessToken(final String token,
                           final HashCode tokenHash,
                           final String clientId,
                           final String username,
                           final Collection<String> scopes,
                           final Instant expiresAt,
                           final Optional<String> refreshTokenId) {
      this.token = token;
      this.tokenHash = tokenHash;
      this.clientId = clientId;
      this.username = username;
      this.scopes = ImmutableSet.copyOf(scopes);
      this.expiresAt = expiresAt;
      this.refreshTokenId = refreshTokenId;
   }

   /**
    * Is this token expired?
    * @return {@code true} if expired.
    */
   public boolean isExpired() {
      return Instant.now().isAfter(expiresAt);
   }

   /**
    * The opaque bearer token.
    */
   public final String token;

   /**
    * The SHA-256 hash for secure storage/lookup.
    */
   public final HashCode tokenHash;

   /**
    * The client id.
    */
   public final String clientId;

   /**
    * The username.
    */
   public final String username;

   /**
    * The granted scopes.
    */
   public final ImmutableSet<String> scopes;

   /**
    * The expiration time.
    */
   public final Instant expiresAt;

   /**
    * The associated refresh token id, if any.
    */
   public final Optional<String> refreshTokenId;
}
