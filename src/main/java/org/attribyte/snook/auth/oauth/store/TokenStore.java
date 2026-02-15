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

package org.attribyte.snook.auth.oauth.store;

import com.google.common.hash.HashCode;
import org.attribyte.snook.auth.oauth.model.OAuthAccessToken;
import org.attribyte.snook.auth.oauth.model.OAuthRefreshToken;

import java.util.Optional;

/**
 * Store for OAuth access and refresh tokens.
 * <p>
 *    Tokens are always looked up by hash, never by raw token value.
 * </p>
 */
public interface TokenStore {

   /**
    * Stores an access token.
    * @param token The access token.
    */
   void storeAccessToken(OAuthAccessToken token);

   /**
    * Resolves an access token by its hash.
    * @param tokenHash The SHA-256 hash of the raw token.
    * @return The access token, or empty if not found.
    */
   Optional<OAuthAccessToken> resolveAccessToken(HashCode tokenHash);

   /**
    * Revokes an access token.
    * @param tokenHash The SHA-256 hash of the raw token.
    */
   void revokeAccessToken(HashCode tokenHash);

   /**
    * Stores a refresh token.
    * @param token The refresh token.
    */
   void storeRefreshToken(OAuthRefreshToken token);

   /**
    * Resolves a refresh token by its hash.
    * @param tokenHash The SHA-256 hash of the raw token.
    * @return The refresh token, or empty if not found.
    */
   Optional<OAuthRefreshToken> resolveRefreshToken(HashCode tokenHash);

   /**
    * Revokes a refresh token.
    * @param tokenHash The SHA-256 hash of the raw token.
    */
   void revokeRefreshToken(HashCode tokenHash);

   /**
    * Revokes all tokens for a user.
    * @param username The username.
    */
   void revokeAllForUser(String username);
}
