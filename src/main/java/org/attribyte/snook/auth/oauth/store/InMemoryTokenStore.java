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
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory token store for development and testing.
 */
public class InMemoryTokenStore implements TokenStore {

   private final ConcurrentHashMap<HashCode, OAuthAccessToken> accessTokens = new ConcurrentHashMap<>();
   private final ConcurrentHashMap<HashCode, OAuthRefreshToken> refreshTokens = new ConcurrentHashMap<>();

   @Override
   public void storeAccessToken(final OAuthAccessToken token) {
      accessTokens.put(token.tokenHash, token);
   }

   @Override
   public Optional<OAuthAccessToken> resolveAccessToken(final HashCode tokenHash) {
      return Optional.ofNullable(accessTokens.get(tokenHash));
   }

   @Override
   public void revokeAccessToken(final HashCode tokenHash) {
      accessTokens.remove(tokenHash);
   }

   @Override
   public void storeRefreshToken(final OAuthRefreshToken token) {
      refreshTokens.put(token.tokenHash, token);
   }

   @Override
   public Optional<OAuthRefreshToken> resolveRefreshToken(final HashCode tokenHash) {
      return Optional.ofNullable(refreshTokens.get(tokenHash));
   }

   @Override
   public void revokeRefreshToken(final HashCode tokenHash) {
      refreshTokens.remove(tokenHash);
   }

   @Override
   public void revokeAllForUser(final String username) {
      accessTokens.entrySet().removeIf(e -> e.getValue().username.equals(username));
      refreshTokens.entrySet().removeIf(e -> e.getValue().username.equals(username));
   }

   /**
    * Removes expired tokens.
    * @return The number of expired tokens removed.
    */
   public int cleanup() {
      int removed = 0;
      var atIter = accessTokens.entrySet().iterator();
      while(atIter.hasNext()) {
         if(atIter.next().getValue().isExpired()) {
            atIter.remove();
            removed++;
         }
      }
      var rtIter = refreshTokens.entrySet().iterator();
      while(rtIter.hasNext()) {
         if(rtIter.next().getValue().isExpired()) {
            rtIter.remove();
            removed++;
         }
      }
      return removed;
   }
}
