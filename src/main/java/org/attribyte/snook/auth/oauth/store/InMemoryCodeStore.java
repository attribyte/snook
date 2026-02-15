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

import org.attribyte.snook.auth.oauth.model.AuthorizationCode;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory authorization code store for development and testing.
 */
public class InMemoryCodeStore implements AuthorizationCodeStore {

   private final ConcurrentHashMap<String, AuthorizationCode> codes = new ConcurrentHashMap<>();

   @Override
   public void store(final AuthorizationCode code) {
      codes.put(code.code, code);
   }

   @Override
   public Optional<AuthorizationCode> consume(final String code) {
      return Optional.ofNullable(codes.remove(code));
   }

   /**
    * Removes expired authorization codes.
    * @return The number of expired codes removed.
    */
   public int cleanup() {
      int removed = 0;
      var iter = codes.entrySet().iterator();
      while(iter.hasNext()) {
         if(iter.next().getValue().isExpired()) {
            iter.remove();
            removed++;
         }
      }
      return removed;
   }
}
