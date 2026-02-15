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

/**
 * Store for OAuth authorization codes.
 */
public interface AuthorizationCodeStore {

   /**
    * Stores an authorization code.
    * @param code The authorization code.
    */
   void store(AuthorizationCode code);

   /**
    * Consumes an authorization code (one-time use).
    * <p>
    *    Returns and removes the code atomically. Prevents replay attacks.
    * </p>
    * @param code The authorization code string.
    * @return The authorization code, or empty if not found.
    */
   Optional<AuthorizationCode> consume(String code);
}
