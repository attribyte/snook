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

package org.attribyte.snook.auth.oauth.client;

import org.attribyte.snook.auth.oauth.PKCE;

/**
 * An immutable PKCE code_verifier + code_challenge pair.
 */
public class PKCEPair {

   /**
    * Generates a new PKCE pair.
    * @return The PKCE pair.
    */
   public static PKCEPair generate() {
      String verifier = PKCE.generateVerifier();
      String challenge = PKCE.computeChallenge(verifier);
      return new PKCEPair(verifier, challenge);
   }

   /**
    * Creates a PKCE pair.
    * @param verifier The code verifier.
    * @param challenge The S256 challenge.
    */
   public PKCEPair(final String verifier, final String challenge) {
      this.verifier = verifier;
      this.challenge = challenge;
   }

   /**
    * The code verifier (kept by the client for the token exchange).
    */
   public final String verifier;

   /**
    * The S256 code challenge (sent in the authorization request).
    */
   public final String challenge;
}
