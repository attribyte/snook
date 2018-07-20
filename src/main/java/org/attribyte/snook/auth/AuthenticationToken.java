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

package org.attribyte.snook.auth;

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.hash.HashCode;

import java.security.SecureRandom;

/**
 * An authentication token associated with a username.
 */
public class AuthenticationToken {

   /**
    * Creates a random token.
    * @param username The username.
    */
   public AuthenticationToken(final String username) {
      this.username = username;
      byte[] tokenBytes = new byte[TOKEN_BYTES];
      rnd.nextBytes(tokenBytes);
      this.token = HashCode.fromBytes(tokenBytes);
   }

   /**
    * Creates a token from a string.
    * @param username The username.
    * @param tokenString The token value as a string.
    */
   public AuthenticationToken(final String username, final String tokenString) {
      this.username = username;
      this.token = HashCode.fromString(tokenString);
   }

   /**
    * Creates a token.
    * @param username The username.
    * @param token The token.
    */
   public AuthenticationToken(final String username, final HashCode token) {
      this.username = username;
      this.token = token;
   }

   @Override
   public boolean equals(final Object o) {
      if(this == o) return true;
      if(o == null || getClass() != o.getClass()) return false;
      final AuthenticationToken that = (AuthenticationToken)o;
      return Objects.equal(username, that.username) &&
              Objects.equal(token, that.token);
   }

   @Override
   public int hashCode() {
      return Objects.hashCode(username, token);
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("username", username)
              .add("token", token)
              .toString();
   }

   /**
    * The username.
    */
   public final String username;

   /**
    * The token.
    */
   public final HashCode token;

   /**
    * The number of bytes in a token.
    */
   public static final int TOKEN_BYTES = 16;

   /**
    * The secure random number generator.
    */
   private static final SecureRandom rnd = new SecureRandom();
}