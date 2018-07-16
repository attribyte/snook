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

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableSet;
import com.google.common.hash.HashCode;

import javax.servlet.http.HttpServletRequest;
import java.util.function.Function;

/**
 * Authenticator for 'Bearer' auth.
 */
public class BearerAuthenticator extends Authenticator {

   /**
    * Creates the authenticator.
    * @param validCredentials A set containing valid (securely hashed) credentials.
    * @param credentialsValidator A function that indicates if securely hashed credentials are valid.
    */
   public BearerAuthenticator(final ImmutableSet<HashCode> validCredentials,
                              final Function<HashCode, Boolean> credentialsValidator) {
      this.validCredentials = validCredentials;
      this.credentialsValidator = credentialsValidator;
   }

   @Override
   public boolean authorized(final HttpServletRequest request) {
      String credentials = credentials(request);
      if(credentials == null) {
         return false;
      }

      HashCode hashedCredentials = credentialHasher.hashString(credentials, Charsets.US_ASCII);
      if(validCredentials.contains(hashedCredentials)) {
         return true;
      } else {
         return credentialsValidator.apply(hashedCredentials);
      }
   }

   @Override
   public String scheme() {
      return "Bearer";
   }

   /**
    * An immutable set containing hashes of valid credentials.
    */
   private final ImmutableSet<HashCode> validCredentials;

   /**
    * A function that gets hashed credentials for a username.
    */
   private final Function<HashCode, Boolean> credentialsValidator;
}
