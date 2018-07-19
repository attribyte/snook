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

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.hash.HashCode;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.function.Function;

/**
 * Authenticator for 'Bearer' auth.
 */
public class BearerAuthenticator extends Authenticator {

   /**
    * Creates the authenticator.
    * @param validCredentials A map containing username vs valid (securely hashed) credentials.
    * @param credentialsValidator A function that indicates if securely hashed credentials are valid.
    */
   public BearerAuthenticator(final Map<HashCode, String> validCredentials,
                              final Function<HashCode, String> credentialsValidator) {
      this.validCredentials = validCredentials != null ? ImmutableMap.copyOf(validCredentials) : ImmutableMap.of();
      this.credentialsValidator = credentialsValidator;
   }

   @Override
   public String authorizedUsername(final HttpServletRequest request) {
      String credentials = credentials(request);
      if(credentials == null) {
         return null;
      }
      HashCode hashedCredentials = hashCredentials(credentials);
      String username = validCredentials.get(hashedCredentials);
      return username != null ? username : credentialsValidator.apply(hashedCredentials);
   }

   @Override
   public boolean authorized(final HttpServletRequest request) {
      String credentials = credentials(request);
      if(credentials == null) {
         return false;
      }
      HashCode hashedCredentials = hashCredentials(credentials);
      return validCredentials.containsKey(hashedCredentials) || !Strings.isNullOrEmpty(credentialsValidator.apply(hashedCredentials));
   }

   @Override
   public String scheme() {
      return "Bearer";
   }

   /**
    * An immutable map of username vs hashed credentials.
    */
   private final ImmutableMap<HashCode, String> validCredentials;

   /**
    * A function that gets a username from hashed credentials.
    */
   private final Function<HashCode, String> credentialsValidator;
}
