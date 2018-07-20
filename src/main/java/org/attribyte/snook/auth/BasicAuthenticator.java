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
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.hash.HashCode;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;
import java.util.function.Function;

/**
 * Authenticator for 'Basic' auth.
 */
public class BasicAuthenticator extends LoginAuthenticator {

   /**
    * Creates the authenticator.
    * @param validCredentials A set containing valid (securely hashed) credentials.
    * @param usernameCredentials A function that returns securely hashed credentials for a username.
    */
   public BasicAuthenticator(final Set<HashCode> validCredentials,
                             final Function<String, HashCode> usernameCredentials) {
      this.validCredentials = validCredentials != null ? ImmutableSet.copyOf(validCredentials) : ImmutableSet.of();
      this.usernameCredentials = usernameCredentials;
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
      }

      String username = username(request);
      if(username == null) {
         return false;
      }

      HashCode checkCredentials = usernameCredentials.apply(username);
      return checkCredentials != null && checkCredentials.equals(hashedCredentials);
   }

   @Override
   public String authorizedUsername(final HttpServletRequest request) {
      String credentials = credentials(request);
      if(credentials == null) {
         return null;
      }

      String username = username(request);
      if(username == null) {
         return null;
      }

      HashCode hashedCredentials = credentialHasher.hashString(credentials, Charsets.US_ASCII);
      if(validCredentials.contains(hashedCredentials)) {
         return username;
      }

      HashCode checkCredentials = usernameCredentials.apply(username);
      return checkCredentials != null && checkCredentials.equals(hashedCredentials) ? username : null;
   }

   @Override
   public String username(final HttpServletRequest request) {
      String credentials = credentials(request);
      if(credentials == null) {
         return null;
      }

      String upass = new String(base64Encoding.decode(credentials));
      int userIndex = upass.indexOf(':');
      return userIndex < 1 ? null : upass.substring(0, userIndex);
   }

   @Override
   public HashCode hashCredentials(final String username, final String password) {
      return hashCredentials(buildCredentials(username, password));
   }

   /**
    * Merge a username and password into a single credentials string.
    * @param username The username.
    * @param password The password.
    * @return The credentials.
    */
   public static String buildCredentials(final String username, final String password) {
      return base64Encoding.encode((Strings.nullToEmpty(username) + ":" + Strings.nullToEmpty(password)).getBytes(Charsets.UTF_8));
   }

   @Override
   public String scheme() {
      return "Basic";
   }

   /**
    * An immutable set containing hashes of valid credentials.
    */
   private final ImmutableSet<HashCode> validCredentials;

   /**
    * A function that gets hashed credentials for a username.
    */
   private final Function<String, HashCode> usernameCredentials;
}