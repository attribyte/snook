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
import com.google.common.cache.Cache;
import com.google.common.hash.HashCode;
import org.attribyte.util.Pair;
import org.mindrot.jbcrypt.BCrypt;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;
import java.util.function.Function;

/**
 * Authenticator for 'Basic' auth with password stored with BCrypt.
 * A user-supplied cache contains the hashed credentials of previously
 * authenticated users to avoid slow BCrypt on every call.
 * Credentials dumped from storage are secure from off-line attack.
 * Credentials dumped from memory are not secure from off-line attack.
 */
public class BasicBCryptAuthenticator extends Authenticator {

   /**
    * Creates the authenticator.
    * @param validCredentials A cache containing valid (securely hashed) credentials.
    * @param usernameCredentials A function that returns the BCrypt password hash for a username.
    * Should return a random/constant BCrypt hash with typical rounds for invalid users.
    */
   public BasicBCryptAuthenticator(final Cache<HashCode, Boolean> validCredentials,
                                   final Function<String, String> usernameCredentials) {
      this.validCredentials = validCredentials;
      this.usernameCredentials = usernameCredentials;
   }

   @Override
   public boolean authorized(final HttpServletRequest request) {
      return authorizedUsername(request) != null;
   }

   @Override
   public String authorizedUsername(final HttpServletRequest request) {
      Optional<Credentials> maybeCredentials = Credentials.credentials(request);
      if(!maybeCredentials.isPresent()) {
         return null;
      }

      Credentials credentials = maybeCredentials.get();
      if(!credentials.scheme.equalsIgnoreCase("basic")) {
         return null;
      }

      Pair<String, String> upass = BasicAuthenticator.usernamePassword(credentials);
      if(upass == null) {
         return null;
      }

      HashCode hashedCredentials = credentials.hashCredentials();
      if(validCredentials.getIfPresent(hashedCredentials) != null) {
         return upass.getKey();
      }

      String bcrypt = usernameCredentials.apply(upass.getKey());
      if(Strings.isNullOrEmpty(bcrypt)) {
         return null;
      }

      boolean valid = BCrypt.checkpw(upass.getValue(), bcrypt);
      if(valid) {
         validCredentials.put(hashedCredentials, Boolean.TRUE);
         return upass.getKey();
      } else {
         return null;
      }
   }

   @Override
   public String scheme() {
      return "Basic";
   }

   /**
    * A cache for valid credentials.
    */
   private final Cache<HashCode, Boolean> validCredentials;

   /**
    * A function that returns the BCrypt password hash for a username.
    */
   private final Function<String, String> usernameCredentials;
}