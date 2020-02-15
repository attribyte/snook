/*
 * Copyright 2020 Attribyte, LLC
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
import com.google.common.collect.ImmutableList;
import com.google.common.hash.HashCode;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A simple authenticator for testing.
 */
public class TestAuthenticators {

   static class TestLoginAuthenticator extends MultiAuthenticator implements LoginAuthenticator<Boolean> {

      /**
       * Creates the test authenticator with a single username and password.
       * @param username The username.
       * @param password The password.
       */
      public TestLoginAuthenticator(final String username, final String password) {
         super(ImmutableList.of(), "Test");
         this.username = Strings.nullToEmpty(username);
         this.passwordHash = Authenticator.hashCredentials(Strings.nullToEmpty(password));
      }

      @Override
      public String authorizedUsername(final HttpServletRequest request) {
         return username;
      }

      @Override
      public Boolean doLogin(final String username, final String password,
                             final int tokenLifetimeSeconds,
                             final HttpServletResponse resp) throws IOException {
         if(Strings.nullToEmpty(username).equalsIgnoreCase(username) &&
                 passwordHash.equals(Authenticator.hashCredentials(password))) {
            return Boolean.TRUE;
         } else {
            return Boolean.FALSE;
         }
      }

      @Override
      public void doLogout(final HttpServletResponse resp) {
      }

      /**
       * The username.
       */
      protected final String username;

      /**
       * The password.
       */
      protected final HashCode passwordHash;
   }

   /**
    * Creates a single-user test authenticator that always authorizes the user.
    * @param username The username.
    * @param password The password.
    * @return The authenticator.
    */
   public static LoginAuthenticator<Boolean> testAuthenticator(final String username, final String password) {
      return new TestLoginAuthenticator(username, password);
   }
}
