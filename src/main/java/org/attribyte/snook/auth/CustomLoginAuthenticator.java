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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.function.Function;

/**
 * An authenticator that returns a custom object for authentication and login.
 */
public class CustomLoginAuthenticator<T> extends CustomAuthenticator<T> {

   /**
    * Creates the custom authenticator.
    * @param authenticator The authenticator.
    * @param authenticatedFunction A function that returns a custom object when the user is authenticated.
    */
   public CustomLoginAuthenticator(final LoginAuthenticator authenticator,
                                   final Function<String, T> authenticatedFunction) {
      super(authenticator, authenticatedFunction);
   }

   /**
    * Check for an authorized user and return permission.
    * @param request The request.
    * @return A custom object if authenticated or {@code null} if not.
    */
   public T authenticate(final HttpServletRequest request) {
      return super.authenticate(request);
   }

   /**
    * Performs a login.
    * <p>
    *    If username + password is valid, sets a header or a cookie on the response
    *    and returns the custom object. Otherwise, does nothing and returns {@code null}.
    * </p>
    * @param username The username.
    * @param password The password.
    * @param tokenLifetimeSeconds The authentication token lifetime in seconds.
    * @param resp The response.
    * @return Was the password valid and token saved and set as a cookie?
    * @throws IOException if credentials save failed.
    */
   public T doLogin(final String username, final String password,
                    final int tokenLifetimeSeconds,
                    final HttpServletResponse resp) throws IOException {
      if(((LoginAuthenticator)authenticator).doLogin(username, password, tokenLifetimeSeconds, resp)) {
         return authenticatedFunction.apply(username);
      } else {
         return null;
      }
   }
}
