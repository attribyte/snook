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
import java.util.function.Function;

/**
 * An authenticator that returns a custom object if a user is authenticated.
 */
public class CustomAuthenticator<T> {

   /**
    * Creates the custom authenticator.
    * @param authenticator The authenticator.
    * @param authenticatedFunction A function that returns a custom object when the user is authenticated.
    */
   public CustomAuthenticator(final Authenticator authenticator,
                              final Function<String, T> authenticatedFunction) {
      this.authenticator = authenticator;
      this.authenticatedFunction = authenticatedFunction;
   }

   /**
    * Check for an authorized user and return permission.
    * @param request The request.
    * @return A custom object if authenticated or {@code null} if not.
    */
   public T authenticate(final HttpServletRequest request) {
      String username = authenticator.authorizedUsername(request);
      return Strings.isNullOrEmpty(username) ? null : authenticatedFunction.apply(username);
   }

   /**
    * The authenticator.
    */
   private final Authenticator authenticator;

   /**
    * The function called to return a custom object when a user is authenticated.
    */
   private final Function<String, T> authenticatedFunction;
}
