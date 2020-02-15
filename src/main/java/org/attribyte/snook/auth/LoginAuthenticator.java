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

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public interface LoginAuthenticator<T> extends Authenticator<T> {

   /**
    * Performs a login.
    * <p>
    *    If username + password is valid, sets a header or a cookie on the response
    *    and returns {@code true}.
    *    Otherwise, does nothing and returns {@code false}.
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
                    final HttpServletResponse resp) throws IOException;


   /**
    * Performs a logout, if possible.
    * @param resp The response.
    */
   public void doLogout(final HttpServletResponse resp);
}
