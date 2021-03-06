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

public interface CredentialsSupplier {

   /**
    * A credentials supplier that does nothing.
    */
   public static CredentialsSupplier NOOP = new CredentialsSupplier() {
      @Override
      public boolean addCredentials(final String username, final int tokenLifetimeSeconds, final HttpServletResponse resp) {
         return true;
      }

      @Override
      public void removeCredentials(final HttpServletResponse resp) {
      }
   };

   /**
    * Adds credentials to a response.
    * @param username The username.
    * @param tokenLifetimeSeconds The response token lifetime in seconds, if any.
    * @param resp The response to add credentials to.
    * @return Were credentials supplied?
    */
   public boolean addCredentials(final String username,
                                 final int tokenLifetimeSeconds,
                                 final HttpServletResponse resp);

   /**
    * Remove credentials from the response, if possible.
    * @param resp The response.
    */
   public void removeCredentials(final HttpServletResponse resp);
}
