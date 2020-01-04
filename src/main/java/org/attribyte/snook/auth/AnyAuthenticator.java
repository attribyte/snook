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

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * Verify authorized by any in a sequence.
 * <p>
 *    The {@code authorizedUsername} returned is the first authorized.
 * </p>
 */
public class AnyAuthenticator extends MultiAuthenticator {

   public AnyAuthenticator(final List<Authenticator> authenticators) {
      super(authenticators, "Any");
   }

   @Override
   public boolean authorized(final HttpServletRequest request) {
      for(Authenticator authenticator : authenticators) {
         if(authenticator.authorized(request)) {
            return true;
         }
      }
      return false;
   }

   @Override
   public String authorizedUsername(final HttpServletRequest request) {
      for(Authenticator authenticator : authenticators) {
         String username = Strings.emptyToNull(authenticator.authorizedUsername(request));
         if(username != null) {
            return username;
         }
      }

      return null;
   }
}
