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
 * Verify all authenticators in a sequence.
 * <p>
 *    The {@code authorizedUsername} returned is the last authorized.
 * </p>
 */
public class AllAuthenticator extends MultiAuthenticator {

   public AllAuthenticator(final List<Authenticator<?>> authenticators) {
      super(authenticators, "All");
   }

   @Override
   public Boolean authorized(final HttpServletRequest request) {
      for(Authenticator<?> authenticator : authenticators) {
         if(isNullOrFalse(authenticator.authorized(request))) {
            return Boolean.FALSE;
         }
      }
      return Boolean.TRUE;
   }

   @Override
   public String authorizedUsername(final HttpServletRequest request) {
      String lastUsername = null;
      for(Authenticator<?> authenticator : authenticators) {
         lastUsername = Strings.emptyToNull(authenticator.authorizedUsername(request));
         if(lastUsername == null) {
            return null;
         }
      }
      return lastUsername;
   }
}
