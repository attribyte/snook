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

import javax.servlet.http.HttpServletRequest;

/**
 * An authenticator that excludes all requests.
 */
public class DenyAllAuthenticator extends Authenticator {

   @Override
   public boolean authorized(final HttpServletRequest request) {
      return false;
   }

   @Override
   public String scheme() {
      return "Deny";
   }
}