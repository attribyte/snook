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
import org.eclipse.jetty.http.HttpHeader;

import javax.servlet.http.HttpServletRequest;

/**
 * Authenticate based on the value of an HTTP header.
 */
public abstract class HeaderAuthenticator<T> implements Authenticator<T> {

   /**
    * Gets the credentials from the request.
    * @param request The request.
    * @return The credentials, or {@code null} if none.
    */
   public String credentials(final HttpServletRequest request) {
      final String header = Strings.nullToEmpty(request.getHeader(credentialsHeader()));
      final String expectedScheme = Strings.emptyToNull(scheme());

      if(expectedScheme == null) {
         return Strings.emptyToNull(header);
      } else {
         if(header.length() < expectedScheme.length() + 2) {
            return null;
         }

         int schemeIndex = header.indexOf(' ');

         if(schemeIndex != expectedScheme.length()) {
            return null;
         }

         String checkScheme = header.substring(0, schemeIndex);
         if(!checkScheme.equalsIgnoreCase(expectedScheme)) {
            return null;
         }

         return header.substring(schemeIndex + 1);
      }
   }

   /**
    * The authentication scheme.
    * <p>
    *    If {@code null} or empty, no scheme is expected.
    * </p>
    * @return The scheme.
    */
   protected abstract String scheme();

   /**
    * The header (name) that contains credentials.
    * @return The name or {@code null} if none.
    */
   public String credentialsHeader() {
      return HttpHeader.AUTHORIZATION.asString();
   }
}
