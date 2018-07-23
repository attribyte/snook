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
import java.util.Optional;

public class Credentials {

   /**
    * Gets credentials from the 'Authorization' header in a servlet request.
    * @param request The request.
    * @return The credentials or {@code empty} if none.
    */
   public static final Optional<Credentials> credentials(final HttpServletRequest request) {
      return credentials(request.getHeader(HttpHeader.AUTHORIZATION.asString()));
   }

   /**
    * Creates credentials from a header value of the format [scheme] [credentials].
    * @return The credentials or {@code empty} if none.
    */
   public static final Optional<Credentials> credentials(final String header) {

      if(Strings.isNullOrEmpty(header)) {
         return Optional.empty();
      }

      int pos = header.indexOf(' ');
      if(pos < 1) { //First space can't be at the beginning
         return Optional.empty();
      }

      if(pos == header.length() - 1) {
         return Optional.of(new Credentials(header.substring(0, pos), ""));
      } else {
         return Optional.of(new Credentials(header.substring(0, pos), header.substring(pos + 1)));
      }
   }

   /**
    * Creates credentials.
    * @param scheme The scheme.
    * @param value The value.
    */
   public Credentials(final String scheme, final String value) {
      this.scheme = scheme;
      this.value = value;
   }

   /**
    * The scheme.
    */
   public final String scheme;

   /**
    * The value.
    */
   public final String value;
}