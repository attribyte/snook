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

import com.google.common.base.Charsets;
import com.google.common.base.Strings;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import org.eclipse.jetty.http.HttpHeader;

import javax.servlet.http.HttpServletRequest;

/**
 * Authenticate HTTP requests.
 */
public abstract class Authenticator {

   /**
    * Gets the credentials from the request.
    * @param request The request.
    * @return The credentials, or {@code null} if none.
    */
   public String credentials(final HttpServletRequest request) {
      String header = Strings.nullToEmpty(request.getHeader(HttpHeader.AUTHORIZATION.asString()));
      if(header.length() < scheme().length() + 2) {
         return null;
      }

      int schemeIndex = header.indexOf(' ');

      if(schemeIndex != scheme().length()) {
         return null;
      }

      String checkScheme = header.substring(0, schemeIndex);
      if(!checkScheme.equalsIgnoreCase(scheme())) {
         return null;
      }

      return header.substring(schemeIndex + 1);
   }

   /**
    * Securely hash the credentials.
    * Note that Guava {@code HashCode} is implemented with constant-time equals.
    * @param credentials The credentials.
    * @return The hash code.
    */
   public static HashCode hashCredentials(final String credentials) {
      return credentialHasher.hashString(credentials, Charsets.UTF_8);
   }

   /**
    * The authentication scheme.
    * @return The scheme.
    */
   public abstract String scheme();

   /**
    * Determine if a request is authorized.
    * @param request The request.
    * @return Is the request authorized?
    */
   public abstract boolean authorized(final HttpServletRequest request);

   /**
    * Gets the authorized username.
    * @param request The request.
    * @return The authorized username or {@code null} if not authorized.
    */
   public abstract String authorizedUsername(final HttpServletRequest request);

   /**
    * The hash function for credentials.
    */
   protected static final HashFunction credentialHasher = Hashing.sha256();

   /**
    * Base64 encoding.
    */
   protected static final BaseEncoding base64Encoding = BaseEncoding.base64();
}