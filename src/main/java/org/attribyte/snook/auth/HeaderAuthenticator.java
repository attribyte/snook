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

import com.google.common.net.HttpHeaders;
import org.attribyte.api.http.Header;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import jakarta.servlet.http.HttpServletRequest;

import static com.google.common.base.Strings.isNullOrEmpty;

/**
 * Authenticate based on the value of an HTTP header.
 */
public abstract class HeaderAuthenticator<T> implements Authenticator<T> {

   /**
    * Creates a credentials header to be added to a request.
    * @param scheme the scheme.
    * @param credentialsHeader the credentials header name.
    * @param credentialsValue The credentials value.
    * @return The input response builder.
    */
   public static Header requestHeader(@Nullable final String scheme,
                                      @NonNull final String credentialsHeader,
                                      final String credentialsValue) {
      if(isNullOrEmpty(scheme)) {
         return new Header(credentialsHeader, credentialsValue);
      } else {
         return new Header(credentialsHeader, scheme + " " + credentialsValue);
      }
   }

   /**
    * Creates a credentials header to be added to a request.
    * @param credentialsValue The credentials header vaulue.
    * @return The header.
    */
   public Header requestHeader(final String credentialsValue) {
      return requestHeader(scheme(), credentialsHeader(), credentialsValue);
   }

   /**
    * Gets the credentials from the default ({@code Authorization}) header.
    * @param expectedScheme The expected scheme.
    * @param request The request.
    * @return The credentials, or {@code null} if none.
    */
   public static String credentials(final String expectedScheme,
                                    final HttpServletRequest request) {
      return credentials(expectedScheme, HttpHeaders.AUTHORIZATION, request);
   }

   /**
    * Gets the credentials from the request.
    * @param expectedScheme The expected scheme.
    * @param credentialsHeader The credentials header name.
    * @param request The request.
    * @return The credentials, or {@code null} if none.
    */
   public static String credentials(final String expectedScheme,
                                    final String credentialsHeader,
                                    final HttpServletRequest request) {
      final String header = request.getHeader(credentialsHeader);

      if(isNullOrEmpty(header)) {
         return null;
      }

      if(isNullOrEmpty(expectedScheme)) {
         return header;
      }

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

   /**
    * Gets the credentials from the request.
    * @param request The request.
    * @return The credentials, or {@code null} if none.
    */
   public String credentials(final HttpServletRequest request) {
      return credentials(scheme(), credentialsHeader(), request);
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
      return HttpHeaders.AUTHORIZATION;
   }
}
