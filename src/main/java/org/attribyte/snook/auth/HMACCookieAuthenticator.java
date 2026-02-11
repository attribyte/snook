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

import com.google.common.hash.HashFunction;
import org.attribyte.snook.Cookies;

import jakarta.servlet.http.HttpServletRequest;
import java.util.function.Function;

import static org.attribyte.snook.Cookies.cookieValue;

/**
 * An authenticator that validates an {@code HMACToken} sent as a cookie value.
 */
public abstract class HMACCookieAuthenticator<T> implements Authenticator<T> {

   /**
    * @see #HMACCookieAuthenticator(Cookies.CookieKey, Function)
    */
   public static HMACCookieAuthenticator<Boolean> booleanAuthenticator(final Cookies.CookieKey cookieKey,
                                                                       final Function<String, HashFunction> hmacFunctions) {
      return new HMACCookieAuthenticator<Boolean>(cookieKey, hmacFunctions) {
         @Override
         public Boolean validCredentials(final String username) {
            return Boolean.TRUE;
         }

         @Override
         public Boolean invalidCredentials(final String username) {
            return Boolean.FALSE;
         }
      };
   }

   /**
    * Creates an authenticator.
    * @param cookieKey The cookie key.
    * @param hmacFunctions The HMAC functions.
    */
   public HMACCookieAuthenticator(final Cookies.CookieKey cookieKey,
                                  final Function<String, HashFunction> hmacFunctions) {
      this.cookieKey = cookieKey;
      this.hmacFunctions = hmacFunctions;
   }

   @Override
   public String authorizedUsername(final HttpServletRequest request) {
      HMACToken validToken = HMACToken.validate(credentials(request), hmacFunctions);
      return (validToken != null && !validToken.isExpired()) ? validToken.username : null;
   }

   @Override
   public String schemeName() {
      return "HMAC";
   }

   @Override
   public String credentials(final HttpServletRequest request) {
      return cookieValue(cookieKey.name, request);
   }

   @Override
   public T authorized(final HttpServletRequest request) {
      String authorizedUsername = authorizedUsername(request);
      return authorizedUsername != null ? validCredentials(authorizedUsername) : invalidCredentials(authorizedUsername);
   }

   /**
    * Supplies credentials for a valid login.
    * @param username The username.
    * @return The credentials.
    */
   public abstract T validCredentials(final String username);

   /**
    * Supplies credentials for an invalid login.
    * @param username The username.
    * @return The credentials.
    */
   public abstract T invalidCredentials(final String username);

   /**
    * The cookie key
    */
   public final Cookies.CookieKey cookieKey;

   /**
    * A map of (keyed) HMAC function vs key id.
    */
   protected final Function<String, HashFunction> hmacFunctions;
}
