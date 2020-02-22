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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.EnumSet;
import java.util.function.BiFunction;
import java.util.function.Function;

import static org.attribyte.snook.Cookies.cookieValue;

/**
 * An authenticator that validates an {@code HMACToken} sent as a cookie value.
 */
public abstract class HMACCookieAuthenticator<T> implements LoginAuthenticator<T> {


   /**
    * @see #HMACCookieAuthenticator(Cookies.CookieKey, Function, BiFunction, Function)
    */
   public static HMACCookieAuthenticator<Boolean> booleanAuthenticator(final Cookies.CookieKey cookieKey,
                                                                       final Function<String, HashFunction> hmacFunctions,
                                                                       final BiFunction<String, String, Boolean> checkPasswordFunction,
                                                                       final Function<String, String> hmacKeyFunction) {
      return booleanAuthenticator(cookieKey, hmacFunctions, checkPasswordFunction, hmacKeyFunction,
              HMACCookieSupplier.DEFAULT_COOKIE_OPTIONS);
   }

   /**
    * @see #HMACCookieAuthenticator(Cookies.CookieKey, Function, BiFunction, Function, EnumSet)
    */
   public static HMACCookieAuthenticator<Boolean> booleanAuthenticator(final Cookies.CookieKey cookieKey,
                                                                       final Function<String, HashFunction> hmacFunctions,
                                                                       final BiFunction<String, String, Boolean> checkPasswordFunction,
                                                                       final Function<String, String> hmacKeyFunction,
                                                                       final EnumSet<Cookies.Option> cookieOptions) {
      return new HMACCookieAuthenticator<Boolean>(cookieKey, hmacFunctions, checkPasswordFunction, hmacKeyFunction, cookieOptions) {
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
    * @param hmacFunctions A map of HMAC function vs key id.
    * @param checkPasswordFunction A function to check username/password.
    * @param hmacKeyFunction A function that returns the key id for a username.
    */
   public HMACCookieAuthenticator(final Cookies.CookieKey cookieKey,
                                  final Function<String, HashFunction> hmacFunctions,
                                  final BiFunction<String, String, Boolean> checkPasswordFunction,
                                  final Function<String, String> hmacKeyFunction) {
      this(cookieKey, hmacFunctions, checkPasswordFunction, hmacKeyFunction, HMACCookieSupplier.DEFAULT_COOKIE_OPTIONS);
   }

   /**
    * Creates an authenticator.
    * @param hmacFunctions A map of HMAC function vs key id.
    * @param checkPasswordFunction A function to check username/password.
    * @param hmacKeyFunction A function that returns the key id for a username.
    * @param cookieOptions The cookie options.
    */
   public HMACCookieAuthenticator(final Cookies.CookieKey cookieKey,
                                  final Function<String, HashFunction> hmacFunctions,
                                  final BiFunction<String, String, Boolean> checkPasswordFunction,
                                  final Function<String, String> hmacKeyFunction,
                                  final EnumSet<Cookies.Option> cookieOptions) {
      this.cookieKey = cookieKey;
      this.hmacFunctions = hmacFunctions;
      this.checkPasswordFunction = checkPasswordFunction;
      this.cookieSupplier = new HMACCookieSupplier(cookieKey, hmacFunctions, hmacKeyFunction, cookieOptions);
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

   @Override
   public T doLogin(final String username, final String password,
                    final int tokenLifetimeSeconds,
                    final HttpServletResponse resp) {

      if(!checkPasswordFunction.apply(username, password)) {
         return invalidCredentials(username);
      }

      return cookieSupplier.addCredentials(username, tokenLifetimeSeconds, resp) ?
              validCredentials(username) : invalidCredentials(username);
   }

   @Override
   public void doLogout(final HttpServletResponse resp) {
      cookieSupplier.removeCredentials(resp);
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
   private final Function<String, HashFunction> hmacFunctions;

   /**
    * The function used to check a username/password.
    */
   private final BiFunction<String, String, Boolean> checkPasswordFunction;

   /**
    * The cookie supplier.
    */
   private final HMACCookieSupplier cookieSupplier;
}
