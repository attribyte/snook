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
import com.google.common.hash.HashFunction;
import org.attribyte.snook.Cookies;

import javax.servlet.http.HttpServletResponse;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

public class HMACCookieSupplier implements CredentialsSupplier {

   /**
    * Creates an authenticator.
    * @param hmacFunctions A map of HMAC function vs key id.
    * @param hmacKeyFunction A function that returns the key id for a username.
    */
   public HMACCookieSupplier(final Cookies.CookieKey cookieKey,
                             final Function<String, HashFunction> hmacFunctions,
                             final Function<String, String> hmacKeyFunction) {
      this(cookieKey, hmacFunctions, hmacKeyFunction, DEFAULT_COOKIE_OPTIONS);
   }

   /**
    * Creates an authenticator.
    * @param hmacFunctions A map of HMAC function vs key id.
    * @param hmacKeyFunction A function that returns the key id for a username.
    * @param cookieOptions The cookie options.
    */
   public HMACCookieSupplier(final Cookies.CookieKey cookieKey,
                             final Function<String, HashFunction> hmacFunctions,
                             final Function<String, String> hmacKeyFunction,
                             final EnumSet<Cookies.Option> cookieOptions) {
      this.cookieKey = cookieKey;
      this.hmacFunctions = hmacFunctions;
      this.hmacKeyFunction = hmacKeyFunction;
      this.cookieOptions = cookieOptions == null ? DEFAULT_COOKIE_OPTIONS : cookieOptions;
   }

   @Override
   public boolean addCredentials(final String username,
                                 final int tokenLifetimeSeconds,
                                 final HttpServletResponse resp) {

      String keyId = hmacKeyFunction.apply(username);
      if(Strings.isNullOrEmpty(keyId)) {
         return false;
      }

      HashFunction hmacFunction = hmacFunctions.apply(keyId);
      if(hmacFunction == null) {
         return false;
      }

      HMACToken token = new HMACToken(username, tokenLifetimeSeconds, TimeUnit.SECONDS);
      Cookies.setCookie(cookieKey, token.toCookieValue(keyId, hmacFunction), tokenLifetimeSeconds, cookieOptions, resp);
      return true;
   }

   @Override
   public void removeCredentials(final HttpServletResponse resp) {
      Cookies.removeCookie(cookieKey, resp);
   }

   /**
    * The cookie key
    */
   public final Cookies.CookieKey cookieKey;

   /**
    * A map of (keyed) HMAC function vs key id.
    */
   private final Function<String, HashFunction> hmacFunctions;

   /**
    * A function that returns the HMAC key for a username.
    */
   private final Function<String, String> hmacKeyFunction;

   /**
    * The cookie options to be set with the authentication token cookie.
    */
   private final EnumSet<Cookies.Option> cookieOptions;

   /**
    * The default cookie options to be set with the authentication token cookie.
    */
   public static final EnumSet<Cookies.Option> DEFAULT_COOKIE_OPTIONS = EnumSet.of(Cookies.Option.HTTP_ONLY, Cookies.Option.SECURE_ONLY);
}
