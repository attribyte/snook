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
import com.google.common.hash.HashFunction;
import org.attribyte.snook.Cookies;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;
import java.util.function.Function;

import static org.attribyte.snook.Cookies.cookieValue;

/**
 * An authenticator that validates an {@code HMACToken} sent as a cookie value.
 */
public class HMACCookieAuthenticator implements LoginAuthenticator {

   /**
    * Creates an authenticator.
    * @param hmacFunctions A map of HMAC function vs key id.
    * @param checkPasswordFunction A function to check username/password.
    */
   public HMACCookieAuthenticator(final Cookies.CookieKey cookieKey,
                                  final Function<String, HashFunction> hmacFunctions,
                                  final BiFunction<String, String, Boolean> checkPasswordFunction,
                                  final Function<String, String> hmacKeyFunction) {
      this.cookieKey = cookieKey;
      this.hmacFunctions = hmacFunctions;
      this.checkPasswordFunction = checkPasswordFunction;
      this.hmacKeyFunction = hmacKeyFunction;
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

   /**
    * Performs a login.
    * <p>
    *    If username + password is valid, creates a new HMAC token
    *    and sets the value as a response cookie. Otherwise, does nothing
    *    and returns {@code false}.
    * </p>
    * @param username The username.
    * @param password The password.
    * @param tokenLifetimeSeconds The authentication token lifetime in seconds.
    * @param resp The response.
    * @return Was the password valid and token saved and set as a cookie?
    * @throws IOException if credentials save failed.
    */
   public boolean doLogin(final String username, final String password,
                          final int tokenLifetimeSeconds,
                          final HttpServletResponse resp) throws IOException {

      if(!checkPasswordFunction.apply(username, password)) {
         return false;
      }

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
    * A function that returns the HMAC key for a username.
    */
   private final Function<String, String> hmacKeyFunction;

   /**
    * The cookie options to be set with the authentication token cookie.
    */
   private static final EnumSet<Cookies.Option> cookieOptions = EnumSet.of(Cookies.Option.HTTP_ONLY, Cookies.Option.SECURE_ONLY);
}