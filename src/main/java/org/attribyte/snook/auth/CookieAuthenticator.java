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

import com.google.common.collect.ImmutableMap;
import com.google.common.hash.HashCode;
import org.attribyte.snook.Cookies;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.function.Function;

import static org.attribyte.snook.Cookies.cookieValue;

/**
 * Authenticator where a token is sent as the value of a cookie.
 */
public abstract class CookieAuthenticator<T> implements Authenticator<T> {

   /**
    * @see #booleanAuthenticator(Cookies.CookieKey, Map, Function)
    */
   public static CookieAuthenticator<Boolean> booleanAuthenticator(final Cookies.CookieKey cookieKey,
                                                                   final Map<HashCode, String> validCredentials,
                                                                   final Function<HashCode, String> credentialsValidator) {
      return new CookieAuthenticator<Boolean>(cookieKey, validCredentials, credentialsValidator) {
         @Override
         public Boolean authorized(final HttpServletRequest request) {
            return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
         }
      };
   }

   /**
    * Creates the authenticator.
    * @param cookieKey The key that identifies the cookie.
    * @param validCredentials A map containing username vs valid (securely hashed) credentials.
    * @param credentialsValidator A function that indicates if securely hashed credentials are valid.
    */
   public CookieAuthenticator(final Cookies.CookieKey cookieKey,
                              final Map<HashCode, String> validCredentials,
                              final Function<HashCode, String> credentialsValidator) {
      this.validCredentials = validCredentials != null ? ImmutableMap.copyOf(validCredentials) : ImmutableMap.of();
      this.credentialsValidator = credentialsValidator;
      this.cookieKey = cookieKey;
   }

   @Override
   public String credentials(final HttpServletRequest request) {
      return cookieValue(cookieKey.name, request);
   }

   @Override
   public String authorizedUsername(final HttpServletRequest request) {
      String credentials = credentials(request);
      if(credentials == null) {
         return null;
      }
      HashCode hashedCredentials = Authenticator.hashCredentials(credentials);
      String username = validCredentials.get(hashedCredentials);
      return username != null ? username : credentialsValidator.apply(hashedCredentials);
   }

   @Override
   public String schemeName() {
      return "Cookie";
   }

   /**
    * The cookie key.
    */
   public final Cookies.CookieKey cookieKey;


   /**
    * An immutable map of username vs hashed credentials.
    */
   private final ImmutableMap<HashCode, String> validCredentials;

   /**
    * A function that gets a username from hashed credentials.
    */
   private final Function<HashCode, String> credentialsValidator;
}
