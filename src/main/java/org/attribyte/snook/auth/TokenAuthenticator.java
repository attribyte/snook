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

import com.google.common.hash.HashCode;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.function.Function;

/**
 * Authenticator where a token is the value of a cookie (with no scheme, unlike 'Bearer').
 */
public abstract class TokenAuthenticator<T> extends BearerAuthenticator<T> {

   /**
    * Creates a boolean authenticator.
    * @see #TokenAuthenticator(String, Users)
    */
   public static TokenAuthenticator<Boolean> booleanAuthenticator(final String headerName,
                                                                  final Users credentialsFile) {
      return new TokenAuthenticator<Boolean>(headerName, credentialsFile) {
         @Override
         public Boolean authorized(final HttpServletRequest request) {
            return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
         }
      };
   };

   /**
    * Creates a boolean authenticator.
    * @see #TokenAuthenticator(String, Map)
    */
   public static TokenAuthenticator<Boolean> booleanAuthenticator(final String headerName,
                                                                  final Map<HashCode, String> validCredentials) {
      return new TokenAuthenticator<Boolean>(headerName, validCredentials) {
         @Override
         public Boolean authorized(final HttpServletRequest request) {
            return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
         }
      };
   };

   /**
    * Creates a boolean authenticator.
    * @see #TokenAuthenticator(String, Function)
    */
   public static TokenAuthenticator<Boolean> booleanAuthenticator(final String headerName,
                                                                  final Function<HashCode, String> credentialsValidator) {
      return new TokenAuthenticator<Boolean>(headerName, credentialsValidator) {
         @Override
         public Boolean authorized(final HttpServletRequest request) {
            return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
         }
      };
   };

   /**
    * Creates a boolean authenticator.
    * @see #TokenAuthenticator(String, Map, Function)
    */
   public static TokenAuthenticator<Boolean> booleanAuthenticator(final String headerName,
                                                                  final Map<HashCode, String> validCredentials,
                                                                  final Function<HashCode, String> credentialsValidator) {
      return new TokenAuthenticator<Boolean>(headerName, validCredentials, credentialsValidator) {
         @Override
         public Boolean authorized(final HttpServletRequest request) {
            return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
         }
      };
   };

   /**
    * Creates an authenticator from a credentials file.
    * @param headerName The header name.
    * @param credentialsFile The credentials file.
    */
   public TokenAuthenticator(final String headerName, final Users credentialsFile) {
      this(headerName, credentialsFile.userForHash);
   }

   /**
    * Creates an authenticator from a map of credentials.
    * @param headerName The header name.
    * @param validCredentials A map containing username vs valid (securely hashed) credentials.
    */
   public TokenAuthenticator(final String headerName, final Map<HashCode, String> validCredentials) {
      this(headerName, validCredentials, null);
   }

   /**
    * Creates an authenticator with an authentication function.
    * @param headerName The header name.
    * @param credentialsValidator The function that indicates if securely hashed credentials are valid
    *                             by returning the username or {@code null} if invalid..
    */
   public TokenAuthenticator(final String headerName, final Function<HashCode, String> credentialsValidator) {
      this(headerName,null, credentialsValidator);
   }

   /**
    * Creates the authenticator.
    * @param headerName The header name.
    * @param validCredentials A map containing username vs valid (securely hashed) credentials.
    * @param credentialsValidator A function that indicates if securely hashed credentials are valid.
    */
   public TokenAuthenticator(final String headerName,
                             final Map<HashCode, String> validCredentials,
                             final Function<HashCode, String> credentialsValidator) {
      super(validCredentials, credentialsValidator);
      this.headerName = headerName;
   }

   @Override
   protected String scheme() {
      return null;
   }

   @Override
   public String schemeName() {
      return "Token";
   }

   @Override
   public String credentialsHeader() {
      return headerName;
   }

   /**
    * The header name.
    */
   public final String headerName;
}
