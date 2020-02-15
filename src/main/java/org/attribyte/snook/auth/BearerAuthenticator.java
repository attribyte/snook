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

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.function.Function;

/**
 * Authenticator for 'Bearer' auth.
 */
public abstract class BearerAuthenticator<T> extends HeaderAuthenticator<T> {

   /**
    * Creates a boolean authenticator.
    * @see #BearerAuthenticator(Users)
    */
   public static BearerAuthenticator<Boolean> booleanAuthenticator(final Users credentialsFile) {
      return new BearerAuthenticator<Boolean>(credentialsFile) {
         @Override
         public Boolean authorized(final HttpServletRequest request) {
            return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
         }
      };
   };

   /**
    * Creates a boolean authenticator.
    * @see #BearerAuthenticator(Map)
    */
   public static BearerAuthenticator<Boolean> booleanAuthenticator(final Map<HashCode, String> validCredentials) {
      return new BearerAuthenticator<Boolean>(validCredentials) {
         @Override
         public Boolean authorized(final HttpServletRequest request) {
            return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
         }
      };
   };

   /**
    * Creates a boolean authenticator.
    * @see #BearerAuthenticator(Function)
    */
   public static BearerAuthenticator<Boolean> booleanAuthenticator(final Function<HashCode, String> credentialsValidator) {
      return new BearerAuthenticator<Boolean>(credentialsValidator) {
         @Override
         public Boolean authorized(final HttpServletRequest request) {
            return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
         }
      };
   };

   /**
    * Creates a boolean authenticator.
    * @see #BearerAuthenticator(Map, Function)
    */
   public static BearerAuthenticator<Boolean> booleanAuthenticator(final Map<HashCode, String> validCredentials,
                                                                   final Function<HashCode, String> credentialsValidator) {
      return new BearerAuthenticator<Boolean>(validCredentials, credentialsValidator) {
         @Override
         public Boolean authorized(final HttpServletRequest request) {
            return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
         }
      };
   };

   /**
    * Creates an authenticator from a credentials file.
    * @param credentialsFile The credentials file.
    */
   public BearerAuthenticator(final Users credentialsFile) {
      this(credentialsFile.userForHash);
   }

   /**
    * Creates an authenticator from a map of credentials.
    * @param validCredentials A map containing username vs valid (securely hashed) credentials.
    */
   public BearerAuthenticator(final Map<HashCode, String> validCredentials) {
      this(validCredentials, null);
   }

   /**
    * Creates an authenticator with an authentication function.
    * @param credentialsValidator The function that indicates if securely hashed credentials are valid
    *                             by returning the username or {@code null} if invalid..
    */
   public BearerAuthenticator(final Function<HashCode, String> credentialsValidator) {
      this(null, credentialsValidator);
   }

   /**
    * Creates an authenticator with a map of credentials (used first) as well as an authentication function.
    * @param validCredentials A map containing username vs valid (securely hashed) credentials.
    * @param credentialsValidator A function used in sequence (after {@code validCredentials})
    *                             that indicates if securely hashed credentials are valid
    *                             by returning the username or {@code null}.
    */
   public BearerAuthenticator(final Map<HashCode, String> validCredentials,
                              final Function<HashCode, String> credentialsValidator) {
      this.validCredentials = validCredentials != null ? ImmutableMap.copyOf(validCredentials) : ImmutableMap.of();
      this.credentialsValidator = credentialsValidator != null ? credentialsValidator : s -> null;
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
   protected String scheme() {
      return "Bearer";
   }

   @Override
   public String schemeName() {
      return scheme();
   }

   /**
    * An immutable map of username vs hashed credentials.
    */
   private final ImmutableMap<HashCode, String> validCredentials;

   /**
    * A function that gets a username from hashed credentials.
    */
   private final Function<HashCode, String> credentialsValidator;
}
