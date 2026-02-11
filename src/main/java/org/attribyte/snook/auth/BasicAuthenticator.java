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

import java.nio.charset.StandardCharsets;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.google.common.hash.HashCode;
import com.google.common.net.HttpHeaders;
import org.attribyte.api.http.Header;
import org.attribyte.util.Pair;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;
import java.util.function.Function;

/**
 * Authenticator for 'Basic' auth.
 */
public abstract class BasicAuthenticator<T> extends HeaderAuthenticator<T> {

   /**
    * Creates a boolean authenticator.
    * @see #BasicAuthenticator(Set, Function)
    */
   public static BasicAuthenticator<Boolean> booleanAuthenticator(final Set<HashCode> validCredentials,
                                                                  final Function<String, HashCode> usernameCredentials) {
      return new BasicAuthenticator<Boolean>(validCredentials, usernameCredentials) {
         @Override
         public Boolean authorized(final HttpServletRequest request) {
            return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
         }
      };
   };

   /**
    * Creates a boolean authenticator.
    * @see #BasicAuthenticator(Users)
    */
   public static BasicAuthenticator<Boolean> booleanAuthenticator(final Users credentialsFile) {

      return new BasicAuthenticator<Boolean>(credentialsFile) {
         @Override
         public Boolean authorized(final HttpServletRequest request) {
            return authorizedUsername(request) != null ? Boolean.TRUE : Boolean.FALSE;
         }
      };
   };

   /**
    * Creates an authenticator that uses *hashed tokens* from a credentials file.
    * @param credentialsFile The credentials file.
    */
   public BasicAuthenticator(final Users credentialsFile) {
      this(Sets.newHashSet(credentialsFile.sha256Hashes.values()),
              credentialsFile.sha256Hashes::get);
   }

   /**
    * Creates the authenticator.
    * @param validCredentials A set containing valid (securely hashed) credentials.
    * @param usernameCredentials A function that returns securely hashed credentials for a username.
    */
   public BasicAuthenticator(final Set<HashCode> validCredentials,
                             final Function<String, HashCode> usernameCredentials) {
      this.validCredentials = validCredentials != null ? ImmutableSet.copyOf(validCredentials) : ImmutableSet.of();
      this.usernameCredentials = usernameCredentials;
   }

   /**
    * Creates the standard authorization header to send with a request.
    * @param username The username.
    * @param password The password.
    * @return The header.
    */
   public static Header authorizationHeader(final String username, final String password) {
      return requestHeader(SCHEME, HttpHeaders.AUTHORIZATION, buildCredentials(username, password));
   }

   /**
    * Creates the appropriate request header to send with a request.
    * @param username The username.
    * @param password The password.
    * @return The request header.
    */
   public Header requestHeader(final String username, final String password) {
      return super.requestHeader(buildCredentials(username, password));
   }

   @Override
   public String authorizedUsername(final HttpServletRequest request) {
      String credentials = credentials(request);
      if(credentials == null) {
         return null;
      }

      String username = username(request);
      if(username == null) {
         return null;
      }

      HashCode hashedCredentials = credentialHasher.hashString(credentials, StandardCharsets.US_ASCII);
      if(validCredentials.contains(hashedCredentials)) {
         return username;
      }

      HashCode checkCredentials = usernameCredentials.apply(username);
      return checkCredentials != null && checkCredentials.equals(hashedCredentials) ? username : null;
   }

   /**
    * Gets the username and password from previously extracted header value.
    * @param headerValue The header value.
    * @return The username and password or {@code null} if none.
    */
   public static Pair<String, String> usernamePassword(final String headerValue) {
      if(Strings.isNullOrEmpty(headerValue)) {
         return null;
      }

      String upass = new String(base64Encoding.decode(headerValue));
      int userIndex = upass.indexOf(':');
      if(userIndex < 1) {
         return null;
      } else if(userIndex < upass.length() - 1) {
         return new Pair<>(upass.substring(0, userIndex), upass.substring(userIndex + 1));
      } else {
         return new Pair<>(upass.substring(0, userIndex), "");
      }
   }

   /**
    * Gets the username and password from previously extracted credentials.
    * @param credentials The credentials.
    * @return The username and password or {@code null} if none.
    */
   public static Pair<String, String> usernamePassword(final Credentials credentials) {
      return credentials != null ? usernamePassword(credentials.value) : null;
   }

   /**
    * Gets a pair containing the username and password sent with the request or {@code null} if none.
    * @param request The request.
    * @return The username/password pair.
    */
   public static Pair<String, String> usernamePassword(final HttpServletRequest request) {
      String credentials = credentials(SCHEME, request);
      if(credentials == null) {
         return null;
      }
      return usernamePassword(credentials);
   }

   public String username(final HttpServletRequest request) {
      String credentials = credentials(request);
      if(credentials == null) {
         return null;
      }

      String upass = new String(base64Encoding.decode(credentials));
      int userIndex = upass.indexOf(':');
      return userIndex < 1 ? null : upass.substring(0, userIndex);
   }

   /**
    * Merge a username and password into a single credentials string.
    * @param username The username.
    * @param password The password.
    * @return The credentials.
    */
   public static String buildCredentials(final String username, final String password) {
      return base64Encoding.encode((Strings.nullToEmpty(username) + ":" + Strings.nullToEmpty(password)).getBytes(StandardCharsets.UTF_8));
   }

   /**
    * The scheme name ({@value}).
    */
   public static final String SCHEME = "Basic";

   @Override
   protected String scheme() {
      return SCHEME;
   }

   @Override
   public String schemeName() {
      return scheme();
   }

   /**
    * An immutable set containing hashes of valid credentials.
    */
   private final ImmutableSet<HashCode> validCredentials;

   /**
    * A function that gets hashed credentials for a username.
    */
   private final Function<String, HashCode> usernameCredentials;
}
