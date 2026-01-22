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
import com.google.common.collect.ImmutableMap;
import com.google.common.hash.HashCode;
import org.attribyte.snook.Cookies;
import org.mindrot.jbcrypt.BCrypt;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.EnumSet;
import java.util.function.Function;

/**
 * An authenticator that checks username + password against
 * a stored BCrypt hash. On valid password, sets a cookie
 * that holds a random authentication token used for subsequent
 * authentication.
 */
public abstract class BCryptAuthenticator<T> extends CookieAuthenticator<T> implements LoginAuthenticator<T> {


   /**
    * @see #BCryptAuthenticator(Cookies.CookieKey, Function, ImmutableMap, Function)
    */
   public static BCryptAuthenticator<Boolean> booleanAuthenticator(final Cookies.CookieKey cookieKey,
                                                                   final Function<HashCode, String> credentialsValidator,
                                                                   final ImmutableMap<String, HashCode> passwordHashMap,
                                                                   final Function<AuthenticationToken, Boolean> saveCredentials) {

      return new BCryptAuthenticator<Boolean>(cookieKey, credentialsValidator, passwordHashMap, saveCredentials) {

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
    * @see #BCryptAuthenticator(Cookies.CookieKey, Function, Function, Function)
    */
   public static BCryptAuthenticator<Boolean> booleanAuthenticator(final Cookies.CookieKey cookieKey,
                                                                   final Function<HashCode, String> credentialsValidator,
                                                                   final Function<String, HashCode> selectPasswordHash,
                                                                   final Function<AuthenticationToken, Boolean> saveCredentials) {

      return new BCryptAuthenticator<Boolean>(cookieKey, credentialsValidator, selectPasswordHash, saveCredentials) {

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
    * Creates the authenticator with a map that contains valid password hashes.
    * @param cookieKey The key that identifies the cookie.
    * @param credentialsValidator A function that indicates if credentials are valid.
    *   Returns the authentication token exactly as saved.
    * @param passwordHashMap A map containing all valid password hashes.
    * @param saveCredentials A function that saves credentials, returning {@code true} if saved or {@code false} if not.
    */
   public BCryptAuthenticator(final Cookies.CookieKey cookieKey,
                              final Function<HashCode, String> credentialsValidator,
                              final ImmutableMap<String, HashCode> passwordHashMap,
                              final Function<AuthenticationToken, Boolean> saveCredentials) {
      super(cookieKey, ImmutableMap.of(), credentialsValidator);
      this.selectPasswordHash = passwordHashMap::get;
      this.saveCredentials = saveCredentials;
   }


   /**
    * Creates the authenticator.
    * @param cookieKey The key that identifies the cookie.
    * @param validateToken A function that returns the username associated with a token.
    *   Returns the authentication token exactly as saved.
    * @param selectPasswordHash A function that returns the password hash for a username or {@code null} if none.
    * @param saveCredentials A function that saves credentials, returning {@code true} if saved or {@code false} if not.
    */
   public BCryptAuthenticator(final Cookies.CookieKey cookieKey,
                              final Function<HashCode, String> validateToken,
                              final Function<String, HashCode> selectPasswordHash,
                              final Function<AuthenticationToken, Boolean> saveCredentials) {
      super(cookieKey, ImmutableMap.of(), validateToken);
      this.selectPasswordHash = selectPasswordHash;
      this.saveCredentials = saveCredentials;
   }

   @Override
   public T authorized(final HttpServletRequest request) {
      String authorizedUsername = authorizedUsername(request);
      return authorizedUsername != null ? validCredentials(authorizedUsername) : invalidCredentials(authorizedUsername);
   }

   /**
    * Performs a login.
    * <p>
    *    If username + password is valid, creates a random token for the username,
    *    saves it and sets the value as a response cookie. Otherwise, does nothing
    *    and returns {@code false}.
    * </p>
    * @param username The username.
    * @param password The password.
    * @param tokenLifetimeSeconds The authentication token lifetime in seconds.
    * @param resp The response.
    * @return Was the password valid and token saved and set as a cookie?
    * @throws IOException if credentials save failed.
    */
   public T doLogin(final String username, final String password,
                    final int tokenLifetimeSeconds,
                    final HttpServletResponse resp) throws IOException {

      HashCode passwordHash = selectPasswordHash.apply(username);
      if(!checkPassword(password, passwordHash)) {
         return invalidCredentials(username);
      }

      AuthenticationToken returnedToken = new AuthenticationToken(username);
      AuthenticationToken savedToken =
              new AuthenticationToken(username, Authenticator.hashCredentials(returnedToken.token.toString()));

      boolean saved = saveCredentials.apply(savedToken);
      if(saved) {
         Cookies.setCookie(cookieKey, returnedToken.token.toString(), tokenLifetimeSeconds, cookieOptions, resp);
         return validCredentials(username);
      } else {
         throw new IOException("Credentials save failed");
      }
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
    * Check a password against a hash code.
    * @param password The password.
    * @param passwordHash The password hash.
    * @return Does the hash match?
    */
   public static boolean checkPassword(final String password, final HashCode passwordHash) {
      if(password == null || passwordHash == null) {
         return false;
      }

      String hashed = new String(passwordHash.asBytes(), StandardCharsets.US_ASCII);
      return BCrypt.checkpw(password, hashed);
   }

   @Override
   public String schemeName() {
      return "Cookie (BCrypt)";
   }

   @Override
   public void doLogout(final HttpServletResponse resp) {
      Cookies.removeCookie(cookieKey, resp);
   }

   /**
    * A function that saves credentials.
    */
   private final Function<AuthenticationToken, Boolean> saveCredentials;

   /**
    * A function that selects the password hash for a user.
    */
   private final Function<String, HashCode> selectPasswordHash;

   /**
    * The cookie options to be set with the authentication token cookie.
    */
   private static final EnumSet<Cookies.Option> cookieOptions = EnumSet.of(Cookies.Option.HTTP_ONLY, Cookies.Option.SECURE_ONLY);
}
