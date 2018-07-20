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

package org.attribyte.snook;

import com.google.common.base.Strings;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.EnumSet;

/**
 * "Cookie" operations.
 */
public class Cookies {

   /**
    * Cookie options.
    */
   public enum Option {

      /**
       * Cookie is only sent if the connection is secure.
       */
      SECURE_ONLY,

      /**
       * Cookie is not accessible to browser scripts.
       */
      HTTP_ONLY;
   }

   /**
    * Creates a cookie.
    * @param cookieName The name.
    * @param cookieValue The value.
    * @param domain The domain.
    * @param path The path.
    * @param maxAgeSeconds The maximum age in seconds. If {@code < 0}, cookie is temporary.
    *   If {@code 0}, cookie is deleted, if it exists.
    * @param options The cookie options.
    * @return The cookie.
    */
   public static Cookie createCookie(final String cookieName, final String cookieValue,
                                     final String domain, final String path,
                                     final int maxAgeSeconds, final EnumSet<Option> options) {
      Cookie cookie = new Cookie(cookieName, cookieValue);
      cookie.setMaxAge(maxAgeSeconds);

      if(!Strings.isNullOrEmpty(domain)) {
         cookie.setDomain(domain);
      }

      if(!Strings.isNullOrEmpty(path)) {
         cookie.setPath(path);
      }

      if(options.contains(Option.SECURE_ONLY)) {
         cookie.setSecure(true);
      }

      if(options.contains(Option.HTTP_ONLY)) {
         cookie.setHttpOnly(true);
      }

      return cookie;
   }

   /**
    * Sets a cookie.
    * @param cookieName The name.
    * @param cookieValue The value.
    * @param domain The domain.
    * @param path The path.
    * @param maxAgeSeconds The maximum age in seconds. If {@code < 0}, cookie is temporary.
    *   If {@code 0}, cookie is deleted, if it exists.
    * @param options The cookie options.
    * @param resp The response.
    */
   public static void setCookie(final String cookieName, final String cookieValue,
                                final String domain, final String path,
                                final int maxAgeSeconds, final EnumSet<Option> options,
                                final HttpServletResponse resp) {
      resp.addCookie(createCookie(cookieName, cookieValue, domain, path, maxAgeSeconds, options));
   }

   /**
    * Creates a session (temporary) cookie.
    * @param cookieName The name.
    * @param cookieValue The value.
    * @param domain The domain.
    * @param path The path.
    * @param options The cookie options.
    * @return The cookie.
    */
   public static Cookie createSessionCookie(final String cookieName, final String cookieValue,
                                            final String domain, final String path,
                                            final EnumSet<Option> options) {
      return createCookie(cookieName, cookieValue, domain, path, -1, options);
   }

   /**
    * Sets a session (temporary) cookie.
    * @param cookieName The name.
    * @param cookieValue The value.
    * @param domain The domain.
    * @param path The path.
    * @param options The cookie options.
    * @param resp The response.
    */
   public static void setSessionCookie(final String cookieName, final String cookieValue,
                                       final String domain, final String path,
                                       final EnumSet<Option> options,
                                       final HttpServletResponse resp) {
      resp.addCookie(createSessionCookie(cookieName, cookieValue, domain, path, options));
   }

   /**
    * Creates a session (temporary) cookie that applies to the current domain and any path.
    * @param cookieName The name.
    * @param cookieValue The value.
    * @param options The cookie options.
    * @return The cookie.
    */
   public static Cookie createSessionCookie(final String cookieName, final String cookieValue,
                                            final EnumSet<Option> options) {
      return createSessionCookie(cookieName, cookieValue, null, "/", options);
   }

   /**
    * Sets a session (temporary) cookie that applies to the current domain and any path.
    * @param cookieName The name.
    * @param cookieValue The value.
    * @param options The cookie options.
    * @param resp The response.
    */
   public static void setSessionCookie(final String cookieName, final String cookieValue,
                                       final EnumSet<Option> options, final HttpServletResponse resp) {
      resp.addCookie(createSessionCookie(cookieName, cookieValue, options));
   }

   /**
    * Creates a persistent cookie that applies to the current domain and any path.
    * @param cookieName The name.
    * @param cookieValue The value.
    * @param options The cookie options.
    * @return The cookie.
    */
   public static Cookie createCookie(final String cookieName, final String cookieValue,
                                     final int maxAgeSeconds, final EnumSet<Option> options) {
      return createCookie(cookieName, cookieValue, null, "/", maxAgeSeconds, options);
   }

   /**
    * Sets a persistent cookie that applies to the current domain and any path.
    * @param cookieName The name.
    * @param cookieValue The value.
    * @param options The cookie options.
    * @param resp The response.
    */
   public static void createCookie(final String cookieName, final String cookieValue,
                                   final int maxAgeSeconds, final EnumSet<Option> options,
                                   final HttpServletResponse resp) {
      resp.addCookie(createCookie(cookieName, cookieValue, maxAgeSeconds, options));
   }

   /**
    * Removes a previously set cookie that applies to the current domain and any path.
    * @param cookieName The name.
    * @param resp The HTTP response.
    */
   public static final void removeCookie(final String cookieName, final HttpServletResponse resp) {
      removeCookie(cookieName, null, "/", resp);
   }

   /**
    * Removes a previously set cookie that applies to the current domain and any path.
    * @param cookieName The name.
    * @param domain The cookie domain.
    * @param path The cookie path.
    * @param resp The HTTP response.
    */
   public static final void removeCookie(final String cookieName,
                                         final String domain, final String path,
                                         final HttpServletResponse resp) {
      Cookie cookie = new Cookie(cookieName, "false");
      cookie.setMaxAge(0);
      if(!Strings.isNullOrEmpty(domain)) {
         cookie.setDomain(domain);
      }
      if(!Strings.isNullOrEmpty(path)) {
         cookie.setPath(path);
      }
      resp.addCookie(cookie);
   }


   /**
    * Gets the first named cookie sent with the request.
    * @param cookieName The name.
    * @param req The HTTP request.
    * @return The cookie, or {@code null} if not found.
    */
   public static final Cookie getCookie(final String cookieName, final HttpServletRequest req) {

      Cookie[] cookies = req.getCookies();
      if(cookies == null) {
         return null;
      }

      for(Cookie curr : cookies) {
         if(curr.getName().equals(cookieName)) {
            return curr;
         }
      }

      return null;
   }
}