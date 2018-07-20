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

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
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
      HTTP_ONLY
   }

   /**
    * A key that uniquely identifies a cookie.
    */
   public static class CookieKey {

      /**
       * Creates a key.
       * @param name The cookie name. Must not be {@code null} or empty.
       * @param domain The domain.
       * @param path The path.
       * @throws IllegalArgumentException if name is null or empty.
       */
      public CookieKey(final String name, final String domain, final String path) {

         if(Strings.isNullOrEmpty(name)) {
            throw new IllegalArgumentException("Name must not be null or empty");
         }

         this.name = name;
         this.domain = domain;
         this.path = path;
      }

      /**
       * Creates a key that applies to any path for the current domain.
       * @param name The cookie name.
       */
      public CookieKey(final String name) {
         this(name, null, "/");
      }

      @Override
      public String toString() {
         return MoreObjects.toStringHelper(this)
                 .add("name", name)
                 .add("domain", domain)
                 .add("path", path)
                 .toString();
      }

      @Override
      public boolean equals(final Object o) {
         if(this == o) return true;
         if(o == null || getClass() != o.getClass()) return false;
         final CookieKey cookieKey = (CookieKey)o;
         return Objects.equal(name, cookieKey.name) &&
                 Objects.equal(domain, cookieKey.domain) &&
                 Objects.equal(path, cookieKey.path);
      }

      @Override
      public int hashCode() {
         return Objects.hashCode(name, domain, path);
      }

      /**
       * Creates a (mutable) cookie with this key.
       * @param value The value.
       * @return The cookie.
       */
      public Cookie cookie(final String value) {
         Cookie cookie = new Cookie(name, value);

         if(!Strings.isNullOrEmpty(domain)) {
            cookie.setDomain(domain);
         }

         if(!Strings.isNullOrEmpty(path)) {
            cookie.setPath(path);
         }
         return cookie;
      }

      /**
       * The cookie name.
       */
      public final String name;

      /**
       * The domain.
       */
      public final String domain;

      /**
       * The path.
       */
      public final String path;
   }

   /**
    * Creates a cookie.
    * @param cookieKey The key.
    * @param cookieValue The value.
    * @param maxAgeSeconds The maximum age in seconds. If {@code < 0}, cookie is temporary.
    *   If {@code 0}, cookie is deleted, if it exists.
    * @param options The cookie options.
    * @return The cookie.
    */
   public static Cookie createCookie(final CookieKey cookieKey, final String cookieValue,
                                     final int maxAgeSeconds, final EnumSet<Option> options) {
      Cookie cookie = cookieKey.cookie(cookieValue);
      cookie.setMaxAge(maxAgeSeconds);

      if(options.contains(Option.SECURE_ONLY)) {
         cookie.setSecure(true);
      }

      if(options.contains(Option.HTTP_ONLY)) {
         cookie.setHttpOnly(true);
      }

      return cookie;
   }

   /**
    * Creates a session (temporary) cookie.
    * @param cookieKey The key.
    * @param cookieValue The value.
    * @param options The cookie options.
    * @return The cookie.
    */
   public static Cookie createSessionCookie(final CookieKey cookieKey, final String cookieValue,
                                            final EnumSet<Option> options) {
      return createCookie(cookieKey, cookieValue, -1, options);
   }

   /**
    * Sets a cookie.
    * @param cookieKey The key.
    * @param cookieValue The value.
    * @param maxAgeSeconds The maximum age in seconds. If {@code < 0}, cookie is temporary.
    *   If {@code 0}, cookie is deleted, if it exists.
    * @param options The cookie options.
    * @param resp The response.
    */
   public static void setCookie(final CookieKey cookieKey, final String cookieValue,
                                final int maxAgeSeconds, final EnumSet<Option> options,
                                final HttpServletResponse resp) {
      resp.addCookie(createCookie(cookieKey, cookieValue, maxAgeSeconds, options));
   }

   /**
    * Sets a cookie that applies to the current domain and any path.
    * @param cookieName The name.
    * @param cookieValue The value.
    * @param maxAgeSeconds The maximum age in seconds. If {@code < 0}, cookie is temporary.
    *   If {@code 0}, cookie is deleted, if it exists.
    * @param options The cookie options.
    * @param resp The response.
    */
   public static void setCookie(final String cookieName, final String cookieValue,
                                final int maxAgeSeconds, final EnumSet<Option> options,
                                final HttpServletResponse resp) {
      setCookie(new CookieKey(cookieName), cookieValue, maxAgeSeconds, options, resp);
   }

   /**
    * Sets a session (temporary) cookie.
    * @param cookieKey The key.
    * @param cookieValue The value.
    * @param options The cookie options.
    * @param resp The response.
    */
   public static void setSessionCookie(final CookieKey cookieKey, final String cookieValue,
                                       final EnumSet<Option> options,
                                       final HttpServletResponse resp) {
      resp.addCookie(createSessionCookie(cookieKey, cookieValue, options));
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
      setSessionCookie(new CookieKey(cookieName), cookieValue, options, resp);
   }

   /**
    * Removes a previously set cookie.
    * @param cookieKey The key.
    * @param resp The HTTP response.
    */
   public static final void removeCookie(final CookieKey cookieKey,
                                         final HttpServletResponse resp) {
      Cookie cookie = cookieKey.cookie("false");
      cookie.setMaxAge(0);
      resp.addCookie(cookie);
   }

   /**
    * Removes a previously set cookie that applies to the current domain and any path.
    * @param cookieName The name.
    * @param resp The HTTP response.
    */
   public static final void removeCookie(final String cookieName, final HttpServletResponse resp) {
      removeCookie(new CookieKey(cookieName), resp);
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