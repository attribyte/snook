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
import org.attribyte.snook.Cookies;
import org.attribyte.snook.TestHttpServletRequest;
import org.junit.Test;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.junit.Assert.*;

public class CookieAuthenticatorTest {

   @Test
   public void testAuthorized() {
      CookieAuthenticator cookieAuthenticator = new CookieAuthenticator(new Cookies.CookieKey("token"),
              ImmutableMap.of(
              Authenticator.hashCredentials("test12345"), "test_user_0"
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public Cookie[] getCookies() {
            return new Cookie[] {new Cookie("token", "test12345")};
         }
      };

      assertTrue(cookieAuthenticator.authorized(request));
      assertEquals("test_user_0", cookieAuthenticator.authorizedUsername(request));
   }

   @Test
   public void testUnauthorized() {
      CookieAuthenticator cookieAuthenticator = new CookieAuthenticator(new Cookies.CookieKey("token"),
              ImmutableMap.of(
                      Authenticator.hashCredentials("test12344"), "test_user_0"
              ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public Cookie[] getCookies() {
            return new Cookie[] {new Cookie("token", "test12345")};
         }
      };

      assertFalse(cookieAuthenticator.authorized(request));
   }

   @Test
   public void testUnauthorizedMissing() {
      CookieAuthenticator cookieAuthenticator = new CookieAuthenticator(new Cookies.CookieKey("token"),
              ImmutableMap.of(
                      Authenticator.hashCredentials("test12344"), "test_user_0"
              ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public Cookie[] getCookies() {
            return null;
         }
      };

      assertFalse(cookieAuthenticator.authorized(request));
   }
}
