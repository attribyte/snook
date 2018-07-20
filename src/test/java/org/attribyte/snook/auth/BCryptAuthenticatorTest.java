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

import com.google.common.base.Charsets;
import com.google.common.collect.Sets;
import com.google.common.hash.HashCode;
import org.attribyte.snook.Cookies;
import org.attribyte.snook.TestHttpServletRequest;
import org.attribyte.snook.TestHttpServletResponse;
import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.Set;
import java.util.function.Function;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BCryptAuthenticatorTest {

   @Test
   public void testAuthorized() throws IOException {

      String hashed = BCrypt.hashpw("test1234", BCrypt.gensalt(4));
      Function<String, HashCode> hashedPasswords = s -> HashCode.fromBytes(hashed.getBytes(Charsets.US_ASCII));

      Set<HashCode> savedTokens = Sets.newHashSet();
      Function<HashCode, String> credentialsValidator = hashCode -> savedTokens.contains(hashCode) ? "test_user" : null;
      Function<AuthenticationToken, Boolean> saveToken = authenticationToken -> savedTokens.add(authenticationToken.token);

      BCryptAuthenticator authenticator = new BCryptAuthenticator(
              new Cookies.CookieKey("authtoken"), credentialsValidator, hashedPasswords, saveToken);

      TestHttpServletResponse resp = new TestHttpServletResponse();

      assertTrue(authenticator.doLogin("test_user", "test1234", 3600, resp));

      assertEquals(1, resp.cookies.size());

      Cookie cookie = resp.cookies.get(0);
      assertEquals("authtoken", cookie.getName());

      HashCode hashedValue = Authenticator.hashCredentials(cookie.getValue());
      assertTrue(savedTokens.contains(hashedValue));

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public Cookie[] getCookies() {
            return new Cookie[] {new Cookie("authtoken", resp.cookies.get(0).getValue())};
         }
      };

      assertTrue(authenticator.authorized(request));
      assertEquals("test_user", authenticator.authorizedUsername(request));
   }

   @Test
   public void testFailedLogin() throws IOException {

      String hashed = BCrypt.hashpw("test1234", BCrypt.gensalt(4));
      Function<String, HashCode> hashedPasswords = s -> HashCode.fromBytes(hashed.getBytes(Charsets.US_ASCII));

      Set<HashCode> savedTokens = Sets.newHashSet();
      Function<HashCode, String> credentialsValidator = hashCode -> savedTokens.contains(hashCode) ? "test_user" : null;
      Function<AuthenticationToken, Boolean> saveToken = authenticationToken -> savedTokens.add(authenticationToken.token);

      BCryptAuthenticator authenticator = new BCryptAuthenticator(
              new Cookies.CookieKey("authtoken"), credentialsValidator, hashedPasswords, saveToken);

      TestHttpServletResponse resp = new TestHttpServletResponse();

      assertFalse(authenticator.doLogin("test_user", "test12345", 3600, resp));
      assertEquals(0, resp.cookies.size());
   }
}