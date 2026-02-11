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
import org.attribyte.snook.test.TestHttpServletRequest;
import org.eclipse.jetty.http.HttpHeader;
import org.junit.Test;

import jakarta.servlet.http.HttpServletRequest;

import static org.junit.Assert.*;

public class TokenAuthenticatorTest {


   private static final String HEADER_NAME = "X-Test-Header";

   @Test
   public void testAuthorized() {
      TokenAuthenticator<Boolean> tokenAuthenticator = TokenAuthenticator.booleanAuthenticator(HEADER_NAME, ImmutableMap.of(
              Authenticator.hashCredentials("test12345"), "test_user_0"
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HEADER_NAME) ?
                    "test12345" : null;
         }
      };

      assertTrue(tokenAuthenticator.authorized(request));
   }

   @Test
   public void testAuthorizedUsername() {

      TokenAuthenticator<Boolean> tokenAuthenticator = TokenAuthenticator.booleanAuthenticator(HEADER_NAME, ImmutableMap.of(
              Authenticator.hashCredentials("test12345"), "test_user_0"
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HEADER_NAME) ?
                    "test12345" : null;
         }
      };

      assertEquals("test_user_0", tokenAuthenticator.authorizedUsername(request));
   }

   @Test
   public void testAuthorizedFunction() {

      TokenAuthenticator<Boolean> tokenAuthenticator = TokenAuthenticator.booleanAuthenticator(HEADER_NAME, ImmutableMap.of(
              Authenticator.hashCredentials("test12345"), "test_user_0"
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HEADER_NAME) ?
                    "test12345" : null;
         }
      };

      assertTrue(tokenAuthenticator.authorized(request));
      assertEquals("test_user_0", tokenAuthenticator.authorizedUsername(request));
   }

   @Test
   public void testUnauthorized() {

      TokenAuthenticator<Boolean> tokenAuthenticator = TokenAuthenticator.booleanAuthenticator(HEADER_NAME, ImmutableMap.of(
              Authenticator.hashCredentials("test12344"), "test_user_0"
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HEADER_NAME) ?
                    "test12345" : null;
         }
      };

      assertFalse(tokenAuthenticator.authorized(request));
      assertNull(tokenAuthenticator.authorizedUsername(request));
   }

   @Test
   public void testUnauthorizedFunction() {

      TokenAuthenticator<Boolean> tokenAuthenticator = TokenAuthenticator.booleanAuthenticator(HEADER_NAME, ImmutableMap.of(
              Authenticator.hashCredentials("test12344"), "test_user_0"
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "test12345" : null;
         }
      };

      assertFalse(tokenAuthenticator.authorized(request));
      assertNull(tokenAuthenticator.authorizedUsername(request));
   }
}
