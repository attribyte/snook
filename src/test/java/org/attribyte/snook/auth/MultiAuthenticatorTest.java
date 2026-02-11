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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import org.attribyte.snook.test.TestHttpServletRequest;
import org.junit.Test;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Map;

import static org.junit.Assert.*;

public class MultiAuthenticatorTest {


   private static final String HEADER_NAME_0 = "X-Test-Header-0";
   private static final String HEADER_NAME_1 = "X-Test-Header-1";

   private static TokenAuthenticator<Boolean> tokenAuthenticator0 = TokenAuthenticator.booleanAuthenticator(HEADER_NAME_0, ImmutableMap.of(
           Authenticator.hashCredentials("test12345"), "test_user_0"
   ), s -> null);

   private static TokenAuthenticator<Boolean> tokenAuthenticator1 = TokenAuthenticator.booleanAuthenticator(HEADER_NAME_1, ImmutableMap.of(
           Authenticator.hashCredentials("test54321"), "test_user_1"
   ), s -> null);

   @Test
   public void testAuthorizedFirst() {
      FirstAuthenticator auth = new FirstAuthenticator(ImmutableList.of(tokenAuthenticator0, tokenAuthenticator1));
      final Map<String, String> headers = ImmutableMap.of(HEADER_NAME_1, "test54321");
      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return headers.get(s);
         }
      };

      assertTrue(auth.authorized(request));
      assertEquals("test_user_1", auth.authorizedUsername(request));
   }

   @Test
   public void testUnauthorizedFirst() {
      FirstAuthenticator auth = new FirstAuthenticator(ImmutableList.of(tokenAuthenticator0, tokenAuthenticator1));
      final Map<String, String> headers = ImmutableMap.of(HEADER_NAME_1, "test54321x");
      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return headers.get(s);
         }
      };

      assertFalse(auth.authorized(request));
      assertNull(auth.authorizedUsername(request));
   }

   @Test
   public void testAuthorizedAny() {
      AnyAuthenticator auth = new AnyAuthenticator(ImmutableList.of(tokenAuthenticator0, tokenAuthenticator1));
      final Map<String, String> headers = ImmutableMap.of(HEADER_NAME_0, "invalid", HEADER_NAME_1, "test54321");
      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return headers.get(s);
         }
      };

      assertTrue(auth.authorized(request));
      assertEquals("test_user_1", auth.authorizedUsername(request));
   }

   @Test
   public void testUnauthorizedAny() {
      AnyAuthenticator auth = new AnyAuthenticator(ImmutableList.of(tokenAuthenticator0, tokenAuthenticator1));
      final Map<String, String> headers = ImmutableMap.of(HEADER_NAME_0, "invalid", HEADER_NAME_1, "test54321x");
      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return headers.get(s);
         }
      };

      assertFalse(auth.authorized(request));
      assertNull(auth.authorizedUsername(request));
   }


   @Test
   public void testAuthorizedAll() {
      AllAuthenticator auth = new AllAuthenticator(ImmutableList.of(tokenAuthenticator0, tokenAuthenticator1));
      final Map<String, String> headers = ImmutableMap.of(HEADER_NAME_0, "test12345", HEADER_NAME_1, "test54321");
      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return headers.get(s);
         }
      };

      assertTrue(auth.authorized(request));
      assertEquals("test_user_1", auth.authorizedUsername(request));
   }

   @Test
   public void testUnauthorizedAll() {
      AllAuthenticator auth = new AllAuthenticator(ImmutableList.of(tokenAuthenticator0, tokenAuthenticator1));
      final Map<String, String> headers = ImmutableMap.of(HEADER_NAME_0, "invalid", HEADER_NAME_1, "test54321x");
      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return headers.get(s);
         }
      };

      assertFalse(auth.authorized(request));
      assertNull(auth.authorizedUsername(request));
   }

}
