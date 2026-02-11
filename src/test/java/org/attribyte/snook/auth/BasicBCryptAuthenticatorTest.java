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
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.Lists;
import com.google.common.hash.HashCode;
import org.attribyte.snook.test.TestHttpServletRequest;
import org.eclipse.jetty.http.HttpHeader;
import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

import jakarta.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.List;

import static org.junit.Assert.*;

public class BasicBCryptAuthenticatorTest {

   @Test
   public void testValid() {

      Cache<HashCode, Boolean> cache = CacheBuilder.newBuilder().build();
      String bcrypt = BCrypt.hashpw("test_password", BCrypt.gensalt(4));


      BasicBCryptAuthenticator<Boolean> basicAuthenticator = BasicBCryptAuthenticator.booleanAuthenticator(cache, h -> bcrypt);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      String username = basicAuthenticator.authorizedUsername(request);
      assertNotNull(username);
      assertEquals("test_user", username);

      //Cached...

      assertEquals(1, cache.size());

      username = basicAuthenticator.authorizedUsername(request);
      assertNotNull(username);
      assertTrue(basicAuthenticator.authorized(request));
      assertEquals("test_user", username);

   }

   @Test
   public void testInvalid() {

      Cache<HashCode, Boolean> cache = CacheBuilder.newBuilder().build();
      String bcrypt = BCrypt.hashpw("test_passwordx", BCrypt.gensalt(4));


      BasicBCryptAuthenticator<Boolean> basicAuthenticator = BasicBCryptAuthenticator.booleanAuthenticator(cache, h -> bcrypt);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      String username = basicAuthenticator.authorizedUsername(request);
      assertNull(username);
      assertFalse(basicAuthenticator.authorized(request));
      assertEquals(0, cache.size());
   }

   @Test
   public void credentialsFile() throws IOException {
      List<String> lines = Lists.newArrayList();
      String token = AuthenticationToken.randomToken().toString();
      lines.add("tester:$password$" + token);
      List<Users.Record> records = Users.parse(lines, false);
      assertEquals(1, records.size());
      Users credentialsFile = new Users(records);
      Cache<HashCode, Boolean> cache = CacheBuilder.newBuilder().build();

      BasicBCryptAuthenticator<Boolean> basicAuthenticator = BasicBCryptAuthenticator.booleanAuthenticator(cache, credentialsFile);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode(("tester:" + token).getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      assertTrue(basicAuthenticator.authorized(request));
      String username = basicAuthenticator.authorizedUsername(request);
      assertNotNull(username);
      assertEquals("tester", username);

      request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode(("tester:x" + token).getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      assertFalse(basicAuthenticator.authorized(request));
      assertNull(basicAuthenticator.authorizedUsername(request));
   }
}
