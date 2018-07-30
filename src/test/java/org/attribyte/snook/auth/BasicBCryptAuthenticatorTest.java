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
import com.google.common.hash.HashCode;
import org.attribyte.snook.TestHttpServletRequest;
import org.eclipse.jetty.http.HttpHeader;
import org.junit.Test;
import org.mindrot.jbcrypt.BCrypt;

import javax.servlet.http.HttpServletRequest;

import static org.junit.Assert.*;

public class BasicBCryptAuthenticatorTest {

   @Test
   public void testValid() {

      Cache<HashCode, Boolean> cache = CacheBuilder.newBuilder().build();
      String bcrypt = BCrypt.hashpw("test_password", BCrypt.gensalt(4));


      BasicBCryptAuthenticator basicAuthenticator = new BasicBCryptAuthenticator(cache, h -> bcrypt);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + Authenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
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


      BasicBCryptAuthenticator basicAuthenticator = new BasicBCryptAuthenticator(cache, h -> bcrypt);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + Authenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      String username = basicAuthenticator.authorizedUsername(request);
      assertNull(username);
      assertFalse(basicAuthenticator.authorized(request));
      assertEquals(0, cache.size());
   }
}
