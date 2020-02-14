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
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import org.attribyte.snook.TestHttpServletRequest;
import org.attribyte.util.Pair;
import org.eclipse.jetty.http.HttpHeader;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;

import java.io.IOException;
import java.util.List;

import static org.junit.Assert.*;

public class BasicAuthenticatorTest {

   @Test
   public void buildCredentials() {
      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(), s -> null);
      String checkCredentials = BasicAuthenticator.buildCredentials("test_user", "test_password");
      assertEquals(
              HeaderAuthenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8)),
              checkCredentials);
   }

   @Test
   public void username() {

      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      String checkUser = basicAuthenticator.username(request);
      assertNotNull(checkUser);
      assertEquals("test_user", checkUser);
   }

   @Test
   public void usernamePassword() {

      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      Pair<String, String> upass = basicAuthenticator.usernamePassword(request);
      assertEquals("test_user", upass.getKey());
      assertEquals("test_password", upass.getValue());
   }

   @Test
   public void usernameEmptyPassword() {

      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      Pair<String, String> upass = basicAuthenticator.usernamePassword(request);
      assertEquals("test_user", upass.getKey());
      assertTrue(upass.getValue().isEmpty());
   }

   @Test
   public void authorized() {
      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(
              Authenticator.hashCredentials(BasicAuthenticator.buildCredentials("test_user", "test_password"))
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      assertTrue(basicAuthenticator.authorized(request));
   }

   public void unauthorized() {
      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(
              Authenticator.hashCredentials(BasicAuthenticator.buildCredentials("test_user", "test_password"))
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_password_nope".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      assertTrue(basicAuthenticator.authorized(request));
   }

   public void unauthorizedInvalidScheme() {
      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(
              Authenticator.hashCredentials(BasicAuthenticator.buildCredentials("test_user", "test_password"))
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Bxsic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      assertFalse(basicAuthenticator.authorized(request));
   }

   public void unauthorizedNoScheme() {
      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(
              Authenticator.hashCredentials(BasicAuthenticator.buildCredentials("test_user", "test_password"))
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    Authenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      assertFalse(basicAuthenticator.authorized(request));
   }

   @Test
   public void unauthorizedNoValue() {
      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(
              Authenticator.hashCredentials(BasicAuthenticator.buildCredentials("test_user", "test_password"))
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic "
                    : null;
         }
      };

      assertFalse(basicAuthenticator.authorized(request));
   }

   @Test
   public void unauthorizedNullValue() {
      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(
              Authenticator.hashCredentials(BasicAuthenticator.buildCredentials("test_user", "test_password"))
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
      };

      assertFalse(basicAuthenticator.authorized(request));
   }

   @Test
   public void authorizedUser() {

      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(), s -> s.equals("test_user") ?
              Authenticator.hashCredentials(BasicAuthenticator.buildCredentials("test_user", "test_password")) : null);


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
   }

   @Test
   public void authorizedUserFromSet() {

      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(
              Authenticator.hashCredentials(BasicAuthenticator.buildCredentials("test_user", "test_password"))
      ), s -> null);

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
   }

   @Test
   public void unauthorizedUser() {

      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(), s -> s.equals("test_user") ?
              Authenticator.hashCredentials(BasicAuthenticator.buildCredentials("test_userx", "test_password")) : null);


      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      assertNull(basicAuthenticator.authorizedUsername(request));
   }

   @Test
   public void unauthorizedUserFromSet() {

      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(
              Authenticator.hashCredentials(BasicAuthenticator.buildCredentials("test_user", "test_passwordx"))
      ), s -> null);

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      assertNull(basicAuthenticator.authorizedUsername(request));
   }

   @Test
   public void credentialsFile() throws IOException {
      List<String> lines = Lists.newArrayList();
      String token = AuthenticationToken.randomToken().toString();
      lines.add("tester:$basic$" + token);
      List<Users.Record> records = Users.parse(lines, false);
      assertEquals(1, records.size());
      Users credentialsFile = new Users(records);
      BasicAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(credentialsFile);

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
