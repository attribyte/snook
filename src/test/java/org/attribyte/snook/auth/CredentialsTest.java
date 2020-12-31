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

import org.attribyte.snook.test.TestHttpServletRequest;
import org.eclipse.jetty.http.HttpHeader;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

public class CredentialsTest {

   @Test
   public void testValid() {
      String headerValue = "Basic test1234";
      Optional<Credentials> maybeCredentials = Credentials.credentials(headerValue);
      assertNotNull(maybeCredentials);
      assertTrue(maybeCredentials.isPresent());
      maybeCredentials.ifPresent(credentials -> {
         assertNotNull(credentials.scheme);
         assertEquals("Basic", credentials.scheme);
         assertNotNull(credentials.value);
         assertEquals("test1234", credentials.value);
      });
   }

   @Test
   public void testHeaderValid() {

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ? "Basic test1234" : null;
         }
      };
      Optional<Credentials> maybeCredentials = Credentials.credentials(request);
      assertNotNull(maybeCredentials);
      assertTrue(maybeCredentials.isPresent());
      maybeCredentials.ifPresent(credentials -> {
         assertNotNull(credentials.scheme);
         assertEquals("Basic", credentials.scheme);
         assertNotNull(credentials.value);
      });
   }

   @Test
   public void testEmptyCredentails() {
      String headerValue = "Basic";
      Optional<Credentials> maybeCredentials = Credentials.credentials(headerValue);
      assertNotNull(maybeCredentials);
      assertFalse(maybeCredentials.isPresent());
   }

   @Test
   public void testSpacesAtEnd() {
      String headerValue = "Basic test1234 ";
      Optional<Credentials> maybeCredentials = Credentials.credentials(headerValue);
      assertNotNull(maybeCredentials);
      assertTrue(maybeCredentials.isPresent());
      maybeCredentials.ifPresent(credentials -> {
         assertNotNull(credentials.scheme);
         assertEquals("Basic", credentials.scheme);
         assertNotNull(credentials.value);
         assertEquals("test1234 ", credentials.value);
      });
   }

   @Test
   public void testEmptyValue() {
      String headerValue = "Basic ";
      Optional<Credentials> maybeCredentials = Credentials.credentials(headerValue);
      assertNotNull(maybeCredentials);
      assertTrue(maybeCredentials.isPresent());
      maybeCredentials.ifPresent(credentials -> {
         assertNotNull(credentials.scheme);
         assertEquals("Basic", credentials.scheme);
         assertNotNull(credentials.value);
         assertTrue(credentials.value.isEmpty());
      });
   }

   @Test
   public void testEmptyHeader() {
      String headerValue = "";
      Optional<Credentials> maybeCredentials = Credentials.credentials(headerValue);
      assertNotNull(maybeCredentials);
      assertFalse(maybeCredentials.isPresent());
   }

   @Test
   public void testNullHeader() {
      Optional<Credentials> maybeCredentials = Credentials.credentials((String)null);
      assertNotNull(maybeCredentials);
      assertFalse(maybeCredentials.isPresent());
   }

   @Test
   public void testInvalidSpacesOnly() {
      String headerValue = "   ";
      Optional<Credentials> maybeCredentials = Credentials.credentials(headerValue);
      assertNotNull(maybeCredentials);
      assertFalse(maybeCredentials.isPresent());
   }
}
