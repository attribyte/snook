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

import org.junit.Test;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.*;

public class OriginTest {

   @Test
   public void testValidSecure() {
      String headerValue = "https://attribyte.com";
      Origin origin = new Origin(headerValue);
      assertEquals("attribyte.com", origin.host());
      assertEquals(443, origin.port());
      assertTrue(origin.isSecure());
   }

   @Test
   public void testValidInsecure() {
      String headerValue = "http://attribyte.com";
      Origin origin = new Origin(headerValue);
      assertEquals("attribyte.com", origin.host());
      assertEquals(80, origin.port());
      assertFalse(origin.isSecure());
   }

   @Test
   public void testCustomPort() {
      String headerValue = "https://attribyte.com:8443";
      Origin origin = new Origin(headerValue);
      assertEquals("attribyte.com", origin.host());
      assertEquals(8443, origin.port());
      assertTrue(origin.isSecure());
   }

   @Test
   public void testWSS() {
      String headerValue = "wss://attribyte.com/x/y/z";
      Origin origin = new Origin(headerValue);
      assertEquals("attribyte.com", origin.host());
      assertEquals(443, origin.port());
      assertTrue(origin.isSecure());
   }

   @Test
   public void testWS() {
      String headerValue = "ws://attribyte.com/x/y/z";
      Origin origin = new Origin(headerValue);
      assertEquals("attribyte.com", origin.host());
      assertEquals(80, origin.port());
      assertFalse(origin.isSecure());
   }

   @Test
   public void testEquals() {
      String headerValue = "https://attribyte.com:8443";
      Origin origin0 = new Origin(headerValue);
      Origin origin1 = new Origin(headerValue);
      assertEquals(origin0, origin1);
      assertNotEquals(Origin.EMPTY, origin0);
      assertNotEquals(origin0, Origin.EMPTY);
   }

   @Test
   public void testHostAndPort() {
      String headerValue = "https://attribyte.com:8443";
      Origin origin0 = new Origin(headerValue);
      Origin origin1 = new Origin("attribyte.com", 8443, true);
      assertEquals(origin0, origin1);
   }

   @Test(expected = IllegalArgumentException.class)
   public void testInvalid() throws Exception {
      String headerValue = "attribyte.com:8080";
      Origin origin = new Origin(headerValue);
   }

   @Test(expected = IllegalArgumentException.class)
   public void testInvalidProtocol() throws Exception {
      String headerValue = "ftp://attribyte.com:8080";
      Origin origin = new Origin(headerValue);
   }
}
