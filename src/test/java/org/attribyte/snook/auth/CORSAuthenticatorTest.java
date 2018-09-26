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

import org.attribyte.snook.TestHttpServletRequest;
import org.attribyte.snook.TestHttpServletResponse;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.EnumSet;
import java.util.Properties;

import static org.junit.Assert.*;

public class CORSAuthenticatorTest {

   @Test
   public void testAllowAll() {

      Properties props = new Properties();
      props.put(CORSAuthenticator.ALLOW_ORIGIN_HOST_PROP, "*");
      CORSAuthenticator authenticator = new CORSAuthenticator(props);

      HttpServletRequest request = new TestHttpServletRequest() {
         public String getHeader(final String s) {
            switch(s.toLowerCase()) {
               case "origin":
                  return "https://attribyte.com";
               default:
                  return null;
            }
         }
      };

      HttpServletResponse response = new TestHttpServletResponse();

      String allowedUsername = authenticator.authorizeRequest(request, response, EnumSet.of(CORSAuthenticator.Option.ALLOW_ANY_ORGIN));

      assertNotNull(allowedUsername);
      assertEquals("attribyte.com", allowedUsername);
      assertTrue(response.containsHeader("Access-Control-Allow-Origin"));
      assertEquals("*", response.getHeader("Access-Control-Allow-Origin"));
      assertFalse(response.containsHeader("Access-Control-Allow-Credentials"));
   }

   @Test
   public void testAllowSpecific() {

      Properties props = new Properties();
      props.put(CORSAuthenticator.ALLOW_ORIGIN_HOST_PROP, "attribyte.com");
      CORSAuthenticator authenticator = new CORSAuthenticator(props);

      HttpServletRequest request = new TestHttpServletRequest() {
         public String getHeader(final String s) {
            switch(s.toLowerCase()) {
               case "origin":
                  return "https://attribyte.com";
               default:
                  return null;
            }
         }
      };

      HttpServletResponse response = new TestHttpServletResponse();

      String allowedUsername = authenticator.authorizeRequest(request, response, EnumSet.noneOf(CORSAuthenticator.Option.class));
      assertNotNull(allowedUsername);

      assertTrue(response.containsHeader("Access-Control-Allow-Origin"));
      assertEquals("https://attribyte.com", response.getHeader("Access-Control-Allow-Origin"));
      assertFalse(response.containsHeader("Access-Control-Allow-Credentials"));
   }

   @Test
   public void testAllowDomain() {

      Properties props = new Properties();
      props.put(CORSAuthenticator.ALLOW_ORIGIN_DOMAIN_PROP, "attribyte.com");
      CORSAuthenticator authenticator = new CORSAuthenticator(props);

      HttpServletRequest request = new TestHttpServletRequest() {
         public String getHeader(final String s) {
            switch(s.toLowerCase()) {
               case "origin":
                  return "https://test.attribyte.com";
               default:
                  return null;
            }
         }
      };

      HttpServletResponse response = new TestHttpServletResponse();

      String allowedUsername = authenticator.authorizeRequest(request, response, EnumSet.of(CORSAuthenticator.Option.ALLOW_CREDENTIALS));
      assertNotNull(allowedUsername);
   }

   @Test
   public void testDenyDomain() {

      Properties props = new Properties();
      props.put(CORSAuthenticator.ALLOW_ORIGIN_DOMAIN_PROP, "*");
      props.put(CORSAuthenticator.DENY_ORIGIN_DOMAIN_PROP, "attribyte.com");

      CORSAuthenticator authenticator = new CORSAuthenticator(props);

      HttpServletRequest request = new TestHttpServletRequest() {
         public String getHeader(final String s) {
            switch(s.toLowerCase()) {
               case "origin":
                  return "https://test.attribyte.com";
               default:
                  return null;
            }
         }
      };

      HttpServletResponse response = new TestHttpServletResponse();

      String allowedUsername = authenticator.authorizeRequest(request, response, EnumSet.of(CORSAuthenticator.Option.ALLOW_CREDENTIALS));
      assertNull(allowedUsername);
   }

   @Test
   public void testDenyHost() {

      Properties props = new Properties();
      props.put(CORSAuthenticator.ALLOW_ORIGIN_HOST_PROP, "*");
      props.put(CORSAuthenticator.DENY_ORIGIN_HOST_PROP, "test.attribyte.com");

      CORSAuthenticator authenticator = new CORSAuthenticator(props);

      HttpServletRequest request = new TestHttpServletRequest() {
         public String getHeader(final String s) {
            switch(s.toLowerCase()) {
               case "origin":
                  return "https://test.attribyte.com";
               default:
                  return null;
            }
         }
      };

      HttpServletResponse response = new TestHttpServletResponse();

      String allowedUsername = authenticator.authorizeRequest(request, response, EnumSet.of(CORSAuthenticator.Option.ALLOW_CREDENTIALS));
      assertNull(allowedUsername);

      request = new TestHttpServletRequest() {
         public String getHeader(final String s) {
            switch(s.toLowerCase()) {
               case "origin":
                  return "https://test2.attribyte.com";
               default:
                  return null;
            }
         }
      };

      allowedUsername = authenticator.authorizeRequest(request, response, EnumSet.of(CORSAuthenticator.Option.ALLOW_CREDENTIALS));
      assertNotNull(allowedUsername);
   }

   @Test
   public void testDenySimple() {

      Properties props = new Properties();
      props.put(CORSAuthenticator.ALLOW_ORIGIN_HOST_PROP, "attribyte.com");
      CORSAuthenticator authenticator = new CORSAuthenticator(props);

      HttpServletRequest request = new TestHttpServletRequest() {
         public String getHeader(final String s) {
            switch(s.toLowerCase()) {
               case "origin":
                  return "https://attribytex.com";
               default:
                  return null;
            }
         }
      };

      HttpServletResponse response = new TestHttpServletResponse();

      String allowedUsername = authenticator.authorizeRequest(request, response, EnumSet.of(CORSAuthenticator.Option.ALLOW_ANY_ORGIN,
              CORSAuthenticator.Option.ALLOW_CREDENTIALS));
      assertNull(allowedUsername);
   }

   @Test
   public void testRequireSecureOrigin() {

      Properties props = new Properties();
      props.put(CORSAuthenticator.ALLOW_ORIGIN_HOST_PROP, "*");
      props.put(CORSAuthenticator.REQUIRE_SECURE_ORIGIN_PROP, "true");
      CORSAuthenticator authenticator = new CORSAuthenticator(props);

      HttpServletRequest request = new TestHttpServletRequest() {
         public String getHeader(final String s) {
            switch(s.toLowerCase()) {
               case "origin":
                  return "http://attribyte.com";
               default:
                  return null;
            }
         }
      };

      HttpServletResponse response = new TestHttpServletResponse();

      String allowedUsername = authenticator.authorizeRequest(request, response, EnumSet.of(CORSAuthenticator.Option.ALLOW_ANY_ORGIN,
              CORSAuthenticator.Option.ALLOW_CREDENTIALS));

      assertNull(allowedUsername);
   }

   @Test
   public void testAllowPreFlight() {

      Properties props = new Properties();
      props.put(CORSAuthenticator.ALLOW_ORIGIN_HOST_PROP, "*");
      props.put(CORSAuthenticator.EXPOSE_HEADERS_PROP, "X-Response-Header");
      props.put(CORSAuthenticator.ALLOW_HEADERS_PROP, "X-Request-Header");
      props.put(CORSAuthenticator.MAX_AGE_PROP, "12");
      props.put(CORSAuthenticator.ALLOW_METHODS_PROP, "OPTIONS, GET");
      CORSAuthenticator authenticator = new CORSAuthenticator(props);

      HttpServletRequest request = new TestHttpServletRequest() {
         public String getHeader(final String s) {
            switch(s.toLowerCase()) {
               case "origin":
                  return "https://attribyte.com";
               default:
                  return null;
            }
         }
      };

      HttpServletResponse response = new TestHttpServletResponse();

      String allowedUsername = authenticator.authorizePreFlightRequest(request, response,
              EnumSet.of(CORSAuthenticator.Option.ALLOW_ANY_ORGIN,
              CORSAuthenticator.Option.ALLOW_CREDENTIALS));

      assertNotNull(allowedUsername);

      assertEquals("attribyte.com", allowedUsername);

      assertTrue(response.containsHeader("Access-Control-Allow-Origin"));
      assertEquals("https://attribyte.com", response.getHeader("Access-Control-Allow-Origin"));

      assertTrue(response.containsHeader("Access-Control-Allow-Credentials"));
      assertEquals("true", response.getHeader("Access-Control-Allow-Credentials"));

      assertTrue(response.containsHeader("Access-Control-Max-Age"));
      assertEquals("12", response.getHeader("Access-Control-Max-Age"));

      assertTrue(response.containsHeader("Access-Control-Allow-Headers"));
      assertEquals("X-Request-Header", response.getHeader("Access-Control-Allow-Headers"));

      assertTrue(response.containsHeader("Access-Control-Allow-Methods"));
      assertEquals("OPTIONS, GET", response.getHeader("Access-Control-Allow-Methods"));

      assertTrue(response.containsHeader("Access-Control-Expose-Headers"));
      assertEquals("X-Response-Header", response.getHeader("Access-Control-Expose-Headers"));
   }
}