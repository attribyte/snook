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

package org.attribyte.snook;

import org.junit.Test;

import static org.attribyte.snook.Util.*;
import static org.junit.Assert.assertEquals;

/**
 * Tests for utility. methods.
 */
public class UtilTest {

   @Test
   public void normalPath() {
      String url = "https://attribyte.com/a/b/c.html";
      assertEquals("/a/b/c.html", path(url));
   }

   @Test
   public void noPath() {
      String url = "https://attribyte.com";
      assertEquals("", path(url));
   }

   @Test
   public void nullPath() {
      assertEquals("", path(null));
   }

   @Test
   public void rootPath() {
      String url = "https://attribyte.com/";
      assertEquals("/", path(url));
   }

   @Test
   public void queryString() {
      String url = "https://attribyte.com/a/b/c?x=y";
      assertEquals("/a/b/c", path(url));
   }

   @Test
   public void noProtocol() {
      String url = "/a/b/c?x=y";
      assertEquals("/a/b/c", path(url));
   }

   @Test
   public void noProtocolRelative() {
      String url = "a/b/c?x=y";
      assertEquals("a/b/c", path(url));
   }

   @Test
   public void validHost() {
      String url = "https://attribyte.com/1/2/3";
      assertEquals("attribyte.com", host(url));
   }

   @Test
   public void validDomain() {
      String url = "https://something.attribyte.com/1/2/3";
      assertEquals("attribyte.com", domain(url));
   }

   @Test
   public void validDomainBlogspot() {
      String url = "https://x.blogspot.com/1/2/3";
      assertEquals("x.blogspot.com", domain(url));
   }

   @Test
   public void validHostNoProtocol() {
      String url = "attribyte.com/1/2/3";
      assertEquals("attribyte.com", host(url));
   }

   @Test
   public void validDomainNoProtocol() {
      String url = "something.attribyte.com/1/2/3";
      assertEquals("attribyte.com", domain(url));
   }
}
