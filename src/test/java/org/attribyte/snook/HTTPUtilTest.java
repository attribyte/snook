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

import org.eclipse.jetty.http.HttpHeader;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertFalse;

/**
 * Tests for HTTP Utility methods.
 */
public class HTTPUtilTest {

   @Test
   public void acceptsHTML() {
      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.ACCEPT.asString()) ?
                    "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" : null;
         }
      };
      assertTrue(HTTPUtil.clientAcceptsHTML(request));
   }

   @Test
   public void rejectsHTML() {
      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.ACCEPT.asString()) ?
                    "text/plain, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" : null;
         }
      };
      assertFalse(HTTPUtil.clientAcceptsHTML(request));
   }
}