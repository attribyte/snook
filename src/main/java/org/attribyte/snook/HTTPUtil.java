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

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import org.attribyte.api.http.Response;
import org.eclipse.jetty.http.HttpHeader;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * HTTP-related utilities.
 */
public class HTTPUtil {

   /**
    * Splits the accept header.
    */
   private static final Splitter acceptHeaderSplitter = Splitter.on(',').limit(5).omitEmptyStrings().trimResults();

   /**
    * Determines if the client accepts {@code text/html}.
    * @param request The request.
    * @return Does the client accept HTML?
    */
   public static boolean clientAcceptsHTML(final HttpServletRequest request) {
      String acceptHeader = Strings.nullToEmpty(request.getHeader(HttpHeader.ACCEPT.asString()));
      if(!acceptHeader.isEmpty()) {
         for(String type : acceptHeaderSplitter.split(acceptHeader)) {
            if(type.equalsIgnoreCase("text/html")) {
               return true;
            }
         }
      }
      return false;
   }

   /**
    * Template for WWW-Authenticate value when basic auth is required.
    */
   private static final String WWW_AUTHENTICATE_BASIC = "Basic realm=\"%s\"";

   /**
    * Sends HTTP unauthorized.
    * <p>
    *    If the client accepts {@code text/html}, the standard message will be returned via ({@code sendError}),
    *    otherwise no content (other than the status) will be sent with the response.
    * </p>
    * @param request The request.
    * @param response The response.
    * @param basicAuthRealm The realm sent with the {@code WWW-Authenticate} response header.
    * @throws IOException on output error.
    */
   public static void sendHTTPUnauthorized(final HttpServletRequest request,
                                           final HttpServletResponse response,
                                           final String basicAuthRealm) throws IOException {
      response.setHeader("WWW-Authenticate", String.format(WWW_AUTHENTICATE_BASIC, Strings.nullToEmpty(basicAuthRealm)));
      if(clientAcceptsHTML(request)) {
         response.sendError(Response.Code.UNAUTHORIZED, "Authorization Required");
      } else {
         response.setStatus(Response.Code.UNAUTHORIZED);
         response.setContentLength(0);
         response.flushBuffer();
      }
   }

   /**
    * Sends HTTP unauthorized.
    * @param request The request.
    * @param response The response.
    * @param basicAuthRealm The realm sent with the 'WWW-Authenticate' response header.
    * @param message The message to send with the response.
    * @throws IOException on output error.
    */
   public static void sendHTTPUnauthorized(final HttpServletRequest request,
                                           final HttpServletResponse response,
                                           final String basicAuthRealm,
                                           final String message) throws IOException {
      response.setHeader("WWW-Authenticate", String.format(WWW_AUTHENTICATE_BASIC, Strings.nullToEmpty(basicAuthRealm)));
      response.setStatus(Response.Code.UNAUTHORIZED);
      response.getOutputStream().print(message);
      response.flushBuffer();
   }
}
