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

package org.attribyte.snook.auth.webauthn;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A servlet that handles webauthn registration.
 */
public class RegistrationChallengeServlet extends HttpServlet {
   @Override
   protected final void doGet(final HttpServletRequest request,
                              final HttpServletResponse response) throws IOException {
      request(request, response);
   }

   @Override
   protected final void doPost(final HttpServletRequest request,
                               final HttpServletResponse response) throws IOException {
      request(request, response);
   }

   protected final void request(final HttpServletRequest request,
                                final HttpServletResponse response) throws IOException {

   }
}
