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

package org.attribyte.snook.auth.oauth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Renders the OAuth login form.
 * <p>
 *    Implementations are responsible for writing the complete HTML response.
 *    The rendered form must include {@code username} and {@code password} input fields,
 *    the provided hidden fields HTML, and submit via POST to the given form action URL.
 * </p>
 */
@FunctionalInterface
public interface LoginFormRenderer {

   /**
    * Renders the login form.
    * @param request The HTTP request.
    * @param response The HTTP response.
    * @param clientName The OAuth client display name.
    * @param errorMessage An error message, or {@code null} on first render.
    * @param formAction The URL the form should POST to.
    * @param hiddenFieldsHtml Pre-built HTML string of hidden input fields for OAuth parameters.
    * @throws IOException on write error.
    */
   void render(HttpServletRequest request,
               HttpServletResponse response,
               String clientName,
               String errorMessage,
               String formAction,
               String hiddenFieldsHtml) throws IOException;
}
