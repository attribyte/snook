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

import org.attribyte.snook.auth.oauth.model.OAuthClient;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

/**
 * Handler for rendering the OAuth consent screen.
 * <p>
 *    Consuming projects implement this to show their own consent UI.
 * </p>
 */
public interface ConsentHandler {

   /**
    * Renders the consent screen.
    * @param request The HTTP request.
    * @param response The HTTP response.
    * @param client The OAuth client requesting authorization.
    * @param requestedScopes The scopes being requested.
    * @param state The OAuth state parameter.
    * @param approveActionUrl The URL to POST to when the user approves.
    * @throws IOException on write error.
    */
   void renderConsent(HttpServletRequest request,
                      HttpServletResponse response,
                      OAuthClient client,
                      Set<String> requestedScopes,
                      String state,
                      String approveActionUrl) throws IOException;
}
