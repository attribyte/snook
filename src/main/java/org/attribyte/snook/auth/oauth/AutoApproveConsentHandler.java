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
 * Consent handler that auto-approves all requests.
 * <p>
 *    For development/testing and first-party clients where
 *    the user has already authenticated and consent is implicit.
 * </p>
 */
public class AutoApproveConsentHandler implements ConsentHandler {

   @Override
   public void renderConsent(final HttpServletRequest request,
                             final HttpServletResponse response,
                             final OAuthClient client,
                             final Set<String> requestedScopes,
                             final String state,
                             final String approveActionUrl) throws IOException {
      response.sendRedirect(approveActionUrl);
   }
}
