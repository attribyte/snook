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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.ExecutionException;

import com.google.common.cache.Cache;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import org.attribyte.api.Logger;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;


import static org.attribyte.snook.HTTPUtil.splitPath;
import static org.attribyte.snook.auth.webauthn.Util.randomBytes;

/**
 * A servlet that handles webauthn registration.
 */
public class RegistrationServlet extends HttpServlet {

   public RegistrationServlet(final RelyingParty relayingParty,
                              final Storage storage,
                              final Sessions sessions,
                              final Cache<ByteArray, RegistrationRequest> registrationRequestCache,
                              final Logger logger) throws MalformedURLException {
      this.ops = new RegistrationOperations(relayingParty, storage, sessions,
              registrationRequestCache, logger, new URL("http://localhost:8081/register"));
      this.logger = logger;
   }

   @Override
   protected final void doGet(final HttpServletRequest request,
                              final HttpServletResponse response) throws IOException {
      respond(request, response);
   }

   @Override
   protected final void doPost(final HttpServletRequest request,
                               final HttpServletResponse response) throws IOException {
      respond(request, response);
   }

   private void respond(final HttpServletRequest request,
                               final HttpServletResponse response) throws IOException {
      Iterator<String> path = splitPath(request).iterator();
      final String op;
      if(path.hasNext()) {
         op = path.next();
      } else {
         response.sendError(400, "Expecting an operation");
         return;
      }

      switch(op) {
         case "challenge": {
            System.out.println("GOT CHALLENGE");
            if(!path.hasNext()) {
               response.sendError(400, "Expecting a username");
               return;
            }
            final String username = path.next();
            System.out.println("GOT USERNAME: " + username);
            System.out.println("Challenge...");

         }
         break;
         default:
            response.sendError(400, "Invalid operation");

      }

      response.sendError(500, "ERROR");
   }

   /**
    * The registration operations.
    */
   private final RegistrationOperations ops;

   /**
    * The logger.
    */
   private final Logger logger;
}
