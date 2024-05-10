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
import java.util.Collection;
import java.util.Iterator;
import java.util.Optional;
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
                              final Logger logger) {
      this.relayingParty = relayingParty;
      this.storage = storage;
      this.sessions = sessions;
      this.registrationRequestCache = registrationRequestCache;
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
    * Start a registration.
    * @param username The username.
    * @param displayName The display name.
    * @param credentialNickname The optional credential nickname.
    * @param residentKeyRequirement The resident key requirement.
    * @param sessionToken The session token.
    * @return The request or {@code null} if user with name exists.
    */
   public RegistrationRequest startRegistration(
           @NonNull String username,
           @Nullable String displayName,
           @Nullable String credentialNickname,
           ResidentKeyRequirement residentKeyRequirement,
           @Nullable ByteArray sessionToken) throws ExecutionException {
      final Collection<CredentialRegistration> registrations =
              storage.registrationsByUsername(username);
      final UserIdentity registeringUser;
      final boolean permissionGranted;
      if(registrations.isEmpty()) {
         registeringUser = UserIdentity.builder()
                 .name(username)
                 .displayName(displayName)
                 .id(randomBytes(32))
                 .build();
         permissionGranted = true;
      } else {
         registeringUser = registrations.iterator().next().userIdentity;
         CredentialRegistration registration = registrations.iterator().next();
         permissionGranted = sessions.isSessionForUser(registeringUser.getId(), sessionToken);
      }

      if(!permissionGranted) {
         logger.warn("Registration request received for already registered user ('%s')", username);
         return null;
      }

      RegistrationRequest request =
              new RegistrationRequest(
                      username,
                      credentialNickname,
                      randomBytes(32),
                      relayingParty.startRegistration(
                              StartRegistrationOptions.builder()
                                      .user(registeringUser)
                                      .authenticatorSelection(
                                              AuthenticatorSelectionCriteria.builder()
                                                      .residentKey(residentKeyRequirement)
                                                      .build())
                                      .build()),
                      sessions.createSession(registeringUser.getId()));
      registrationRequestCache.put(request.requestId, request);
      return request;
   }

   /**
    * The logger.
    */
   private final Logger logger;

   /**
    * The relaying party.
    */
   private final RelyingParty relayingParty;

   /**
    * The storage.
    */
   private final Storage storage;

   /**
    * Registration sessions.
    */
   private final Sessions sessions;

   /**
    * The registration request cache.
    */
   private final Cache<ByteArray, RegistrationRequest> registrationRequestCache;

}
