package org.attribyte.snook.auth.webauthn;

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

import java.net.URL;
import java.util.Collection;
import java.util.concurrent.ExecutionException;

import static org.attribyte.snook.auth.webauthn.Util.randomBytes;

class RegistrationOperations extends Operations {

   public RegistrationOperations(final RelyingParty relayingParty,
                                 final Storage storage,
                                 final Sessions sessions,
                                 final Cache<ByteArray, RegistrationRequest> registrationRequestCache,
                                 final Logger logger,
                                 final URL baseURL) {
      super(baseURL);
      this.relayingParty = relayingParty;
      this.storage = storage;
      this.sessions = sessions;
      this.registrationRequestCache = registrationRequestCache;
      this.logger = logger;
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