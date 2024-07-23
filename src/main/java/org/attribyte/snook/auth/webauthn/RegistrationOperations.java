package org.attribyte.snook.auth.webauthn;

import com.google.common.base.Charsets;
import com.google.common.cache.Cache;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.attribyte.api.Logger;
import org.attribyte.snook.auth.webauthn.data.CredentialRegistration;
import org.attribyte.snook.auth.webauthn.data.RegistrationRequest;
import org.attribyte.snook.auth.webauthn.data.RegistrationResponse;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.util.TreeSet;
import java.util.Collection;
import java.util.Optional;
import java.util.SortedSet;
import java.util.concurrent.ExecutionException;

import static com.google.common.base.Strings.isNullOrEmpty;
import static org.attribyte.snook.auth.webauthn.Util.randomBytes;

public class RegistrationOperations extends Operations {

   public RegistrationOperations(final RelyingParty relayingParty,
                                 final Storage storage,
                                 final Sessions sessions,
                                 final Cache<ByteArray, RegistrationRequest> registrationRequestCache,
                                 final MetadataService metadataService,
                                 final Logger logger,
                                 final URL baseURL,
                                 final boolean pretty) {
      super(baseURL, pretty);
      this.relayingParty = relayingParty;
      this.storage = storage;
      this.sessions = sessions;
      this.registrationRequestCache = registrationRequestCache;
      this.metadataService = metadataService;
      this.logger = logger;
   }

   /**
    * @return an instance that writes pretty JSON.
    */
   public RegistrationOperations pretty() {
      return new RegistrationOperations(relayingParty, storage, sessions, registrationRequestCache, metadataService,
              logger, baseURL, true);
   }

   public void startRegistration(
           @NonNull final String username,
           @Nullable String displayName,
           @Nullable final String credentialNickname,
           final String requireResidentKey,
           final String sessionTokenBase64,
           final HttpServletResponse response) throws IOException {
      final RegistrationRequest registrationRequest;

      try {
         registrationRequest = buildRegistrationRequest(username, displayName, credentialNickname,
                 requireResidentKey, sessionTokenBase64, response);
         if(registrationRequest == null) {
            return; //Error sent.
         }
      } catch(ExecutionException e) {
         writeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                 "Failed to build registration request");
         return;
      }

      final URL finishPath = new URL(baseURL, "/api/register/finish");
      final StartRegistrationResponse registrationResponse = new StartRegistrationResponse(registrationRequest, finishPath);
      writeResponse(registrationResponse, response);
   }

   /**
    * Builds the registration request.
    * @param username The username.
    * @param displayName The display name.
    * @param credentialNickname The optional credential nickname.
    * @param requireResidentKey The resident key requirement.
    * @param sessionTokenBase64 The session token.
    * @param response The response.
    * @return The request or {@code null} if user with name exists.
    */
   public RegistrationRequest buildRegistrationRequest(
           @NonNull final String username,
           @Nullable String displayName,
           @Nullable final String credentialNickname,
           final String requireResidentKey,
           final String sessionTokenBase64,
           final HttpServletResponse response) throws IOException, ExecutionException {

      if(username.isEmpty()) {
         writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "A 'username' is required");
         return null;
      }

      final ByteArray sessionToken;

      try {
         sessionToken = sessionTokenBase64.isEmpty() ? null : ByteArray.fromBase64Url(sessionTokenBase64);
      } catch(Base64UrlException e) {
         writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,"Session token is invalid Base 64");
         return null;
      }

      ResidentKeyRequirement residentKeyRequirement = requireResidentKey.equalsIgnoreCase("true") ?
              ResidentKeyRequirement.REQUIRED :ResidentKeyRequirement.DISCOURAGED;

      if(isNullOrEmpty(displayName)) {
         displayName = username;
      }

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
         permissionGranted = sessions.isSessionForUser(registeringUser.getId(), sessionToken);
      }

      if(!permissionGranted) {
         writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST,
                 String.format("Registration request received for already registered user ('%s')", username));
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
                      Optional.ofNullable(sessions.createSession(registeringUser.getId())));
      registrationRequestCache.put(request.requestId, request);
      return request;
   }

   public void finishRegistration(final HttpServletRequest request,
                                  final HttpServletResponse response) throws IOException {

      String responseJson = new String(request.getInputStream().readAllBytes(), Charsets.UTF_8);
      RegistrationResponse registrationResponse;
      try {
         registrationResponse = jsonMapper.readValue(responseJson, RegistrationResponse.class);
      } catch (IOException e) {
         writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "Invalid JSON");
         return;
      }

      RegistrationRequest registrationRequest = registrationRequestCache.getIfPresent(registrationResponse.requestId);
      registrationRequestCache.invalidate(registrationResponse.requestId);
      if (registrationRequest == null) {
         writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "Finish registration failed");
      } else {
         try {
            RegistrationResult registration =
                    relayingParty.finishRegistration(
                            FinishRegistrationOptions.builder()
                                    .request(registrationRequest.publicKeyCredentialCreationOptions)
                                    .response(registrationResponse.credential)
                                    .build());

            if (storage.userExists(registrationRequest.username)) {
               boolean permissionGranted = false;

               final boolean isValidSession =
                       registrationRequest
                               .sessionToken
                               .map(
                                       token ->
                                               sessions.isSessionForUser(
                                                       registrationRequest.publicKeyCredentialCreationOptions.getUser().getId(),
                                                       token))
                               .orElse(false);

               System.out.println("IS VALID SESSION");

               logger.debug("Session token: {}", registrationRequest.sessionToken);
               logger.debug("Valid session: {}", isValidSession);

               if (isValidSession) {
                  permissionGranted = true;
                  logger.info(
                          "Session token accepted for user {}",
                          registrationRequest.publicKeyCredentialCreationOptions.getUser().getId());
               }

               logger.debug("permissionGranted: {}", permissionGranted);

               if (!permissionGranted) {
                  System.out.println("PERMISSION DENIED");
                  throw new RegistrationFailedException(
                          new IllegalArgumentException(
                                  String.format("User %s already exists", registrationRequest.username)));
               }
            }

            SuccessfulRegistrationResult successfulRegistrationResult =
                    new SuccessfulRegistrationResult(
                            registrationRequest,
                            registrationResponse,
                            addRegistration(
                                    registrationRequest.publicKeyCredentialCreationOptions.getUser(),
                                    Optional.ofNullable(registrationRequest.credentialNickname),
                                    registration),
                            registration.isAttestationTrusted(),
                            sessions.createSession(
                                    registrationRequest.publicKeyCredentialCreationOptions.getUser().getId()));
            writeResponse(successfulRegistrationResult, response);
         } catch (RegistrationFailedException e) {
            System.out.println("REGISTRATION FAILED");
            e.printStackTrace();
            logger.debug("fail finishRegistration responseJson: {}", responseJson, e);
         } catch (Exception e) {
            System.out.println("REGISTRATION FAILED 2");
            e.printStackTrace();
            logger.error("fail finishRegistration responseJson: {}", responseJson, e);
         }
      }
   }

   private CredentialRegistration addRegistration(
           UserIdentity userIdentity, Optional<String> nickname, RegistrationResult result) {
      return addRegistration(
              userIdentity,
              nickname,
              RegisteredCredential.builder()
                      .credentialId(result.getKeyId().getId())
                      .userHandle(userIdentity.getId())
                      .publicKeyCose(result.getPublicKeyCose())
                      .signatureCount(result.getSignatureCount())
                      .build(),
              result.getKeyId().getTransports().orElseGet(TreeSet::new),
              metadataService.findEntries(result).stream().findAny());
   }

   private CredentialRegistration addRegistration(
           UserIdentity userIdentity,
           Optional<String> nickname,
           RegisteredCredential credential,
           SortedSet<AuthenticatorTransport> transports,
           Optional<Object> attestationMetadata) {
      CredentialRegistration reg = new CredentialRegistration(
              userIdentity, nickname, transports, System.currentTimeMillis(), credential, attestationMetadata);
      logger.debug(
              "Adding registration: user: {}, nickname: {}, credential: {}",
              userIdentity,
              nickname,
              credential);
      storage.addRegistration(userIdentity.getName(), reg);
      return reg;
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

   /**
    * The metadata service.
    */
   private final MetadataService metadataService;

}