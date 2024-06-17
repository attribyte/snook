package org.attribyte.snook.auth.webauthn;

import com.google.common.base.Charsets;
import com.google.common.cache.Cache;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.exception.AssertionFailedException;
import org.attribyte.api.Logger;
import org.attribyte.snook.auth.webauthn.data.AssertionRequestWrapper;
import org.attribyte.snook.auth.webauthn.data.AssertionResponse;
import org.attribyte.snook.auth.webauthn.data.RegistrationResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;

import static com.google.common.base.Strings.isNullOrEmpty;
import static org.attribyte.snook.auth.webauthn.Util.randomBytes;

class AuthenticationOperations extends Operations {

   public AuthenticationOperations(final RelyingParty relayingParty,
                                   final Storage storage,
                                   final Sessions sessions,
                                   final Cache<ByteArray, AssertionRequestWrapper> assertationRequestCache,
                                   final MetadataService metadataService,
                                   final Logger logger,
                                   final URL baseURL,
                                   final boolean pretty) {
      super(baseURL, pretty);
      this.relayingParty = relayingParty;
      this.storage = storage;
      this.sessions = sessions;
      this.assertionRequestCache = assertationRequestCache;
      this.metadataService = metadataService;
      this.logger = logger;
   }

   /**
    * @return an instance that writes pretty JSON.
    */
   public AuthenticationOperations pretty() {
      return new AuthenticationOperations(relayingParty, storage, sessions, assertionRequestCache, metadataService,
              logger, baseURL, true);
   }

   public void startAuthentication(final String username,
           final HttpServletResponse response) throws IOException {

      if(isNullOrEmpty(username) && !storage.userExists(username)) {
         writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "This username is not registered");
         return;
      }

      AssertionRequestWrapper request =
              new AssertionRequestWrapper(
                      randomBytes(32),
                      relayingParty.startAssertion(StartAssertionOptions.builder().username(username).build()));
      assertionRequestCache.put(request.requestId, request);
      writeResponse(new StartAuthenticationResponse(request,
              new URL(baseURL, "/api/authenticate/finish")), response);
   }

   public void finishAuthentication(final HttpServletRequest request,
                                    final HttpServletResponse response) throws IOException {
      String responseJson = new String(request.getInputStream().readAllBytes(), Charsets.UTF_8);
      AssertionResponse assertionResponse;
      try {
         assertionResponse = jsonMapper.readValue(responseJson, AssertionResponse.class);
      } catch (IOException e) {
         writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "Invalid JSON");
         return;
      }

      AssertionRequestWrapper assertionRequest = assertionRequestCache.getIfPresent(assertionResponse.requestId);
      assertionRequestCache.invalidate(assertionResponse.requestId);
      if(assertionRequest == null) {
         System.out.println("Assertion request null");
         writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "Assertion Not Found");
         return;
      }

      try {
         AssertionResult result =
                 relayingParty.finishAssertion(
                         FinishAssertionOptions.builder()
                                 .request(assertionRequest.request)
                                 .response(assertionResponse.credential)
                                 .build());

         if (result.isSuccess()) {
            try {
               storage.updateSignatureCount(result);
            } catch (Exception e) {
               logger.error(
                       "Failed to update signature count for user \"{}\", credential \"{}\"",
                       result.getUsername(),
                       assertionResponse.credential.getId(),
                       e);
            }

            SuccessfulAuthenticationResult authenticationResult =
                    new SuccessfulAuthenticationResult(
                            assertionRequest,
                            assertionResponse,
                            storage.registrationsByUsername(result.getUsername()),
                            result.getUsername(),
                            sessions.createSession(result.getCredential().getUserHandle()));
            System.out.println("AR " + authenticationResult.toString());
            writeResponse(authenticationResult, response);
         } else {
            writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "Assertion Failed");
         }
      } catch (AssertionFailedException e) {
         e.printStackTrace();
         writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "Assertion Failed");
      } catch (Exception e) {
         e.printStackTrace();
         logger.error("Assertion failed", e);
         writeErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "Assertion Failed");
      }
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
   private final Cache<ByteArray, AssertionRequestWrapper> assertionRequestCache;

   /**
    * The metadata service.
    */
   private final MetadataService metadataService;
}