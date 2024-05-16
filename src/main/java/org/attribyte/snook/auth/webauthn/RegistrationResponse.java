package org.attribyte.snook.auth.webauthn;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;

import java.util.Optional;

/**
 * The registration response.
 */
public class RegistrationResponse {
   @JsonCreator
   public RegistrationResponse(
           @JsonProperty("requestId")
           final ByteArray requestId,
           @JsonProperty("credential")
           final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
                   credential,
           @JsonProperty("sessionToken")
           final Optional<ByteArray> sessionToken) {
      this.requestId = requestId;
      this.credential = credential;
      this.sessionToken = sessionToken;
   }

   public final ByteArray requestId;
   public final PublicKeyCredential<
           AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
           credential;
   public final Optional<ByteArray> sessionToken;
}