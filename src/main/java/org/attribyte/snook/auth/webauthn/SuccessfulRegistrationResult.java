package org.attribyte.snook.auth.webauthn;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;
import org.attribyte.snook.auth.webauthn.data.CredentialRegistration;
import org.attribyte.snook.auth.webauthn.data.RegistrationRequest;
import org.attribyte.snook.auth.webauthn.data.RegistrationResponse;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Optional;

public class SuccessfulRegistrationResult {

   public SuccessfulRegistrationResult(
           RegistrationRequest request,
           RegistrationResponse response,
           CredentialRegistration registration,
           boolean attestationTrusted,
           ByteArray sessionToken) throws CertificateException {
      this.request = request;
      this.response = response;
      this.registration = registration;
      this.attestationTrusted = attestationTrusted;
      attestationCert =
              Optional.ofNullable(
                              response
                                      .credential
                                      .getResponse()
                                      .getAttestation()
                                      .getAttestationStatement()
                                      .get("x5c"))
                      .map(certs -> certs.get(0))
                      .flatMap(
                              (JsonNode certDer) -> {
                                 try {
                                    return Optional.of(new ByteArray(certDer.binaryValue()));
                                 } catch (IOException e) {
                                    //logger.error("Failed to get binary value from x5c element: {}", certDer, e);
                                    return Optional.empty();
                                 }
                              })
                      .map(AttestationCertInfo::new);
      this.authData = response.credential.getResponse().getParsedAuthenticatorData();
      this.username = request.username;
      this.sessionToken = sessionToken;
   }

   final boolean success = true;
   final RegistrationRequest request;
   final RegistrationResponse response;
   final CredentialRegistration registration;
   final boolean attestationTrusted;
   final Optional<AttestationCertInfo> attestationCert;
   @JsonSerialize(using = AuthDataSerializer.class)
   final AuthenticatorData authData;
   final String username;
   final ByteArray sessionToken;
}