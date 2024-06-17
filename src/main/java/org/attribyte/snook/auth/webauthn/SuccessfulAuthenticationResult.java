package org.attribyte.snook.auth.webauthn;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.google.common.base.MoreObjects;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;
import org.attribyte.snook.auth.webauthn.data.AssertionRequestWrapper;
import org.attribyte.snook.auth.webauthn.data.AssertionResponse;
import org.attribyte.snook.auth.webauthn.data.CredentialRegistration;

import java.util.Collection;

public class SuccessfulAuthenticationResult {

   public SuccessfulAuthenticationResult(
           AssertionRequestWrapper request,
           AssertionResponse response,
           Collection<CredentialRegistration> registrations,
           String username,
           ByteArray sessionToken) {

      this.success = true;
      this.request = request;
      this.response = response;
      this.registrations = registrations;
      this.username = username;
      this.sessionToken = sessionToken;
   }


   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("success", success)
              .add("request", request)
              .add("response", response)
              .add("registrations", registrations)
              .add("authData", authData)
              .add("username", username)
              .add("sessionToken", sessionToken)
              .toString();
   }

   public final boolean success;
   public final AssertionRequestWrapper request;
   public final AssertionResponse response;
   public final Collection<CredentialRegistration> registrations;

   @JsonSerialize(using = AuthDataSerializer.class)
   public AuthenticatorData authData;

   public final String username;
   public final ByteArray sessionToken;
}
