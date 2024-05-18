package org.attribyte.snook.auth.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableSet;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.RegisteredCredential;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.Collection;
import java.util.Optional;

public class CredentialRegistration {

   public CredentialRegistration(@NonNull final UserIdentity userIdentity,
                                 final Optional<String> credentialNickname,
                                 final Collection<AuthenticatorTransport> transports,
                                 final long registrationTime,
                                 final RegisteredCredential credential,
                                 final Optional<Object> attestationMetadata) {
      this.userIdentity = userIdentity;
      this.credentialNickname = credentialNickname;
      this.transports = transports != null ? ImmutableSet.copyOf(transports) : ImmutableSet.of();
      this.registrationTime = registrationTime;
      this.credential = credential;
      this.attestationMetadata = attestationMetadata;
   }

   /**
    * @return An immutable set of the transports.
    */
   public ImmutableSet<AuthenticatorTransport> transports() {
      return transports != null ? ImmutableSet.copyOf(transports) : ImmutableSet.of();
   }

   /**
    * The user identity.
    */
   public final UserIdentity userIdentity;
   public final Optional<String> credentialNickname;
   public final ImmutableSet<AuthenticatorTransport> transports;
   @JsonIgnore public final long registrationTime;
   public final RegisteredCredential credential;
   public final Optional<Object> attestationMetadata;
   @JsonProperty("registrationTime")
   public String getRegistrationTimestamp() {
      return Long.toString(registrationTime);
   }
}