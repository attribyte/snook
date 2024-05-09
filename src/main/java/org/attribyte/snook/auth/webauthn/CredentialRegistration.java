package org.attribyte.snook.auth.webauthn;

import com.google.common.collect.ImmutableSet;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.RegisteredCredential;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.SortedSet;

public class CredentialRegistration {

   public CredentialRegistration(@NonNull final UserIdentity userIdentity,
                                 final String credentialNickname,
                                 final long registrationTime, final RegisteredCredential credential,
                                 final Object attestationMetadata) {
      this.userIdentity = userIdentity;
      this.credentialNickname = credentialNickname;
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


   public final String credentialNickname;
   private SortedSet<AuthenticatorTransport> transports;
   public final long registrationTime;
   public final RegisteredCredential credential;
   public final Object attestationMetadata;
}
