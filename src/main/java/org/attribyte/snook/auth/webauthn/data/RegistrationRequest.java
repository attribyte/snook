package org.attribyte.snook.auth.webauthn.data;

import com.google.common.base.MoreObjects;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;
import java.util.Optional;

import static com.google.common.base.Strings.emptyToNull;

public class RegistrationRequest {

   public RegistrationRequest(@NonNull final String username,
                              @Nullable final String credentialNickname,
                              @NonNull final ByteArray requestId,
                              @NonNull final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
                              @NonNull final Optional<ByteArray> sessionToken) {
      this.username = username;
      this.credentialNickname = emptyToNull(credentialNickname);
      this.requestId = requestId;
      this.publicKeyCredentialCreationOptions = publicKeyCredentialCreationOptions;
      this.sessionToken = sessionToken;
   }

   @Override
   public boolean equals(final Object o) {
      if(this == o) return true;
      if(o == null || getClass() != o.getClass()) return false;
      final RegistrationRequest that = (RegistrationRequest)o;
      return Objects.equals(username, that.username) && Objects.equals(credentialNickname,
              that.credentialNickname) && Objects.equals(requestId, that.requestId) &&
              Objects.equals(publicKeyCredentialCreationOptions, that.publicKeyCredentialCreationOptions) &&
              Objects.equals(sessionToken, that.sessionToken);
   }

   @Override
   public int hashCode() {
      return Objects.hash(username, credentialNickname, requestId, publicKeyCredentialCreationOptions, sessionToken);
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("username", username)
              .add("credentialNickname", credentialNickname)
              .add("requestId", requestId)
              .add("publicKeyCredentialCreationOptions", publicKeyCredentialCreationOptions)
              .add("sessionToken", sessionToken)
              .toString();
   }

   public final String username;
   public final String credentialNickname;
   public final ByteArray requestId;
   public final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;
   public final Optional<ByteArray> sessionToken;
}
