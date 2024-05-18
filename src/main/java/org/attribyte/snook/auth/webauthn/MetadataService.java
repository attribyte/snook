package org.attribyte.snook.auth.webauthn;

import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.attestation.AttestationTrustSource;
import java.util.Set;
import org.checkerframework.checker.nullness.qual.NonNull;

public interface MetadataService extends AttestationTrustSource {
  Set<Object> findEntries(@NonNull RegistrationResult registrationResult);
}