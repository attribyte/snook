package org.attribyte.snook.auth.webauthn;

import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import org.attribyte.snook.auth.webauthn.data.CredentialRegistration;

import java.util.Collection;

public interface Storage extends CredentialRepository {
   /**
    * Adds registration for a user.
    * @param username The username.
    * @param registration The registration.
    * @return Was the registration previously added?
    */
   public boolean addRegistration(final String username, final CredentialRegistration registration);

   /**
    * Gets all registrations for a user.
    * @param username The username.
    * @return The set of registrations.
    */
   public Collection<CredentialRegistration> registrationsByUsername(String username);

   /**
    * @return Does the user exist?
    */
   public boolean userExists(String username);

   /**
    * Update the signature count.
    * @param result The assertion result.
    */
   public void updateSignatureCount(AssertionResult result);
}
