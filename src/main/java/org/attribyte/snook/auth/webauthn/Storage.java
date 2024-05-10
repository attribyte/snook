package org.attribyte.snook.auth.webauthn;

import com.yubico.webauthn.CredentialRepository;

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
}
