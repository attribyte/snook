package org.attribyte.snook.auth.webauthn;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.attribyte.api.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

public class InMemoryStorage implements CredentialRepository {

   private static final org.slf4j.Logger log = LoggerFactory.getLogger(InMemoryStorage.class);

   /**
    * Create credential storage with a logger.
    * @param logger The logger.
    * @param maximumCacheSize The maximum cache size.
    * @param expireTimeHours Time users expire from the cache if not accessed.
    */
   public InMemoryStorage(final Logger logger,
                          final int maximumCacheSize,
                          final int expireTimeHours) {
      this.logger = logger;
      registrationStorage = CacheBuilder.newBuilder().maximumSize(maximumCacheSize)
              .expireAfterAccess(expireTimeHours, TimeUnit.HOURS).build();
   }

   @Override
   public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(final String username) {
      Set<CredentialRegistration> registrations = registrationStorage.getIfPresent(username);
      if(registrations == null || registrations.isEmpty()) {
         return ImmutableSet.of();
      } else {
         final Set<PublicKeyCredentialDescriptor> descriptors = Sets.newHashSetWithExpectedSize(registrations.size());
         registrations.forEach(registration -> {
            descriptors.add(
                    PublicKeyCredentialDescriptor.builder()
                            .id(registration.credential.getCredentialId())
                            .transports(registration.transports())
                            .build()

            );
         });
         return descriptors;
      }
   }

   @Override
   public Optional<ByteArray> getUserHandleForUsername(final String username) {
      final Set<CredentialRegistration> registrations = registrationStorage.getIfPresent(username);
      if(registrations == null || registrations.isEmpty()) {
         return Optional.empty();
      } else {
         return Optional.of(registrations.iterator().next().userIdentity.getId());
      }
   }

   @Override
   public Optional<String> getUsernameForUserHandle(final ByteArray userHandle) {
      for(Set<CredentialRegistration> registrations : registrationStorage.asMap().values()) {
         if(!registrations.isEmpty()) {
            CredentialRegistration registration = registrations.iterator().next();
            if(registration.userIdentity.getId().equals(userHandle)) {
               return Optional.of(registration.userIdentity.getName());
            }
         }
      }
      return Optional.empty();
   }

   @Override
   public Optional<RegisteredCredential> lookup(final ByteArray credentialId, final ByteArray userHandle) {
      Set<RegisteredCredential> credentials = lookupAll(credentialId);
      for(RegisteredCredential credential : credentials) {
         if(credential.getUserHandle().equals(userHandle)) {
            return Optional.of(credential);
         }
      }
      return Optional.empty();
   }

   @Override
   public Set<RegisteredCredential> lookupAll(final ByteArray credentialId) {
      final Set<RegisteredCredential> credentials = Sets.newHashSetWithExpectedSize(4);
      registrationStorage.asMap().values().forEach(registrations -> {
         registrations.forEach(registration -> {
            if(registration.credential.getCredentialId().equals(credentialId)) {
               credentials.add(
                       RegisteredCredential.builder()
                               .credentialId(registration.credential.getCredentialId())
                               .userHandle(registration.userIdentity.getId())
                               .publicKeyCose(registration.credential.getPublicKeyCose())
                               .signatureCount(registration.credential.getSignatureCount())
                               .build()
               );
            }
         });
      });

      return credentials;
   }

   /**
    * Adds registration for a user.
    * @param username The username.
    * @param registration The registration.
    * @return Was the registration previously added?
    */
   public boolean addRegistration(final String username, final CredentialRegistration registration) {
      try {
         return registrationStorage.get(username, Sets::newHashSet).add(registration);
      } catch (ExecutionException e) {
         logger.error(String.format("Failed to add registration for '%s'", username), e);
         throw new RuntimeException(e);
      }
   }

   /**
    * The logger.
    */
   private final Logger logger;

   /**
    * In-memory cache of registered credentials for a username.
    */
   private final Cache<String, Set<CredentialRegistration>> registrationStorage;
}
