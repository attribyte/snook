/*
 * Copyright 2018 Attribyte, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

package org.attribyte.snook.auth.oauth.model;

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableSet;
import com.google.common.hash.HashCode;

import java.util.Collection;
import java.util.Optional;

/**
 * An OAuth 2.1 registered client.
 */
public class OAuthClient {

   /**
    * Creates a public client (no secret).
    * @param clientId The client id.
    * @param name The display name.
    * @param redirectUris The allowed redirect URIs.
    * @param allowedScopes The allowed scopes.
    * @return The client.
    */
   public static OAuthClient publicClient(final String clientId,
                                          final String name,
                                          final Collection<String> redirectUris,
                                          final Collection<String> allowedScopes) {
      return new OAuthClient(clientId, Optional.empty(), name, redirectUris, allowedScopes, false);
   }

   /**
    * Creates a confidential client (with secret).
    * @param clientId The client id.
    * @param clientSecretHash The SHA-256 hash of the client secret.
    * @param name The display name.
    * @param redirectUris The allowed redirect URIs.
    * @param allowedScopes The allowed scopes.
    * @return The client.
    */
   public static OAuthClient confidentialClient(final String clientId,
                                                final HashCode clientSecretHash,
                                                final String name,
                                                final Collection<String> redirectUris,
                                                final Collection<String> allowedScopes) {
      return new OAuthClient(clientId, Optional.of(clientSecretHash), name, redirectUris, allowedScopes, true);
   }

   private OAuthClient(final String clientId,
                       final Optional<HashCode> clientSecretHash,
                       final String name,
                       final Collection<String> redirectUris,
                       final Collection<String> allowedScopes,
                       final boolean confidential) {
      this.clientId = clientId;
      this.clientSecretHash = clientSecretHash;
      this.name = name;
      this.redirectUris = ImmutableSet.copyOf(redirectUris);
      this.allowedScopes = ImmutableSet.copyOf(allowedScopes);
      this.confidential = confidential;
   }

   /**
    * Validates that a redirect URI is registered for this client.
    * @param uri The redirect URI to validate.
    * @return {@code true} if the URI is registered.
    */
   public boolean validateRedirectUri(final String uri) {
      return redirectUris.contains(uri);
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("clientId", clientId)
              .add("name", name)
              .add("confidential", confidential)
              .add("redirectUris", redirectUris)
              .add("allowedScopes", allowedScopes)
              .toString();
   }

   /**
    * The client id.
    */
   public final String clientId;

   /**
    * The SHA-256 hash of the client secret, or empty for public clients.
    */
   public final Optional<HashCode> clientSecretHash;

   /**
    * The display name.
    */
   public final String name;

   /**
    * The allowed redirect URIs (exact match per OAuth 2.1).
    */
   public final ImmutableSet<String> redirectUris;

   /**
    * The scopes this client may request.
    */
   public final ImmutableSet<String> allowedScopes;

   /**
    * Is this a confidential client (has a secret)?
    */
   public final boolean confidential;
}
