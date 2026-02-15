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

package org.attribyte.snook.auth.oauth.store;

import org.attribyte.snook.auth.oauth.model.OAuthClient;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory client store for development and testing.
 */
public class InMemoryClientStore implements ClientStore {

   private final ConcurrentHashMap<String, OAuthClient> clients = new ConcurrentHashMap<>();

   /**
    * Registers a client.
    * @param client The client.
    */
   public void register(final OAuthClient client) {
      clients.put(client.clientId, client);
   }

   @Override
   public Optional<OAuthClient> getClient(final String clientId) {
      return Optional.ofNullable(clients.get(clientId));
   }
}
