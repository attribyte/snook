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

/**
 * Store for registered OAuth clients.
 * <p>
 *    Registration is out-of-band (config, admin UI, etc.).
 * </p>
 */
public interface ClientStore {

   /**
    * Gets a client by id.
    * @param clientId The client id.
    * @return The client, or empty if not found.
    */
   Optional<OAuthClient> getClient(String clientId);
}
