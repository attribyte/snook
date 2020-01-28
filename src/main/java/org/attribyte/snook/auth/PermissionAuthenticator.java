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

package org.attribyte.snook.auth;

import com.google.common.base.Strings;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;

/**
 * An authenticator that returns permissions based on authentication status.
 */
public abstract class PermissionAuthenticator {

   /**
    * Creates the permission authenticator.
    * @param authenticator The authenticator.
    */
   public PermissionAuthenticator(final Authenticator authenticator) {
      this.authenticator = authenticator;
   }

   /**
    * Gets permissions.
    * @param username The authenticated username.
    * @param context The supplied context.
    * @return The permission.
    */
   protected abstract Set<Permission> authenticatedPermission(final String username, final String context);

   /**
    * Gets the permissions for unauthenticated requests. Override to return
    * something other than {@code NONE}.
    * @param context The context.
    * @return The set of permissions ({@code NONE} by default).
    */
   protected Set<Permission> unauthenticatedPermission(final String context) {
      return Permission.NONE;
   }

   /**
    * Check for an authorized user and return permission.
    * @param request The request.
    * @param context The permission context.
    * @return The set of permissions or an empty set if none.
    */
   public Set<Permission> permission(final HttpServletRequest request, final String context) {
      String username = authenticator.authorizedUsername(request);
      return Strings.isNullOrEmpty(username) ? unauthenticatedPermission(context) :
              authenticatedPermission(username, context);
   }

   /**
    * The authenticator.
    */
   private final Authenticator authenticator;
}
