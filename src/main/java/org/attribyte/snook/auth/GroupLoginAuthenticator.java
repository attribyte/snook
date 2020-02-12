/*
 * Copyright 2020 Attribyte, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 *
 */

package org.attribyte.snook.auth;

import com.google.common.collect.ImmutableSet;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * A login authenticator that returns groups/permissions for a user.
 */
public abstract class GroupLoginAuthenticator extends PermissionAuthenticator implements LoginAuthenticator {

   /**
    * Creates a group login authenticator.
    * @param authenticator The
    */
   public GroupLoginAuthenticator(final LoginAuthenticator authenticator) {
      super(authenticator);
      this.loginAuthenticator = authenticator;
   }

   @Override
   public String credentials(final HttpServletRequest request) {
      return loginAuthenticator.credentials(request);
   }

   @Override
   public String authorizedUsername(final HttpServletRequest request) {
      return loginAuthenticator.authorizedUsername((request));
   }

   @Override
   public String schemeName() {
      return loginAuthenticator.schemeName();
   }

   @Override
   public boolean doLogin(final String username, final String password,
                          final int tokenLifetimeSeconds,
                          final HttpServletResponse resp) throws IOException {
      return loginAuthenticator.doLogin(username, password, tokenLifetimeSeconds, resp);
   }

   @Override
   protected Set<Permission> authenticatedPermission(final String username, final String context) {
      GroupProfile matchProfile = findGroup(context, groupsForUser(username));
      return matchProfile != null ? matchProfile.permissions : ImmutableSet.of();
   }

   /**
    * Perform login with a username and password.
    * @param username The username.
    * @param password The password.
    * @param tokenLifetimeSeconds The token lifetime.
    * @param resp The HTTP response.
    * @return The list of groups for the user or {@code null} if login was invalid.
    * @throws IOException on read/write error.
    */
   public List<GroupProfile> login(final String username, final String password,
                                   final int tokenLifetimeSeconds,
                                   final HttpServletResponse resp) throws IOException {
      if(loginAuthenticator.doLogin(username, password, tokenLifetimeSeconds, resp)) {
         return groupsForUser(username);
      } else {
         return LOGIN_FAILED_GROUPS;
      }
   }

   /**
    * Perform login with a username and password for a specific group.
    * @param groupName The group name.
    * @param username The username.
    * @param password The password.
    * @param tokenLifetimeSeconds The token lifetime.
    * @param resp The HTTP response.
    * @return The matching group profile or {@code null} if login failed.
    * @throws IOException on read/write error.
    */
   public GroupProfile login(final String groupName, final String username, final String password,
                             final int tokenLifetimeSeconds,
                             final HttpServletResponse resp) throws IOException {
      return findGroup(groupName, login(username, password, tokenLifetimeSeconds, resp));
   }

   /**
    * Check for an authorized user and return permission.
    * @param request The request.
    * @return A custom object if authenticated or {@code null} if not.
    */
   public List<GroupProfile> authenticate(final HttpServletRequest request) {
      String username = loginAuthenticator.authorizedUsername(request);
      return username != null ? groupsForUser(username) : null;
   }

   /**
    * Authenticate for a specific group.
    * @param request The request.
    * @param groupName The group name.
    * @return The group profile or {@code null} if authentication failed.
    */
   public GroupProfile authenticate(final HttpServletRequest request, final String groupName) {
      return findGroup(groupName, authenticate(request));
   }

   /**
    * Finds a matching group profile.
    * @param groupName The group name.
    * @param profiles A collection of profiles.
    * @return The matching profile or {@code null}.
    */
   protected GroupProfile findGroup(final String groupName, final Collection<GroupProfile> profiles) {
      if(groupName == null || profiles == null || profiles.isEmpty()) {
         return null;
      }

      for(GroupProfile profile : profiles) { //Users are going to be members of just a few groups.
         if(profile.groupName.equalsIgnoreCase(groupName) && profile.enabled) {
            return profile;
         }
      }

      return null;
   }


   /**
    * Gets group membership for an authenticated user.
    * @param username The uesrname.
    * @return The list of group profiles.
    */
   public abstract List<GroupProfile> groupsForUser(final String username);

   /**
    * The list of group profiles returned on failed login.
    */
   public static final List<GroupProfile> LOGIN_FAILED_GROUPS = null;

   /**
    * The request authenticator.
    */
   protected final LoginAuthenticator loginAuthenticator;
}
