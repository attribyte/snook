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

import com.google.common.base.Charsets;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.io.CharStreams;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * User groups with permission-per-user.
 * <pre>{@code
 * #Comments like this an empty lines are ignored
 * #[username]:[group name]:[permission]
 *
 * #A read only user in the 'global' group
 * user0:*:r
 *
 * #An admin in 'group0'.
 * user1:group0:admin
 *
 * #A read-write user in 'group1'.
 * user1:group1:rw
 *
 * #A user with create, read, update, delete in 'group1'.
 * user2:group1:crud
 * }</pre>
 */
public class Groups {

   /**
    * Create groups from a group file.
    * @param file The group file.
    * @throws IOException on read exception.
    */
   public Groups(final File file) throws IOException {
      this(parse(Files.readAllLines(file.toPath())));
   }

   /**
    * Create groups from an input stream (in the group file format).
    * @param is The input stream.
    * @throws IOException on read exception.
    */
   public Groups(final InputStream is) throws IOException {
      this(parse(CharStreams.readLines(new InputStreamReader(is, Charsets.UTF_8))));
   }

   /**
    * Creates the groups from a collection of permissions.
    * @param permissions The permissions.
    */
   public Groups(final Collection<GroupPermission> permissions) {
      this.permissions = Maps.newHashMap();
      for(GroupPermission permission : permissions) {
         Map<String, GroupPermission> userPermissions =
                 this.permissions.computeIfAbsent(permission.groupName, k -> Maps.newHashMap());
         userPermissions.put(permission.username, permission);
      }
   }

   /**
    * Gets permission for a user in a group.
    * @param groupName The group name.
    * @param username The username.
    * @return The permissions or empty permissions if none.
    */
   public GroupPermission permission(final String groupName, final String username) {
      Map<String, GroupPermission> userPermissions = permissions.get(groupName);
      return userPermissions != null ? userPermissions.get(username) :
              new GroupPermission(username, groupName, ImmutableSet.of());
   }

   /**
    * Determine if a user is in a group.
    * @param groupName The group name.
    * @param username The user name.
    * @return Is the user in the group?
    */
   public boolean inGroup(final String groupName, final String username) {
      Map<String, GroupPermission> userPermissions = permissions.get(groupName);
      return userPermissions != null && userPermissions.containsKey(username);
   }

   /**
    * Gets an immutable map of permission vs user for a group.
    * @param groupName The group name.
    * @return The map of permissions or an empty map if none.
    */
   public ImmutableMap<String, GroupPermission> permission(final String groupName) {
      Map<String, GroupPermission> userPermissions = permissions.get(groupName);
      return userPermissions != null ? ImmutableMap.copyOf(userPermissions) : ImmutableMap.of();
   }

   /**
    * Gets an immutable set of all group names.
    * @return The set of groups.
    */
   public ImmutableSet<String> groups() {
      return ImmutableSet.copyOf(permissions.keySet());
   }

   /**
    * Parse lines from a groups file.
    * @param lines The lines.
    * @return The list of permissions.
    */
   static List<GroupPermission> parse(final List<String> lines) {
      Splitter lineSplitter = Splitter.on(":").trimResults().limit(4);
      List<GroupPermission> groups = Lists.newArrayListWithExpectedSize(256);
      for(String line : lines) {
         line = line.trim();
         if(line.isEmpty() || line.startsWith("#")) {
            continue;
         }
         GroupPermission groupPermission = groupPermissionFromComponents(lineSplitter.splitToList(line));
         if(groupPermission != null) {
            groups.add(groupPermission);
         }
      }

      return groups;
   }

   /**
    * Creates group permission from a line in the form of: username:groupName:[rw | r | admin | none]
    * @return The group permission or {@code null} if invalid.
    */
   static GroupPermission groupPermissionFromComponents(final List<String> components) {
      if(components.size() > 1) {
         String username = components.get(0);
         String groupName = components.get(1);
         Set<Permission> permissions = Permission.NONE;
         if(components.size() > 2) {
            permissions = Permission.setFromString(components.get(2));
         }
         return new GroupPermission(username, groupName, permissions);
      } else {
         return null;
      }
   }

   /**
    * A map of permissions for each user in a group.
    */
   private final Map<String, Map<String, GroupPermission>> permissions;
}
