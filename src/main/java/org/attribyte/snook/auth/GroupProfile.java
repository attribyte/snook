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

import com.google.common.base.MoreObjects;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;

import java.lang.reflect.Type;
import java.util.Map;
import java.util.Set;

/**
 * Immutable group permissions for a user.
 */
public class GroupProfile {

   /**
    * The name of the global group ({@value}).
    */
   public static final String GLOBAL_GROUP_NAME = "*";

   /**
    * Creates an enabled group permission.
    * @param username The username.
    * @param groupName The group name.
    * @param permissions The set of permissions.
    * @param properties The optional properties.
    */
   public GroupProfile(final String username,
                       final String groupName,
                       final Set<Permission> permissions,
                       final Map<String, String> properties) {
      this(username, groupName, permissions, true, System.currentTimeMillis(), properties);
   }

   /**
    * Creates a group permission.
    * @param username The username.
    * @param groupName The group name.
    * @param permissions The permissions.
    * @param enabled Is the permission enabled?
    * @param lastUpdateTimestamp The time when the permission was created or last updated.
    * @param properties The optional properties.
    */
   public GroupProfile(final String username,
                       final String groupName,
                       final Set<Permission> permissions,
                       final boolean enabled,
                       final long lastUpdateTimestamp,
                       final Map<String, String> properties) {
      this.username = Strings.nullToEmpty(username);
      this.groupName = Strings.nullToEmpty(groupName);
      this.enabled = enabled;
      this.permissions = permissions != null ? ImmutableSet.copyOf(permissions) : ImmutableSet.of();
      this.lastUpdateTimestamp = lastUpdateTimestamp;
      this.properties = properties != null ? ImmutableMap.copyOf(properties) : ImmutableMap.of();
   }

   /**
    * Disable this permission.
    * @return This permission, disabled.
    */
   public GroupProfile disable() {
      return new GroupProfile(username, groupName, permissions, false, lastUpdateTimestamp, properties);
   }

   /**
    * Change access permission.
    * @param permissions The new access permissions.
    * @return This group permission with access permission changed.
    */
   public GroupProfile withPermission(final Set<Permission> permissions) {
      return new GroupProfile(username, groupName, permissions, enabled, lastUpdateTimestamp, properties);
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("username", username)
              .add("groupName", groupName)
              .add("enabled", enabled)
              .add("permissions", permissions)
              .add("lastUpdateTimestamp", lastUpdateTimestamp)
              .add("properties", properties)
              .toString();
   }

   /**
    * @return Does the user have read permission?
    */
   public boolean hasReadPermission() {
      return permissions.contains(Permission.READ);
   }

   /**
    * @return Does the user have global read permissions?
    */
   public boolean hasGlobalReadPermission() {
      return hasReadPermission() && groupName.equals(GLOBAL_GROUP_NAME);
   }

   /**
    * @return Does the user have write permission?
    */
   public boolean hasWritePermission() {
      return permissions.contains(Permission.UPDATE);
   }

   /**
    * @return Does the user have global write permissions?
    */
   public boolean hasGlobalWritePermission() {
      return hasWritePermission() && groupName.equals(GLOBAL_GROUP_NAME);
   }

   /**
    * @return Does the user have write permission?
    */
   public boolean hasAdminPermission() {
      return permissions.contains(Permission.SUPER);
   }

   /**
    * @return Does the user have global admin permissions?
    */
   public boolean hasGlobalAdminPermission() {
      return hasAdminPermission() && groupName.equals(GLOBAL_GROUP_NAME);
   }

   /**
    * @return Is this the default (empty) group?
    */
   public boolean isDefault() {
      return groupName.isEmpty();
   }

   /**
    * @return The display name for the group.
    */
   public String getDisplayName() {
      return isDefault() ? "Default" : groupName;
   }

   /**
    * The username.
    */
   public final String username;

   /**
    * The group name.
    */
   public final String groupName;

   /**
    * Is the permission enabled?
    */
   public final boolean enabled;

   /**
    * The permission.
    */
   public final ImmutableSet<Permission> permissions;

   /**
    * The last time the permission was updated.
    */
   public final long lastUpdateTimestamp;

   /**
    * Additional properties associated with the user,group.
    */
   public final ImmutableMap<String, String> properties;
}
