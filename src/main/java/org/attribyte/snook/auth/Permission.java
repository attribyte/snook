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
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

import java.util.Optional;
import java.util.Set;

/**
 * A CRUD permission.
 */
public enum Permission {

   /**
    * Permission to create.
    */
   CREATE,

   /**
    * Permission to read.
    */
   READ,

   /**
    * Permission to update.
    */
   UPDATE,

   /**
    * Permission to delete.
    */
   DELETE;

   /**
    * Converts a string to a permission.
    * @param str The string.
    * @return The permission or {@code empty} if unknown.
    */
   public static Optional<Permission> fromString(final String str) {
      switch(Strings.nullToEmpty(str).toLowerCase()) {
         case "create":
            return Optional.of(CREATE);
         case "read":
            return Optional.of(READ);
         case "update":
            return Optional.of(UPDATE);
         case "delete":
            return Optional.of(DELETE);
         default:
            return Optional.empty();
      }
   }


   /**
    * Create a set of permissions from a string.
    * For example: r, rw, w, cud, crud, etc.
    * @param str The string.
    * @return The set of permissions.
    */
   public static Set<Permission> setFromString(String str) {
      if(Strings.isNullOrEmpty(str)) {
         return NONE;
      }

      switch(str.toLowerCase().trim()) {
         case "r":
            return READ_ONLY;
         case "rw":
         case "wr":
            return READ_WRITE;
         case "w":
            return WRITE_ONLY;
      }

      Set<Permission> permissions = Sets.newHashSetWithExpectedSize(4);
      for(char ch : str.toCharArray()) {
         switch(ch) {
            case 'c':
               permissions.add(CREATE);
               break;
            case 'r':
               permissions.add(READ);
               break;
            case 'u':
               permissions.add(UPDATE);
               break;
            case 'd':
               permissions.add(DELETE);
         }
      }

      return permissions;
   }

   /**
    * No permissions.
    */
   public static final ImmutableSet<Permission> NONE = ImmutableSet.of();

   /**
    * Read-only permission.
    */
   public static final ImmutableSet<Permission> READ_ONLY = Sets.immutableEnumSet(READ);

   /**
    * Write-only permission.
    */
   public static final ImmutableSet<Permission> WRITE_ONLY = Sets.immutableEnumSet(CREATE, UPDATE, DELETE);

   /**
    * Read-write permission.
    */
   public static final ImmutableSet<Permission> READ_WRITE = Sets.immutableEnumSet(CREATE, READ, UPDATE, DELETE);
}
