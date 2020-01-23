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
    * Permission to do anything.
    */
   SUPER("super"),

   /**
    * Permission to create.
    */
   CREATE("c"),

   /**
    * Permission to read.
    */
   READ("r"),

   /**
    * Permission to update.
    */
   UPDATE("u"),

   /**
    * Permission to delete.
    */
   DELETE("d");

   Permission(final String code) {
      this.code = code;
   }

   /**
    * Converts a string to a permission.
    * @param str The string.
    * @return The permission or {@code empty} if unknown.
    */
   public static Optional<Permission> fromString(final String str) {
      switch(Strings.nullToEmpty(str).toLowerCase()) {
         case "create":
         case "c":
            return Optional.of(CREATE);
         case "read":
         case "r":
            return Optional.of(READ);
         case "update":
         case "u":
            return Optional.of(UPDATE);
         case "delete":
         case "d":
            return Optional.of(DELETE);
         case "super":
         case "admin":
            return Optional.of(SUPER);
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
         case "admin":
         case "super":
            return ADMIN;
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
    * Convert a set of permissions to the compact string.
    * @param permissions The set of permissions.
    * @return The compact string.
    */
   public static String setToString(final Set<Permission> permissions) {
      if(permissions.contains(SUPER)) {
         return "super";
      } else if(permissions.size() == 1 && permissions.contains(READ)) {
         return "r";
      } else if(permissions.size() == READ_WRITE.size()) {
         return "rw";
      } else if(permissions.size() == WRITE_ONLY.size() && !permissions.contains(READ)) {
         return "w";
      } else {
         StringBuilder buf = new StringBuilder();
         permissions.forEach(p -> {
            buf.append(p.code);
         });
         return buf.toString();
      }
   }

   /**
    * The internal code.
    */
   final String code;

   /**
    * No permissions.
    */
   public static final ImmutableSet<Permission> NONE = ImmutableSet.of();

   /**
    * Superuser/admin permission.
    */
   public static final ImmutableSet<Permission> ADMIN = Sets.immutableEnumSet(SUPER, READ, CREATE, UPDATE, DELETE);

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
