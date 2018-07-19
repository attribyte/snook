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

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

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