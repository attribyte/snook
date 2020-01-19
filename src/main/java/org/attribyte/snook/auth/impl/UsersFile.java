/*
 * Copyright 2020 Attribyte, LLC
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

package org.attribyte.snook.auth.impl;

import com.google.common.base.Charsets;
import com.google.common.base.MoreObjects;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.common.hash.HashCode;
import org.attribyte.snook.auth.AuthenticationToken;
import org.attribyte.snook.auth.Authenticator;
import org.mindrot.jbcrypt.BCrypt;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import static com.google.common.base.Strings.nullToEmpty;
import static org.attribyte.util.StringUtil.randomString;
import static com.google.common.base.Strings.isNullOrEmpty;

public class UsersFile {

   public UsersFile(final File file, final boolean preserveFormatting) throws IOException {
      this(parse(Files.readAllLines(file.toPath()), preserveFormatting));
   }

   private UsersFile(final List<Record> records) {
      ImmutableMap.Builder<String, HashCode> bcryptHashes = ImmutableMap.builder();
      ImmutableMap.Builder<String, HashCode> sha256Hashes = ImmutableMap.builder();
      ImmutableMap.Builder<HashCode, String> userForHash = ImmutableMap.builder();
      records.forEach(record -> {
         userForHash.put(record.hashCode, record.username);
         if(record.hashType == HashType.BCRYPT) {
            bcryptHashes.put(record.username, record.hashCode);
         } else {
            sha256Hashes.put(record.username, record.hashCode);
         }
      });
      this.bcryptHashes = bcryptHashes.build();
      this.sha256Hashes = sha256Hashes.build();
      this.userForHash = userForHash.build();
   }

   /**
    * The hash type for password/tokens.
    */
   public enum HashType {

      /**
       * Hash for user-selected passwords.
       */
      BCRYPT,

      /**
       * Hash for randomly generated tokens.
       */
      SHA256,

      /**
       * No hash.
       */
      NONE

   }

   /**
    * A record in the file.
    */
   public static class Record {

      public Record(final String username,
                    final HashType hashType,
                    final HashCode hashCode) {
         this(username, hashType, hashCode, null);
      }


      public Record(final String value) {
         this(null, HashType.NONE, null, value);
      }

      public Record(final String username,
                    final HashType hashType,
                    final HashCode hashCode,
                    final String value) {
         this.username = username;
         this.hashType = hashType;
         this.hashCode = hashCode;
         this.value = value;
      }

      /**
       * Clears the value of a record.
       * @return The record with value cleared.
       */
      public Record clearValue() {
         return isNullOrEmpty(value) ? this : new Record(username, hashType, hashCode, null);
      }

      /**
       * The username.
       */
      public final String username;

      /**
       * The hash type.
       */
      public final HashType hashType;

      /**
       * The hash code.
       */
      public final HashCode hashCode;

      /**
       * The hashed value, if available.
       */
      public final String value;

      @Override
      public String toString() {
         return MoreObjects.toStringHelper(this)
                 .add("username", username)
                 .add("hashType", hashType)
                 .add("hashCode", hashCode)
                 .add("value", value)
                 .toString();
      }

      public String toLine() {
         if(hashType == HashType.NONE) {
            return nullToEmpty(value);
         }

         StringBuilder buf = new StringBuilder(username);
         buf.append(":");
         if(hashType == HashType.SHA256) {
            if(isNullOrEmpty(value)) {
               buf.append("$sha256$");
               buf.append(hashCode.toString());
            } else {
               buf.append("$token$");
               buf.append(nullToEmpty(value));
            }
         } else {
            if(isNullOrEmpty(value)) {
               buf.append(new String(hashCode.asBytes(), Charsets.US_ASCII));
            } else {
               buf.append("$password$").append(nullToEmpty(value));
            }
         }
         return buf.toString();
      }
   }

   /**
    * Transform a list of records to a list of secure records for output.
    * @param records The input records.
    * @return The secure records.
    */
   static List<Record> toSecure(final List<Record> records) {
      List<Record> secureRecords = Lists.newArrayListWithExpectedSize(records.size());
      records.forEach(record -> {
         switch(record.hashType) {
            case SHA256:
            case BCRYPT:
               secureRecords.add(record.clearValue());
         }
      });
      return secureRecords;
   }

   /**
    * Parse lines into a list of records.
    * @param lines The list of lines.
    * @param preserveFormatting Preserve formatting (empty lines, comments) as records.
    * @return The list of records.
    * @throws IOException on invalid record.
    */
   static List<Record> parse(final List<String> lines, final boolean preserveFormatting) throws IOException {
      List<Record> records = Lists.newArrayListWithExpectedSize(Math.min(lines.size(), 1024));
      Set<HashCode> hashes = Sets.newHashSetWithExpectedSize(records.size());
      int lineNumber = 0;
      for(String line : lines) {
         lineNumber++;
         line = line.trim();
         if(line.isEmpty() || line.startsWith("#")) {
            if(preserveFormatting) {
               records.add(new Record(line));
            }
            continue;
         }

         Iterator<String> iter = lineSplitter.split(line).iterator();
         String username = iter.next();
         if(!iter.hasNext()) {
            throw new IOException(String.format("Invalid record '%s' at line %d", line, lineNumber));
         }

         String hash = iter.next();
         final Record record;

         if(hash.startsWith("$2a")) {
            record = new Record(username, HashType.BCRYPT, HashCode.fromBytes(hash.getBytes(Charsets.US_ASCII)));
         } else if(hash.startsWith("$sha256$")) {
            String hashString = hash.substring(8);
            if(hashString.length() != 64) {
               throw new IOException(String.format("Hash is invalid for '%s' at line %d", hashString, lineNumber));
            }
            record = new Record(username, HashType.SHA256, HashCode.fromString(hashString));
         } else if(hash.startsWith("$token$")) {
            String token = hash.substring(7);
            if(token.isEmpty()) {
               token = AuthenticationToken.randomToken().toString();
            } else if(token.length() < MIN_TOKEN_LENGTH) {
               throw new IOException(String.format("Token is too short for '%s' at line %d", token, lineNumber));
            }
            record = new Record(username, HashType.SHA256, Authenticator.hashCredentials(token), token);
         } else if(hash.startsWith("$password$")) {
            String password = hash.substring(10);
            if(password.isEmpty()) {
               password = randomString(MIN_PASSWORD_LENGTH);
            } else if(password.length() < MIN_PASSWORD_LENGTH) {
               throw new IOException(String.format("Password is too short for '%s' at line %d", password, lineNumber));
            }
            record = new Record(username, HashType.BCRYPT,
                    HashCode.fromBytes(BCrypt.hashpw(password, BCrypt.gensalt(DEFAULT_BCRYPT_ROUNDS))
                            .getBytes(Charsets.US_ASCII)), password);
         } else {
            throw new IOException(String.format("Expecting '$2a', '$sha256$, '$token$' or '$password$' at line %d", lineNumber));
         }

         if(!hashes.contains(record.hashCode)) {
            hashes.add(record.hashCode);
            records.add(record);
         } else {
            throw new IOException(String.format("Duplicate hash at line %d", lineNumber));
         }
      }

      return records;
   }

   /**
    * An immutable map of BCrypt hash vs username.
    */
   public final ImmutableMap<String, HashCode> bcryptHashes;

   /**
    * An immutable map of sha256 hash vs username.
    */
   public final ImmutableMap<String, HashCode> sha256Hashes;

   /**
    * A map of username vs  hash.
    */
   public final ImmutableMap<HashCode, String> userForHash;

   /**
    * The default number of bcrypt rounds.
    */
   public static final int DEFAULT_BCRYPT_ROUNDS = 10;

   /**
    * The minimum password length.
    */
   public static final int MIN_PASSWORD_LENGTH = 12;

   /**
    * The minimum token length.
    */
   public static final int MIN_TOKEN_LENGTH = 16;

   /**
    * Splits lines for records.
    */
   private static final Splitter lineSplitter = Splitter.on(':').trimResults().omitEmptyStrings().limit(2);
}
