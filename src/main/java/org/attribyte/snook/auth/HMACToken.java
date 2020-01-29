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

package org.attribyte.snook.auth;

import com.google.common.base.CharMatcher;
import com.google.common.base.Charsets;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.CharStreams;
import com.google.common.primitives.Ints;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.attribyte.util.StringUtil.randomString;

public class HMACToken {

   public static void main(String[] args) throws Exception {
      HMACToken tok = new HMACToken("testing", 1, TimeUnit.DAYS);
      System.out.println(tok.toString());
      byte[] hmacKey = new byte[32];
      new SecureRandom().nextBytes(hmacKey);
      HashFunction hmacFunction = Hashing.hmacSha256(hmacKey);
      String keyId = randomKeyId();
      System.out.println("key id is " + keyId);
      String cookieValue = tok.toCookieValue(keyId, hmacFunction);
      System.out.println(cookieValue);
      HMACToken validate = validate(cookieValue , s -> hmacFunction);
      System.out.println("validated " + validate);
   }

   /**
    * Generates a key file.
    * @param outputFile The output file.
    * @param size The number of keys.
    * @throws IOException on write error.
    */
   public static void generateKeys(final File outputFile, final int size) throws IOException {
      if(outputFile.exists()) {
         throw new IOException(String.format("The output file, '%s', exists", outputFile.getAbsolutePath()));
      }

      SecureRandom rnd = new SecureRandom();
      try(PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
         for(int i = 0; i < size; i++) {
            String id = randomKeyId();
            byte[] hmacKey = new byte[32];
            rnd.nextBytes(hmacKey);
            writer.println(id + BASE_64_ENCODING.encode(hmacKey));
         }
      }
   }

   /**
    * Generate a map of random keys.
    * @param size The size of the keys.
    * @return The map of bas64 encoded key vs id.
    */
   public static Map<String, String> generateKeys(final int size) {
      Map<String, String> keyMap = Maps.newHashMapWithExpectedSize(size);
      SecureRandom rnd = new SecureRandom();
      for(int i = 0; i < size; i++) {
         String id = randomKeyId();
         byte[] hmacKey = new byte[32];
         rnd.nextBytes(hmacKey);
         keyMap.put(id, BASE_64_ENCODING.encode(hmacKey));
      }
      return keyMap;
   }

   /**
    * Loads a previously generated key file.
    * @param inputFile The input file.
    * @return The map of HMAC function vs key id.
    * @throws IOException on read error or invalid file.
    */
   public static Map<String, HashFunction> loadFunctionMap(final File inputFile) throws IOException {
      return loadFunctionMap(Files.readAllLines(inputFile.toPath()));
   }

   /**
    * Loads from an input stream.
    * @param is The input stream.
    * @return The map of HMAC function vs key id.
    * @throws IOException on read error or invalid file.
    */
   public static Map<String, HashFunction> loadFunctionMap(final InputStream is) throws IOException {
      return loadFunctionMap(CharStreams.readLines(new InputStreamReader(is, Charsets.UTF_8)));
   }

   /**
    * Loads the set of ids from an input stream.
    * @param is The input stream.
    * @return The set of key ids.
    * @throws IOException on read error or invalid file.
    */
   public static Set<String> loadIds(final InputStream is) throws IOException {
      return loadIds(CharStreams.readLines(new InputStreamReader(is, Charsets.UTF_8)));
   }


   /**
    * Loads the set of ids from an input file.
    * @param inputFile The input file.
    * @return The set of ids.
    * @throws IOException on read error or invalid file.
    */
   public static Set<String> loadIds(final File inputFile) throws IOException {
      return loadIds(Files.readAllLines(inputFile.toPath()));
   }

   /**
    * Loads from a list of lines.
    * @return The map of HMAC function vs key id.
    * @throws IOException on read error or invalid file.
    */
   public static Map<String, HashFunction> loadFunctionMap(final List<String> lines) throws IOException {
      Map<String, HashFunction> functions = Maps.newHashMap();
      int count = 0;
      for(String line : lines) {
         count++;
         line = line.trim();
         if(line.isEmpty() || line.startsWith("#")) {
            continue;
         }

         if(line.length() < PREFIX_SIZE) {
            throw new IOException(String.format("Invalid key file at line, %d", count));
         }

         try {
            String id = line.substring(0, KEY_ID_SIZE);
            byte[] hmacKey = BASE_64_ENCODING.decode(line.substring(KEY_ID_SIZE));
            functions.put(id, Hashing.hmacSha256(hmacKey));
         } catch(IllegalArgumentException ie) {
            throw new IOException(String.format("Invalid key file at line, %d", count));
         }
      }
      return functions;
   }

   /**
    * Loads the set of available ids.
    * @param lines The lines.
    * @return The set of keys.
    * @throws IOException on invalid line.
    */
   public static Set<String> loadIds(final List<String> lines) throws IOException {
      Set<String> ids = Sets.newHashSetWithExpectedSize(lines.size());
      int count = 0;
      for(String line : lines) {
         count++;
         line = line.trim();
         if(line.isEmpty() || line.startsWith("#")) {
            continue;
         }

         if(line.length() < PREFIX_SIZE) {
            throw new IOException(String.format("Invalid key file at line, %d", count));
         }

         ids.add(line.substring(0, KEY_ID_SIZE));
      }
      return ids;
   }

   /**
    * Validate a cookie value and create a token only if valid.
    * @param cookieValue The cookie value.
    * @param hmacFunctions A function that returns a (keyed) HMAC function for a key id.
    * @return The token or {@code null} if invalid.
    */
   public static HMACToken validate(final String cookieValue, final Function<String, HashFunction> hmacFunctions) {

      if(cookieValue.length() < PREFIX_SIZE) {
         return null;
      }

      String keyId = cookieValue.substring(0, KEY_ID_SIZE);
      HashFunction hmacFunction = hmacFunctions.apply(keyId);
      if(hmacFunction == null) {
         return null;
      }

      HashCode sentCode = HashCode.fromBytes(BASE_64_ENCODING.decode(cookieValue.substring(KEY_ID_SIZE, PREFIX_SIZE)));
      String tokenValue = cookieValue.substring(PREFIX_SIZE);

      HashCode expectedCode = hmacFunction.newHasher()
              .putString(keyId, Charsets.UTF_8)
              .putString(tokenValue, Charsets.UTF_8)
              .hash();

      if(!sentCode.equals(expectedCode)) {
         return null;
      }

      Iterator<String> iter = tokenSplitter.split(tokenValue).iterator();
      if(!iter.hasNext()) {
         return null;
      }

      Integer expireTimestamp = Ints.tryParse(iter.next());
      if(expireTimestamp == null) {
         return null;
      }

      if(!iter.hasNext()) {
         return null;
      }

      return new HMACToken(iter.next(), expireTimestamp);
   }

   /**
    * Creates a token with a lifetime.
    * @param username The username.
    * @param lifetime The lifetime.
    * @param lifetimeUnits The lifetime units.
    */
   public HMACToken(final String username,
                    final int lifetime,
                    final TimeUnit lifetimeUnits) {

      if(username == null) {
         throw new UnsupportedOperationException("The 'username' must not be null");
      }

      if(CharMatcher.whitespace().matchesAllOf(username)) {
         throw new UnsupportedOperationException("The 'username' must not be non-empty");
      }

      if(lifetime < 1) {
         throw new UnsupportedOperationException("The 'lifetime' must be > 0");
      }

      this.username = username;
      int lifeSeconds = (int)(TimeUnit.SECONDS.convert(lifetime, lifetimeUnits));
      this.expireTimestampSeconds = (int)(System.currentTimeMillis()/1000L) + lifeSeconds;
   }

   /**
    * Creates a token with an expire time in seconds.
    * @param username The username.
    * @param expireTimestampSeconds The expire time in seconds.
    */
   HMACToken(final String username,
             final int expireTimestampSeconds) {
      this.username = username;
      this.expireTimestampSeconds = expireTimestampSeconds;
   }

   /**
    * Generate the cookie value for this token.
    * @param keyId The key id associated with the HMAC function.
    * @param hmacFunction The HMAC function.
    * @return The cookie value.
    */
   public String toCookieValue(final String keyId, final HashFunction hmacFunction) {
      if(Strings.nullToEmpty(keyId).length() != KEY_ID_SIZE) {
         throw new UnsupportedOperationException(String.format("The 'keyId' must be exactly %d characters", KEY_ID_SIZE));
      }

      String tokenValue = expireTimestampSeconds + "," + username;
      HashCode hmac = hmacFunction.newHasher()
              .putString(keyId, Charsets.UTF_8)
              .putString(tokenValue, Charsets.UTF_8)
              .hash();

      return keyId + BASE_64_ENCODING.encode(hmac.asBytes()) + tokenValue;
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("username", username)
              .add("expireTimestampSeconds", expireTimestampSeconds)
              .add("expires", new Date(expireTimestampSeconds * 1000L))
              .toString();
   }

   @Override
   public boolean equals(final Object o) {
      if(this == o) return true;
      if(o == null || getClass() != o.getClass()) return false;
      final HMACToken hmacToken = (HMACToken)o;
      return expireTimestampSeconds == hmacToken.expireTimestampSeconds &&
              Objects.equal(username, hmacToken.username);
   }

   @Override
   public int hashCode() {
      return Objects.hashCode(username, expireTimestampSeconds);
   }

   /**
    * The username.
    */
   public final String username;

   /**
    * The expiration timestamp.
    */
   public final int expireTimestampSeconds;

   /**
    * @return Is this token expired?
    */
   public final boolean isExpired() {
      return (expireTimestampSeconds * 1000L) < System.currentTimeMillis();
   }

   /**
    * Generates a random key id.
    * @return The random key id.
    */
   public static String randomKeyId() {
      return randomString(KEY_ID_SIZE);
   }

   /**
    * The encoding to encode/decode the HMAC.
    */
   private static final BaseEncoding BASE_64_ENCODING = BaseEncoding.base64().omitPadding();

   /**
    * The size (in characters) of the encoded HMAC ({@value}).
    */
   private static final int ENCODED_HMAC_SIZE = 43;

   /**
    * The size (in characters) of the key id ({@value}).
    */
   private static final int KEY_ID_SIZE = 8;

   /**
    * The total size of the prefix (key id | mac) {(@value}).
    */
   private static final int PREFIX_SIZE = KEY_ID_SIZE + ENCODED_HMAC_SIZE;

   /**
    * The token splitter.
    */
   private static Splitter tokenSplitter = Splitter.on(',').limit(2);
}
