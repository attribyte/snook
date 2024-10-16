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
import com.google.common.io.Files;
import com.google.common.primitives.Ints;
import org.attribyte.util.InitUtil;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import static org.attribyte.util.StringUtil.randomString;

/**
 * Generates HMAC keys and perform verification.
 */
public class HMACToken {

   /**
    * Generates random HMAC keys.
    * {@code Usage: HMACToken -size=[number of hashes] [output file]}
    * <p>
    *    Generates the key file, a signature key file {@code [name].sig.key} (if not present),
    *    a signature file {@code [name].sig} and a file containing just the ids {@code [name].ids}, one per line.
    *    Fails if any files exist other than the signature key file.
    * </p>
    * @param args The arguments.
    * @throws Exception on error.
    */
   public static void main(String[] args) throws Exception {

      Properties props = new Properties();
      args = InitUtil.fromCommandLine(args, props);

      if(args.length < 1) {
         System.err.println("Usage: HMACToken -size=[number of hashes] [output file]");
         System.exit(1);
      }

      File outputFile = new File(args[0]);
      if(outputFile.exists()) {
         System.err.printf("The output file, '%s' exists!%n", outputFile.getAbsolutePath());
         System.exit(1);
      }

      File keyFile = new File(args[0] + ".sig.key");
      final File generatedKeyFile;
      final byte[] sigKey;
      if(keyFile.exists()) {
         sigKey = Files.toByteArray(keyFile);
         if(sigKey.length != KEY_SIZE) {
            System.err.printf("The key file, '%s' is invalid%n", keyFile.getAbsolutePath());
            System.exit(1);
         } else {
            System.out.printf("Using existing key file, '%s'%n", keyFile.getAbsolutePath());
         }
         generatedKeyFile = null;
      } else {
         sigKey = randomKey(new SecureRandom());
         System.out.printf("Writing key file, '%s'...%n", keyFile.getAbsolutePath());
         Files.write(sigKey, keyFile);
         generatedKeyFile = keyFile;
      }

      File sigFile = new File(args[0] + ".sig");
      if(sigFile.exists()) {
         System.err.printf("The signature file, '%s' exists!%n", sigFile.getAbsolutePath());
         System.exit(1);
      }

      File idsFile = new File(args[0] + ".ids");
      if(idsFile.exists()) {
         System.err.printf("The ids file, '%s' exists!%n", idsFile.getAbsolutePath());
         System.exit(1);
      }

      Integer size = Ints.tryParse(props.getProperty("size", "4096"));
      if(size == null || size < 1) {
         System.err.println("The 'size' must be > 0");
         System.exit(1);
      }

      System.out.printf("Generating and writing '%s' with %d keys...%n", outputFile.getAbsolutePath(), size);

      try {
         generateKeys(outputFile, size);
         HashCode hashCode = hashKeysFile(outputFile, sigKey);
         System.out.printf("Writing signature file, '%s'...%n", sigFile.getAbsolutePath());
         Files.write(hashCode.asBytes(), sigFile);
         System.out.println("Checking signature...");
         if(!checkSigFile(sigFile, outputFile, sigKey)) {
            System.err.println("Invalid signature!");
            deleteFiles(outputFile, sigFile, idsFile, generatedKeyFile);
            System.exit(1);
         }

         System.out.printf("Writing ids file, '%s'...%n", idsFile.getAbsolutePath());
         try(PrintWriter writer = new PrintWriter(new FileWriter(idsFile))) {
            for(String id : loadIds(outputFile)) {
               writer.println(id);
            }
         }

      } catch(IOException ioe) {
         deleteFiles(outputFile, sigFile, idsFile, generatedKeyFile);
         throw ioe;
      }

      System.out.println("Done!");
   }

   /**
    * Delete a sequence of files, ignoring the return status.
    * @param files The files.
    */
   private static void deleteFiles(File...files) {
      for(File file : files) {
         if(file != null) {
            file.delete();
         }
      }
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
            writer.println(randomKeyId() + BASE_64_ENCODING.encode(randomKey(rnd)));
         }
      }
   }

   /**
    * Hash the keys file.
    * @param file The keys file.
    * @param key The signature key.
    * @return The hash code.
    * @throws IOException on read error.
    */
   public static HashCode hashKeysFile(final File file, final byte[] key) throws IOException {
      return Files.asByteSource(file).hash(Hashing.hmacSha256(key));
   }

   /**
    * Checks the hash of a keys file for changes.
    * @param hashCode The hash code.
    * @param file The file.
    * @param key The signature key.
    * @return Does the hash match?
    */
   public static boolean checkKeysFile(final HashCode hashCode, final File file,
                                       final byte[] key) throws IOException {
      return hashCode.equals(hashKeysFile(file, key));
   }

   /**
    * Checks the signature of a keys file.
    * @param sigFile A file containing the signature.
    * @param keysFile The keys file.
    * @param key The signature key.
    * @return Do the hashes match?
    */
   public static boolean checkSigFile(final File sigFile, final File keysFile,
                                      final byte[] key) throws IOException {
      if(!sigFile.exists() || !keysFile.exists()) {
         return false;
      }
      HashCode checkCode = HashCode.fromBytes(Files.toByteArray(sigFile));
      return checkKeysFile(checkCode, keysFile, key);
   }

   /**
    * Generate a map of random keys.
    * @param size The size of the keys.
    * @return The map of bas64 encoded key vs id.
    */
   public static Map<String, String> generateKeys(final int size) {
      Map<String, String> keyMap = Maps.newLinkedHashMapWithExpectedSize(size);
      SecureRandom rnd = new SecureRandom();
      for(int i = 0; i < size; i++) {
         keyMap.put(randomKeyId(), BASE_64_ENCODING.encode(randomKey(rnd)));
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
      return loadFunctionMap(Files.readLines(inputFile, Charsets.US_ASCII));
   }

   /**
    * Loads from an input stream.
    * @param is The input stream.
    * @return The map of HMAC function vs key id.
    * @throws IOException on read error or invalid file.
    */
   public static Map<String, HashFunction> loadFunctionMap(final InputStream is) throws IOException {
      return loadFunctionMap(CharStreams.readLines(new InputStreamReader(is, Charsets.US_ASCII)));
   }

   /**
    * Loads the set of ids from an input stream.
    * @param is The input stream.
    * @return The set of key ids.
    * @throws IOException on read error or invalid file.
    */
   public static Set<String> loadIds(final InputStream is) throws IOException {
      return loadIds(CharStreams.readLines(new InputStreamReader(is, Charsets.US_ASCII)));
   }


   /**
    * Loads the set of ids from an input file.
    * @param inputFile The input file.
    * @return The set of ids.
    * @throws IOException on read error or invalid file.
    */
   public static Set<String> loadIds(final File inputFile) throws IOException {
      return loadIds(Files.readLines(inputFile, Charsets.US_ASCII));
   }

   /**
    * Loads from a list of lines.
    * @return The map of HMAC function vs key id.
    * @throws IOException on read error or invalid file.
    */
   public static Map<String, HashFunction> loadFunctionMap(final List<String> lines) throws IOException {
      Map<String, HashFunction> functions = Maps.newLinkedHashMap();
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
      Set<String> ids = Sets.newLinkedHashSetWithExpectedSize(lines.size());
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

      if(cookieValue == null || cookieValue.length() < PREFIX_SIZE) {
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
    * Generate a random HMAC key.
    * @param rnd The secure random.
    * @return The key.
    */
   public static byte[] randomKey(final SecureRandom rnd) {
      byte[] hmacKey = new byte[KEY_SIZE];
      rnd.nextBytes(hmacKey);
      return hmacKey;
   }

   /**
    * The size in bytes of generated random keys.
    */
   private static final int KEY_SIZE = 32;

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
   private static final Splitter tokenSplitter = Splitter.on(',').limit(2);
}
