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

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.google.common.escape.Escaper;
import com.google.common.io.BaseEncoding;
import com.google.common.net.UrlEscapers;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;

public class TOTP {

   /**
    * The default number of characters in the key encoded for a URL ({@value}).
    */
   public static final int DEFAULT_CHARACTER_COUNT = 32;

   /**
    * The default number of bytes when a key is encoded with the default character count ({@value}).
    */
   public static final int DEFAULT_BYTE_COUNT = 20;

   /**
    * The default time stamp in seconds ({@value}).
    */
   public static final int DEFAULT_TIME_STEP_SECONDS = 30;

   /**
    * The default number of digits ({@value}).
    */
   public static final int DEFAULT_NUM_DIGITS = 6;

   /**
    * Creates an instance with defaults (30s, 6 digits).
    * @return The instance.
    */
   public static TOTP createDefault() {
      return new TOTP(DEFAULT_TIME_STEP_SECONDS, DEFAULT_NUM_DIGITS);
   }

   /**
    * Creates a six digit instance with a specified time step.
    * @param timeStepSeconds The time step in seconds.
    * @return The instance.
    */
   public static TOTP createSixDigit(int timeStepSeconds) {
      return new TOTP(timeStepSeconds, 6);
   }

   /**
    * Creates a eight digit instance with a specified time step.
    * @param timeStepSeconds The time step in seconds.
    * @return The instance.
    */
   public static TOTP createEightDigit(int timeStepSeconds) {
      return new TOTP(timeStepSeconds, 8);
   }

   /**
    * Creates a six digit instance with the default time step.
    * @return The instance.
    */
   public static TOTP createSixDigit() {
      return createSixDigit(DEFAULT_TIME_STEP_SECONDS);
   }

   /**
    * Creates a eight digit instance with the default time step.
    * @return The instance.
    */
   public static TOTP createEightDigit() {
      return createEightDigit(DEFAULT_TIME_STEP_SECONDS);
   }

   /**
    * Create an instance.
    * @param timeStepSeconds The time step in seconds.
    * @param passwordLength The (encoded) password length.
    */
   private TOTP(final int timeStepSeconds, final int passwordLength) {
      if(timeStepSeconds < 1) {
         throw new IllegalArgumentException("Time step must be positive");
      }

      this.timeStepSeconds = timeStepSeconds;

      totp = new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(timeStepSeconds), passwordLength);

      if(passwordLength == 8) {
         this.TOKEN_TEMPLATE = "%08d";
      } else {
         this.TOKEN_TEMPLATE = "%06d";
      }
   }

   /**
    * Generates a secret key with the default size.
    * @return The key.
    */
   public SecretKey generateKey() {
      return secretKey(keyBytes(DEFAULT_CHARACTER_COUNT));
   }

   /**
    * Generates a secret key with a specified number of characters when encoded for a URI.
    * @param numChars The desired number of characters.
    * @return The key.
    */
   public SecretKey generateKey(int numChars) {
      if(numChars < DEFAULT_CHARACTER_COUNT) {
         throw new IllegalArgumentException("Too few characters");
      }
      return secretKey(keyBytes(numChars));
   }

   /**
    * Generates a secret key with a specified number of bytes.
    * @param numBytes The desired number of bytes.
    * @return The key.
    */
   public SecretKey generateKeyBytes(int numBytes) {
      if(numBytes < DEFAULT_BYTE_COUNT) {
         throw new IllegalArgumentException("Too few bytes");
      }

      byte[] b = new byte[numBytes];
      rnd.nextBytes(b);
      return secretKey(b);
   }

   /**
    * Encodes a secret key in the format required for a URL.
    * @param key The key.
    * @return The encoded key.
    */
   public String encodeKey(final SecretKey key) {
      return keyEncoding.encode(key.getEncoded());
   }

   /**
    * Creates a URI in the format required for a QR code.
    * @param key The key.
    * @param issuer The issuer name.
    * @param accountName The account name.
    * @return The URI.
    */
   public String uri(final SecretKey key, final String issuer, final String accountName) {

      if(issuer.contains(":")) {
         throw new IllegalArgumentException("The 'issuer' may not contain ':'");
      }


      if(accountName.contains(":")) {
         throw new IllegalArgumentException("The 'accountName' may not contain ':'");
      }

      return String.format(URI_TEMPLATE,
              uriPathEscaper.escape(issuer),
              uriPathEscaper.escape(accountName),
              keyEncoding.encode(key.getEncoded()),
              uriParameterEscaper.escape(issuer),
              timeStepSeconds);
   }

   /**
    * The current token.
    * @param key The secret key.
    * @return The current token string.
    * @throws InvalidKeyException if key is invalid.
    */
   public String currentToken(SecretKey key) throws InvalidKeyException  {
      return String.format(TOKEN_TEMPLATE, totp.generateOneTimePassword(key, Instant.now()));
   }

   /**
    * The previous token.
    * @param key The secret key.
    * @return The previous token string.
    * @throws InvalidKeyException if key is invalid.
    */
   public String previousToken(SecretKey key) throws InvalidKeyException  {
      return String.format(TOKEN_TEMPLATE, totp.generateOneTimePassword(key, Instant.now().minusSeconds(timeStepSeconds)));
   }

   /**
    * The next token.
    * @param key The secret key.
    * @return The next token string.
    * @throws InvalidKeyException if key is invalid.
    */
   public String nextToken(SecretKey key) throws InvalidKeyException  {
      return String.format(TOKEN_TEMPLATE, totp.generateOneTimePassword(key, Instant.now().plusSeconds(timeStepSeconds)));
   }

   /**
    * The password format template.
    */
   private final String TOKEN_TEMPLATE;

   /**
    * The URI template.
    */
   private static final String URI_TEMPLATE = "otpauth://totp/%s:%s?secret=%s&issuer=%s&period=%d";

   /**
    * Creates a secret key from key bytes.
    * @param keyBytes The key bytes.
    * @return The secret key.
    */
   public SecretKeySpec secretKey(final byte[] keyBytes) {
      return new SecretKeySpec(keyBytes, totp.getAlgorithm());
   }

   /**
    * Gets random key bytes that encode to a specified number of characters.
    * @param numChars The number of characters.
    * @return The bytes.
    */
   private final byte[] keyBytes(final int numChars) {
      byte[] b = new byte[(numChars * 5) / 8];
      rnd.nextBytes(b);
      return b;
   }

   /**
    * The password generator.
    */
   private final TimeBasedOneTimePasswordGenerator totp;

   /**
    * The time step in seconds.
    */
   private final int timeStepSeconds;

   /**
    * The key encoding for URI.
    */
   private final BaseEncoding keyEncoding = BaseEncoding.base32().omitPadding().upperCase();

   /**
    * The URI escaper.
    */
   private final Escaper uriPathEscaper = UrlEscapers.urlPathSegmentEscaper();

   /**
    * The URI parameter escaper.
    */
   private final Escaper uriParameterEscaper = UrlEscapers.urlPathSegmentEscaper();

   /**
    * The secure random generator.
    */
   private final SecureRandom rnd = new SecureRandom();
}
