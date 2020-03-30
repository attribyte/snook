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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;

public class TOTP {

   /**
    * The default number of characters in the key encoded for a URL.
    */
   public static final int DEFAULT_CHARACTER_COUNT = 32;

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
    * Creates a seven digit instance with a specified time step.
    * @param timeStepSeconds The time step in seconds.
    * @return The instance.
    */
   public static TOTP createSevenDigit(int timeStepSeconds) {
      return new TOTP(timeStepSeconds, 7);
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
      return new TOTP(DEFAULT_TIME_STEP_SECONDS, 6);
   }

   /**
    * Creates a seven digit instance with the default time step.
    * @return The instance.
    */
   public static TOTP createSevenDigit() {
      return new TOTP(DEFAULT_TIME_STEP_SECONDS, 7);
   }

   /**
    * Creates a eight digit instance with the default time step.
    * @return The instance.
    */
   public static TOTP createEightDigit() {
      return new TOTP(DEFAULT_TIME_STEP_SECONDS, 8);
   }

   private TOTP(final int timeStepSeconds, final int passwordLength) {
      if(timeStepSeconds < 1) {
         throw new IllegalArgumentException("Time step must be positive");
      }

      this.timeStepSeconds = timeStepSeconds;

      try {
         totp = new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(timeStepSeconds), passwordLength);
      } catch(NoSuchAlgorithmException noe) {
         throw new AssertionError("SHA1 algorithm is unavailable");
      }

      switch(passwordLength) {
         case 7:
            this.PASSWORD_TEMPLATE = "%07d";
            break;
         case 8:
            this.PASSWORD_TEMPLATE = "%08d";
            break;
         default:
            this.PASSWORD_TEMPLATE = "%06d";
            break;
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
         throw new IllegalArgumentException("Number of characters too small");
      }
      return secretKey(keyBytes(numChars));
   }

   /**
    * Encodes a secret key for a URL.
    * @param key The key.
    * @return The encoded key.
    */
   public String encodeKey(final SecretKey key) {
      return keyEncoding.encode(key.getEncoded());
   }

   /**
    * Creates a URI with an image.
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
    * Generates the current password.
    * @param key The secret key.
    * @return The current password as a string.
    * @throws InvalidKeyException if key is invalid.
    */
   public String generateCurrentPassword(SecretKey key) throws InvalidKeyException  {
      return String.format(PASSWORD_TEMPLATE, totp.generateOneTimePassword(key, Instant.now()));
   }

   /**
    * The password format template.
    */
   private final String PASSWORD_TEMPLATE;

   /**
    * The URI template.
    */
   private static final String URI_TEMPLATE = "otpauth://totp/%s:%s?secret=%s&issuer=%s&period=%d";

   /**
    * Creates a secret key from key bytes.
    * @param keyBytes The key bytes.
    * @return The secret key.
    */
   private SecretKeySpec secretKey(final byte[] keyBytes) {
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
