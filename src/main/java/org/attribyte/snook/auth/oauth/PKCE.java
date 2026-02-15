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

package org.attribyte.snook.auth.oauth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * PKCE (Proof Key for Code Exchange) utilities for OAuth 2.1.
 * <p>
 *    OAuth 2.1 mandates PKCE for all clients (public and confidential).
 * </p>
 */
public final class PKCE {

   /**
    * The minimum verifier length ({@value}).
    */
   public static final int MIN_VERIFIER_LENGTH = 43;

   /**
    * The maximum verifier length ({@value}).
    */
   public static final int MAX_VERIFIER_LENGTH = 128;

   /**
    * The default verifier length ({@value}).
    */
   public static final int DEFAULT_VERIFIER_LENGTH = 43;

   /**
    * Unreserved characters allowed in a code verifier (RFC 7636 Section 4.1).
    */
   private static final String UNRESERVED_CHARS =
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

   private static final SecureRandom rnd = new SecureRandom();

   private PKCE() {}

   /**
    * Generates a random code verifier.
    * @return The code verifier string (43 characters).
    */
   public static String generateVerifier() {
      return generateVerifier(DEFAULT_VERIFIER_LENGTH);
   }

   /**
    * Generates a random code verifier.
    * @param length The verifier length (43-128).
    * @return The code verifier string.
    */
   public static String generateVerifier(final int length) {
      if(length < MIN_VERIFIER_LENGTH || length > MAX_VERIFIER_LENGTH) {
         throw new IllegalArgumentException(
                 String.format("Verifier length must be between %d and %d", MIN_VERIFIER_LENGTH, MAX_VERIFIER_LENGTH));
      }
      StringBuilder sb = new StringBuilder(length);
      for(int i = 0; i < length; i++) {
         sb.append(UNRESERVED_CHARS.charAt(rnd.nextInt(UNRESERVED_CHARS.length())));
      }
      return sb.toString();
   }

   /**
    * Computes the S256 code challenge from a verifier.
    * <p>
    *    {@code BASE64URL(SHA256(code_verifier))}
    * </p>
    * @param verifier The code verifier.
    * @return The S256 challenge.
    */
   public static String computeChallenge(final String verifier) {
      try {
         MessageDigest digest = MessageDigest.getInstance("SHA-256");
         byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
         return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
      } catch(NoSuchAlgorithmException e) {
         throw new AssertionError("SHA-256 not available", e);
      }
   }

   /**
    * Validates a code verifier against a stored S256 challenge.
    * @param verifier The code verifier from the token request.
    * @param storedChallenge The challenge stored during the authorization request.
    * @return {@code true} if valid.
    */
   public static boolean validate(final String verifier, final String storedChallenge) {
      String computed = computeChallenge(verifier);
      return MessageDigest.isEqual(
              computed.getBytes(StandardCharsets.US_ASCII),
              storedChallenge.getBytes(StandardCharsets.US_ASCII)
      );
   }
}
