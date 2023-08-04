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

import org.junit.Test;

import javax.crypto.SecretKey;

import static org.junit.Assert.assertArrayEquals;

public class TOTPTest {

   @Test
   public void generateSecretKey() throws Exception {
      TOTP totp = TOTP.createEightDigit();
      SecretKey key = totp.generateKey();
      byte[] keyBytes = key.getEncoded();
      SecretKey testKey = totp.secretKey(keyBytes);
      assertArrayEquals(testKey.getEncoded(), key.getEncoded());
      System.out.println(totp.previousToken(testKey));
      System.out.println(totp.currentToken(testKey));
      System.out.println(totp.nextToken(testKey));

   }

   @Test
   public void generateURL() throws Exception {
      TOTP totp = TOTP.createSixDigit();
      SecretKey key = totp.generateKey();
      System.out.println("Default Key Bytes: " + key.getEncoded().length);
      System.out.println("Default Encoded Chars: " + totp.encodeKey(key).length());
      String url = totp.uri(key, "Attribyte", "matt@attribyte.com");
      System.out.println("URL: " + url);

      /*
      try(FileOutputStream fos = new FileOutputStream("/home/matt/qr.png")) {
         generateQRCode(url, fos);
         fos.flush();
      }

      for(int i = 0; i < 20; i++) {
         System.out.println("Previous: " + totp.previousToken(key));
         System.out.println("Current: " + totp.currentToken(key));
         System.out.println("Next: " + totp.nextToken(key));
         Thread.sleep(15000L);
      }
       */
   }
}
