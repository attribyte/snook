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

import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;

import static junit.framework.TestCase.assertTrue;
import static org.attribyte.snook.Util.generateQRCode;
import static org.junit.Assert.*;

public class TOTPTest {

   @Test
   public void generateURL() throws Exception {
      TOTP totp = TOTP.createSixDigit();
      SecretKey key = totp.generateKey(32);
      String url = totp.uri(key, "Attribyte", "matt@attribyte.com");
      System.out.println("URL: " + url);

      try(FileOutputStream fos = new FileOutputStream("/home/matt/qr.png")) {
         generateQRCode(url, fos);
         fos.flush();
      }

      for(int i = 0; i < 20; i++) {
         System.out.println(totp.generateCurrentPassword(key));
         Thread.sleep(15000L);
      }
   }
}
