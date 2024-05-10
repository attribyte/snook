package org.attribyte.snook.auth.webauthn;

import com.yubico.webauthn.data.ByteArray;

import java.security.SecureRandom;

public class Util {

   private static final SecureRandom random = new SecureRandom();

   /**
    * @return Random bytes with the specific length.
    */
   public static final ByteArray randomBytes(final int length) {
      byte[] sessionId = new byte[length];
      random.nextBytes(sessionId);
      return new ByteArray(sessionId);
   }
}
