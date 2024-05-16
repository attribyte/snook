package org.attribyte.snook.auth.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.yubico.webauthn.data.ByteArray;

import java.security.SecureRandom;

public class Util {

   /**
    * Securely generate random bytes.
    */
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
