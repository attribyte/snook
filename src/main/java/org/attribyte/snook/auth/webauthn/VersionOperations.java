package org.attribyte.snook.auth.webauthn;
import com.yubico.webauthn.meta.VersionInfo;

public class VersionOperations extends Operations {

   static final class VersionResponse {
      public final VersionInfo version = VersionInfo.getInstance();
   }

   VersionOperations() {
      super(null);
   }

   static final VersionResponse VERSION = new VersionResponse();
}
