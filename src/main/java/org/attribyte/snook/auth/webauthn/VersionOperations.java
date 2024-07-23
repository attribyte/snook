package org.attribyte.snook.auth.webauthn;
import com.yubico.webauthn.meta.VersionInfo;

public class VersionOperations extends Operations {

   public static final class VersionResponse {
      public final VersionInfo version = VersionInfo.getInstance();
   }

   public VersionOperations() {
      super(null, true);
   }

   public static final VersionResponse VERSION = new VersionResponse();
}
