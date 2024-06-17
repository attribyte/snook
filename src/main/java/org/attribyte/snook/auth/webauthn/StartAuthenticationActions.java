package org.attribyte.snook.auth.webauthn;

import java.net.MalformedURLException;
import java.net.URL;

public class StartAuthenticationActions {
   StartAuthenticationActions(final URL finishPath) throws MalformedURLException {
      this.finish = finishPath;
   }

   public final URL finish;
}
