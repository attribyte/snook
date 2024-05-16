package org.attribyte.snook.auth.webauthn;

import java.net.MalformedURLException;
import java.net.URL;

public class StartRegistrationActions {

   StartRegistrationActions(final URL finishPath) {
      this.finish = finishPath;
   }

   public final URL finish;
}
