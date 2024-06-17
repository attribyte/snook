package org.attribyte.snook.auth.webauthn;

import org.attribyte.snook.auth.webauthn.data.AssertionRequestWrapper;

import java.net.MalformedURLException;
import java.net.URL;

public class StartAuthenticationResponse {

   StartAuthenticationResponse(AssertionRequestWrapper request, URL finishPath)
           throws MalformedURLException {
      this.request = request;
      this.actions = new StartAuthenticationActions(finishPath);
   }

   public final boolean success = true;
   public final AssertionRequestWrapper request;
   public final StartAuthenticationActions actions;
}
