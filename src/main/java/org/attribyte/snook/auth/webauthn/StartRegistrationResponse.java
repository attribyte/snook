package org.attribyte.snook.auth.webauthn;


import java.net.URL;

class StartRegistrationResponse {

   StartRegistrationResponse(final RegistrationRequest request,
                             final URL finishPath) {
      this.request = request;
      this.actions = new StartRegistrationActions(finishPath);
   }

   public final boolean success = true;
   public final RegistrationRequest request;
   public final StartRegistrationActions actions;
}