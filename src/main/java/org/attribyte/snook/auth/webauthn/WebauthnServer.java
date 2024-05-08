package org.attribyte.snook.auth.webauthn;

import org.attribyte.snook.Server;
import org.eclipse.jetty.servlet.ServletHolder;

public class WebauthnServer extends Server {
   public WebauthnServer(String[] args) throws Exception {
      super(args, "", "webauthn", true);
   }

   public static void main(String[] args) throws Exception {
      WebauthnServer server = new WebauthnServer(args);
      server.rootContext.addServlet(new ServletHolder(new RegistrationServlet()), "/register/*");
      server.httpServer.start();
      server.httpServer.join();
   }

   protected void shutdown() {
   }

}
