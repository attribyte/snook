package org.attribyte.snook.auth.webauthn;

import com.google.common.collect.ImmutableMap;
import org.attribyte.snook.ErrorHandler;
import org.attribyte.snook.Server;

public class WebauthnServer extends Server {
   public WebauthnServer(String[] args) throws Exception {
      super(args, "", "webauthn", true);
   }

   public static void main(String[] args) throws Exception {
      WebauthnServer server = new WebauthnServer(args);
      server.httpServer.start();
      server.httpServer.join();
   }

   protected void shutdown() {
   }

}
