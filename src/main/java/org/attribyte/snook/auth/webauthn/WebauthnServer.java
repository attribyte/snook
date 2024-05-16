package org.attribyte.snook.auth.webauthn;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.attribyte.snook.Server;
import org.eclipse.jetty.servlet.ServletHolder;

import java.util.concurrent.TimeUnit;

public class WebauthnServer extends Server {
   public WebauthnServer(String[] args) throws Exception {
      super(args, "", "webauthn", true);
      String rpId = props.getProperty("rp.id", "");
      if(rpId.isEmpty()) {
         logger.error("The relaying party id (rp.id) must be specified");
      }
      String rpName = props.getProperty("rp.name", "");
      if(rpName.isEmpty()) {
         logger.error("The relaying party name (rp.name) must be specified");
      }

      RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
              .id(rpId)
              .name(rpName).build();

      this.sessions = new Sessions(1000, 5); //TODO
      this.storage = new InMemoryStorage(1000, 24, logger);
      this.relayingParty = RelyingParty.builder()
              .identity(rpIdentity)
              .credentialRepository(this.storage).build();
      this.registrationRequestCache = CacheBuilder.newBuilder()
              .maximumSize(100)
              .expireAfterAccess(10, TimeUnit.MINUTES)
              .build(); //TODO
   }

   public static void main(String[] args) throws Exception {
      WebauthnServer server = new WebauthnServer(args);
      server.rootContext.addServlet(new ServletHolder(new RegistrationServlet(server.relayingParty, server.storage,
                      server.sessions, server.registrationRequestCache, server.logger))
              , "/register/*");
      server.rootContext.addServlet(new ServletHolder(new VersionServlet()), "/version");
      server.httpServer.start();
      server.httpServer.join();
   }

   /**
    * Shutdown the server.
    */
   protected void shutdown() {
   }

   /**
    * The relaying party.
    */
   private final RelyingParty relayingParty;

   /**
    * The registration storage.
    */
   private final Storage storage;

   /**
    * Registration sessions.
    */
   private final Sessions sessions;

   /**
    * The in-memory cache for registration requests.
    */
   private final Cache<ByteArray, RegistrationRequest> registrationRequestCache;

}
