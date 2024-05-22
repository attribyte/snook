package org.attribyte.snook.auth.webauthn;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.fido.metadata.FidoMetadataDownloader;
import com.yubico.fido.metadata.FidoMetadataDownloaderException;
import com.yubico.fido.metadata.FidoMetadataService;
import com.yubico.fido.metadata.UnexpectedLegalHeader;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.exception.Base64UrlException;
import org.attribyte.snook.Server;
import org.attribyte.snook.auth.webauthn.attestation.YubicoJsonMetadataService;
import org.attribyte.snook.auth.webauthn.data.RegistrationRequest;
import org.eclipse.jetty.servlet.ServletHolder;

import java.io.File;
import java.io.IOException;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;

public class WebauthnServer extends Server {

   public static void main(String[] args) throws Exception {
      WebauthnServer server = new WebauthnServer(args);
      server.rootContext.addServlet(new ServletHolder(new RegistrationServlet(server.relayingParty, server.storage,
                      server.sessions, server.registrationRequestCache, server.metadataService, server.logger))
              , "/api/register/*");
      server.rootContext.addServlet(new ServletHolder(new VersionServlet()), "/api/version");
      server.httpServer.start();
      server.httpServer.join();
   }

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
      this.metadataService = buildMetadataService();
      this.useFidoMds = props.getProperty("useFidoMds", "false").equalsIgnoreCase("true");
   }

   private MetadataService getMetadataService()
           throws CertPathValidatorException,
           InvalidAlgorithmParameterException,
           Base64UrlException,
           DigestException,
           FidoMetadataDownloaderException,
           CertificateException,
           UnexpectedLegalHeader,
           IOException,
           NoSuchAlgorithmException,
           SignatureException,
           InvalidKeyException {
      if (useFidoMds) {
         logger.info("Using combination of Yubico JSON file and FIDO MDS for attestation metadata.");
         return new CompositeMetadataService(
                 new YubicoJsonMetadataService(),
                 new FidoMetadataServiceAdapter(
                         FidoMetadataService.builder()
                                 .useBlob(
                                         FidoMetadataDownloader.builder()
                                                 .expectLegalHeader(
                                                         "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/")
                                                 .useDefaultTrustRoot()
                                                 .useTrustRootCacheFile(
                                                         new File("webauthn-server-demo-fido-mds-trust-root-cache.bin"))
                                                 .useDefaultBlob()
                                                 .useBlobCacheFile(
                                                         new File("webauthn-server-demo-fido-mds-blob-cache.bin"))
                                                 .build()
                                                 .loadCachedBlob())
                                 .build()));
      } else {
         logger.info("Using only Yubico JSON file for attestation metadata.");
         return new YubicoJsonMetadataService();
      }
   }

   private MetadataService buildMetadataService()
           throws CertPathValidatorException,
           InvalidAlgorithmParameterException,
           Base64UrlException,
           DigestException,
           FidoMetadataDownloaderException,
           CertificateException,
           UnexpectedLegalHeader,
           IOException,
           NoSuchAlgorithmException,
           SignatureException,
           InvalidKeyException {
      return new FidoMetadataServiceAdapter(
              FidoMetadataService.builder()
                      .useBlob(
                              FidoMetadataDownloader.builder()
                                      .expectLegalHeader(
                                              "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/")
                                      .useDefaultTrustRoot()
                                      .useTrustRootCacheFile(
                                              new File("webauthn-server-demo-fido-mds-trust-root-cache.bin"))
                                      .useDefaultBlob()
                                      .useBlobCacheFile(
                                              new File("webauthn-server-demo-fido-mds-blob-cache.bin"))
                                      .build()
                                      .loadCachedBlob())
                      .build());
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

   /**
    * The metadata service.
    */
   private final MetadataService metadataService;

   /**
    * Use FIDO mds.
    */
   private final boolean useFidoMds;

}
