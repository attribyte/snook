package org.attribyte.snook.auth.webauthn;

import com.yubico.internal.util.CertificateParser;
import com.yubico.webauthn.data.ByteArray;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class AttestationCertInfo {
   public AttestationCertInfo(ByteArray certDer) {
      this.der = certDer;
      X509Certificate cert;
      try {
         cert = CertificateParser.parseDer(certDer.getBytes());
      } catch(CertificateException e) {
         cert = null;
      }

      if(cert == null) {
         this.text = null;
      } else {
         this.text = cert.toString();
      }
   }

   final ByteArray der;
   final String text;
}