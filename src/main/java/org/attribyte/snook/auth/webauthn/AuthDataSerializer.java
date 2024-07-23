package org.attribyte.snook.auth.webauthn;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.yubico.internal.util.JacksonCodecs;
import com.yubico.webauthn.data.AuthenticatorData;

import java.io.IOException;

public class AuthDataSerializer extends JsonSerializer<AuthenticatorData> {
   @Override
   public void serialize(
           AuthenticatorData value, JsonGenerator gen, SerializerProvider serializers)
           throws IOException {
      gen.writeStartObject();
      gen.writeStringField("rpIdHash", value.getRpIdHash().getHex());
      gen.writeObjectField("flags", value.getFlags());
      gen.writeNumberField("signatureCounter", value.getSignatureCounter());
      value
              .getAttestedCredentialData()
              .ifPresent(
                      acd -> {
                         try {
                            gen.writeObjectFieldStart("attestedCredentialData");
                            gen.writeStringField("aaguid", acd.getAaguid().getHex());
                            gen.writeStringField("credentialId", acd.getCredentialId().getHex());
                            gen.writeStringField("publicKey", acd.getCredentialPublicKey().getHex());
                            gen.writeEndObject();
                         } catch(IOException e) {
                            throw new RuntimeException(e);
                         }
                      });
      value
              .getExtensions()
              .ifPresent(
                      extensions -> {
                         try {
                            gen.writeObjectField(
                                    "extensions", JacksonCodecs.cbor().readTree(extensions.EncodeToBytes()));
                         } catch(IOException e) {
                            throw new RuntimeException(e);
                         }
                      });
      gen.writeEndObject();
   }
}