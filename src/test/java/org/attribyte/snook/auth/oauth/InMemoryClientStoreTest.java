package org.attribyte.snook.auth.oauth;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.attribyte.snook.auth.Authenticator;
import org.attribyte.snook.auth.oauth.model.OAuthClient;
import org.attribyte.snook.auth.oauth.store.InMemoryClientStore;
import org.junit.Test;

import java.util.Optional;

import static org.junit.Assert.*;

public class InMemoryClientStoreTest {

   @Test
   public void testRegisterAndGet() {
      InMemoryClientStore store = new InMemoryClientStore();
      OAuthClient client = OAuthClient.publicClient("test-client", "Test App",
              ImmutableList.of("https://example.com/callback"), ImmutableSet.of("read"));
      store.register(client);
      Optional<OAuthClient> found = store.getClient("test-client");
      assertTrue(found.isPresent());
      assertEquals("test-client", found.get().clientId);
      assertEquals("Test App", found.get().name);
   }

   @Test
   public void testGetNotFound() {
      InMemoryClientStore store = new InMemoryClientStore();
      assertFalse(store.getClient("nonexistent").isPresent());
   }

   @Test
   public void testConfidentialClient() {
      InMemoryClientStore store = new InMemoryClientStore();
      OAuthClient client = OAuthClient.confidentialClient("conf-client",
              Authenticator.hashCredentials("my-secret"),
              "Conf App",
              ImmutableList.of("https://example.com/callback"),
              ImmutableSet.of("read", "write"));
      store.register(client);
      Optional<OAuthClient> found = store.getClient("conf-client");
      assertTrue(found.isPresent());
      assertTrue(found.get().confidential);
      assertTrue(found.get().clientSecretHash.isPresent());
   }

   @Test
   public void testPublicClient() {
      OAuthClient client = OAuthClient.publicClient("pub-client", "Pub App",
              ImmutableList.of("https://example.com/callback"), ImmutableSet.of("read"));
      assertFalse(client.confidential);
      assertFalse(client.clientSecretHash.isPresent());
   }

   @Test
   public void testValidateRedirectUri() {
      OAuthClient client = OAuthClient.publicClient("test", "Test",
              ImmutableList.of("https://example.com/callback", "https://example.com/other"),
              ImmutableSet.of("read"));
      assertTrue(client.validateRedirectUri("https://example.com/callback"));
      assertTrue(client.validateRedirectUri("https://example.com/other"));
      assertFalse(client.validateRedirectUri("https://evil.com/callback"));
   }
}
