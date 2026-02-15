package org.attribyte.snook.auth.oauth;

import com.google.common.collect.ImmutableSet;
import org.attribyte.snook.auth.Authenticator;
import org.attribyte.snook.auth.oauth.model.OAuthAccessToken;
import org.attribyte.snook.auth.oauth.model.OAuthRefreshToken;
import org.attribyte.snook.auth.oauth.store.InMemoryTokenStore;
import org.junit.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.Assert.*;

public class InMemoryTokenStoreTest {

   @Test
   public void testStoreAndResolveAccessToken() {
      InMemoryTokenStore store = new InMemoryTokenStore();
      OAuthAccessToken token = OAuthAccessToken.create("client1", "user1",
              ImmutableSet.of("read"), 3600);
      store.storeAccessToken(token);
      Optional<OAuthAccessToken> resolved = store.resolveAccessToken(token.tokenHash);
      assertTrue(resolved.isPresent());
      assertEquals("client1", resolved.get().clientId);
      assertEquals("user1", resolved.get().username);
   }

   @Test
   public void testResolveAccessTokenByHash() {
      InMemoryTokenStore store = new InMemoryTokenStore();
      OAuthAccessToken token = OAuthAccessToken.create("client1", "user1",
              ImmutableSet.of("read"), 3600);
      store.storeAccessToken(token);
      // Resolve using hash computed from the raw token
      var hash = Authenticator.hashCredentials(token.token);
      Optional<OAuthAccessToken> resolved = store.resolveAccessToken(hash);
      assertTrue(resolved.isPresent());
   }

   @Test
   public void testRevokeAccessToken() {
      InMemoryTokenStore store = new InMemoryTokenStore();
      OAuthAccessToken token = OAuthAccessToken.create("client1", "user1",
              ImmutableSet.of("read"), 3600);
      store.storeAccessToken(token);
      store.revokeAccessToken(token.tokenHash);
      assertFalse(store.resolveAccessToken(token.tokenHash).isPresent());
   }

   @Test
   public void testStoreAndResolveRefreshToken() {
      InMemoryTokenStore store = new InMemoryTokenStore();
      OAuthRefreshToken token = OAuthRefreshToken.create("client1", "user1",
              ImmutableSet.of("read"), 86400);
      store.storeRefreshToken(token);
      Optional<OAuthRefreshToken> resolved = store.resolveRefreshToken(token.tokenHash);
      assertTrue(resolved.isPresent());
      assertEquals("client1", resolved.get().clientId);
   }

   @Test
   public void testRevokeRefreshToken() {
      InMemoryTokenStore store = new InMemoryTokenStore();
      OAuthRefreshToken token = OAuthRefreshToken.create("client1", "user1",
              ImmutableSet.of("read"), 86400);
      store.storeRefreshToken(token);
      store.revokeRefreshToken(token.tokenHash);
      assertFalse(store.resolveRefreshToken(token.tokenHash).isPresent());
   }

   @Test
   public void testRevokeAllForUser() {
      InMemoryTokenStore store = new InMemoryTokenStore();
      OAuthAccessToken at1 = OAuthAccessToken.create("client1", "user1", ImmutableSet.of("read"), 3600);
      OAuthAccessToken at2 = OAuthAccessToken.create("client2", "user1", ImmutableSet.of("write"), 3600);
      OAuthAccessToken at3 = OAuthAccessToken.create("client1", "user2", ImmutableSet.of("read"), 3600);
      OAuthRefreshToken rt1 = OAuthRefreshToken.create("client1", "user1", ImmutableSet.of("read"), 86400);
      store.storeAccessToken(at1);
      store.storeAccessToken(at2);
      store.storeAccessToken(at3);
      store.storeRefreshToken(rt1);
      store.revokeAllForUser("user1");
      assertFalse(store.resolveAccessToken(at1.tokenHash).isPresent());
      assertFalse(store.resolveAccessToken(at2.tokenHash).isPresent());
      assertTrue(store.resolveAccessToken(at3.tokenHash).isPresent());
      assertFalse(store.resolveRefreshToken(rt1.tokenHash).isPresent());
   }

   @Test
   public void testCleanup() {
      InMemoryTokenStore store = new InMemoryTokenStore();
      OAuthAccessToken expired = new OAuthAccessToken("expired-token",
              Authenticator.hashCredentials("expired-token"),
              "client1", "user1", ImmutableSet.of("read"),
              Instant.now().minusSeconds(10), Optional.empty());
      OAuthAccessToken valid = OAuthAccessToken.create("client1", "user1",
              ImmutableSet.of("read"), 3600);
      store.storeAccessToken(expired);
      store.storeAccessToken(valid);
      int removed = store.cleanup();
      assertEquals(1, removed);
      assertFalse(store.resolveAccessToken(expired.tokenHash).isPresent());
      assertTrue(store.resolveAccessToken(valid.tokenHash).isPresent());
   }
}
