package org.attribyte.snook.auth.oauth;

import com.google.common.collect.ImmutableSet;
import org.attribyte.snook.auth.oauth.model.AuthorizationCode;
import org.attribyte.snook.auth.oauth.store.InMemoryCodeStore;
import org.junit.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.Assert.*;

public class InMemoryCodeStoreTest {

   @Test
   public void testStoreAndConsume() {
      InMemoryCodeStore store = new InMemoryCodeStore();
      AuthorizationCode code = AuthorizationCode.create("client1", "user1",
              "https://example.com/callback", "challenge123", ImmutableSet.of("read"), 600);
      store.store(code);
      Optional<AuthorizationCode> consumed = store.consume(code.code);
      assertTrue(consumed.isPresent());
      assertEquals("client1", consumed.get().clientId);
      assertEquals("user1", consumed.get().username);
   }

   @Test
   public void testConsumeIsOneTimeUse() {
      InMemoryCodeStore store = new InMemoryCodeStore();
      AuthorizationCode code = AuthorizationCode.create("client1", "user1",
              "https://example.com/callback", "challenge123", ImmutableSet.of("read"), 600);
      store.store(code);
      assertTrue(store.consume(code.code).isPresent());
      assertFalse(store.consume(code.code).isPresent());
   }

   @Test
   public void testConsumeNotFound() {
      InMemoryCodeStore store = new InMemoryCodeStore();
      assertFalse(store.consume("nonexistent").isPresent());
   }

   @Test
   public void testCleanup() {
      InMemoryCodeStore store = new InMemoryCodeStore();
      // Create an already-expired code
      AuthorizationCode expired = new AuthorizationCode("expired-code", "client1", "user1",
              "https://example.com/callback", "challenge123", ImmutableSet.of("read"),
              Instant.now().minusSeconds(10));
      AuthorizationCode valid = AuthorizationCode.create("client1", "user1",
              "https://example.com/callback", "challenge456", ImmutableSet.of("read"), 600);
      store.store(expired);
      store.store(valid);
      assertEquals(1, store.cleanup());
      assertFalse(store.consume("expired-code").isPresent());
      assertTrue(store.consume(valid.code).isPresent());
   }
}
