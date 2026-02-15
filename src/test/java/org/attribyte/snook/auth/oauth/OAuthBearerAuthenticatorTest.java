package org.attribyte.snook.auth.oauth;

import com.google.common.collect.ImmutableSet;
import org.attribyte.snook.auth.Authenticator;
import org.attribyte.snook.auth.oauth.model.OAuthAccessToken;
import org.attribyte.snook.auth.oauth.store.InMemoryTokenStore;
import org.attribyte.snook.test.TestHttpServletRequest;
import org.eclipse.jetty.http.HttpHeader;
import org.junit.Before;
import org.junit.Test;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.Optional;

import static org.junit.Assert.*;

public class OAuthBearerAuthenticatorTest {

   private InMemoryTokenStore tokenStore;
   private OAuthBearerAuthenticator authenticator;

   @Before
   public void setUp() {
      tokenStore = new InMemoryTokenStore();
      authenticator = new OAuthBearerAuthenticator(tokenStore);
   }

   @Test
   public void testAuthorized() {
      OAuthAccessToken token = OAuthAccessToken.create("client1", "testuser",
              ImmutableSet.of("read"), 3600);
      tokenStore.storeAccessToken(token);

      HttpServletRequest request = buildRequest("Bearer " + token.token);
      assertTrue(authenticator.authorized(request));
      assertEquals("testuser", authenticator.authorizedUsername(request));
   }

   @Test
   public void testUnauthorizedNoToken() {
      HttpServletRequest request = buildRequest(null);
      assertFalse(authenticator.authorized(request));
      assertNull(authenticator.authorizedUsername(request));
   }

   @Test
   public void testUnauthorizedInvalidToken() {
      HttpServletRequest request = buildRequest("Bearer invalid_token_value");
      assertFalse(authenticator.authorized(request));
   }

   @Test
   public void testUnauthorizedExpiredToken() {
      OAuthAccessToken token = new OAuthAccessToken("expired-token",
              Authenticator.hashCredentials("expired-token"),
              "client1", "testuser", ImmutableSet.of("read"),
              Instant.now().minusSeconds(10), Optional.empty());
      tokenStore.storeAccessToken(token);

      HttpServletRequest request = buildRequest("Bearer expired-token");
      assertFalse(authenticator.authorized(request));
   }

   @Test
   public void testResolveToken() {
      OAuthAccessToken token = OAuthAccessToken.create("client1", "testuser",
              ImmutableSet.of("read", "write"), 3600);
      tokenStore.storeAccessToken(token);

      HttpServletRequest request = buildRequest("Bearer " + token.token);
      Optional<OAuthAccessToken> resolved = authenticator.resolveToken(request);
      assertTrue(resolved.isPresent());
      assertEquals("testuser", resolved.get().username);
      assertEquals(ImmutableSet.of("read", "write"), resolved.get().scopes);
   }

   @Test
   public void testResolveTokenExpired() {
      OAuthAccessToken token = new OAuthAccessToken("expired-token",
              Authenticator.hashCredentials("expired-token"),
              "client1", "testuser", ImmutableSet.of("read"),
              Instant.now().minusSeconds(10), Optional.empty());
      tokenStore.storeAccessToken(token);

      HttpServletRequest request = buildRequest("Bearer expired-token");
      Optional<OAuthAccessToken> resolved = authenticator.resolveToken(request);
      assertFalse(resolved.isPresent());
   }

   @Test
   public void testResolveTokenNoHeader() {
      Optional<OAuthAccessToken> resolved = authenticator.resolveToken(buildRequest(null));
      assertFalse(resolved.isPresent());
   }

   @Test
   public void testSchemeName() {
      assertEquals("Bearer", authenticator.schemeName());
   }

   private HttpServletRequest buildRequest(final String authHeaderValue) {
      return new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            if(s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString())) {
               return authHeaderValue;
            }
            return null;
         }
      };
   }
}
