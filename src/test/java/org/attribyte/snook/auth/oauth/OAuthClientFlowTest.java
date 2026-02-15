package org.attribyte.snook.auth.oauth;

import com.google.common.collect.ImmutableSet;
import org.attribyte.snook.auth.oauth.client.OAuthClientFlow;
import org.attribyte.snook.auth.oauth.client.PKCEPair;
import org.attribyte.snook.auth.oauth.client.TokenResponse;
import org.junit.Test;

import java.util.Optional;

import static org.junit.Assert.*;

public class OAuthClientFlowTest {

   @Test
   public void testPKCEPairGenerate() {
      PKCEPair pair = PKCEPair.generate();
      assertNotNull(pair.verifier);
      assertNotNull(pair.challenge);
      assertEquals(PKCE.DEFAULT_VERIFIER_LENGTH, pair.verifier.length());
      assertTrue(PKCE.validate(pair.verifier, pair.challenge));
   }

   @Test
   public void testBuildAuthorizationRequest() {
      OAuthClientFlow flow = new OAuthClientFlow("test-client", Optional.empty(),
              "https://auth.example.com/oauth/authorize",
              "https://auth.example.com/oauth/token");

      OAuthClientFlow.AuthorizationRequest request = flow.buildAuthorizationRequest(
              "https://app.example.com/callback",
              ImmutableSet.of("read", "write"),
              "state123");

      assertNotNull(request.url);
      assertTrue(request.url.startsWith("https://auth.example.com/oauth/authorize?"));
      assertTrue(request.url.contains("response_type=code"));
      assertTrue(request.url.contains("client_id=test-client"));
      assertTrue(request.url.contains("redirect_uri="));
      assertTrue(request.url.contains("code_challenge="));
      assertTrue(request.url.contains("code_challenge_method=S256"));
      assertTrue(request.url.contains("state=state123"));
      assertEquals("state123", request.state);
      assertNotNull(request.pkcePair);
      assertNotNull(request.pkcePair.verifier);
      assertNotNull(request.pkcePair.challenge);
   }

   @Test
   public void testBuildAuthorizationRequestNoScopes() {
      OAuthClientFlow flow = new OAuthClientFlow("test-client", Optional.empty(),
              "https://auth.example.com/oauth/authorize",
              "https://auth.example.com/oauth/token");

      OAuthClientFlow.AuthorizationRequest request = flow.buildAuthorizationRequest(
              "https://app.example.com/callback",
              ImmutableSet.of(),
              "state456");

      assertFalse(request.url.contains("scope="));
   }

   @Test
   public void testTokenResponseFromJsonSuccess() {
      String json = "{\"access_token\":\"abc123\",\"token_type\":\"Bearer\"," +
              "\"expires_in\":3600,\"refresh_token\":\"def456\",\"scope\":\"read write\"}";

      TokenResponse response = TokenResponse.fromJson(json);
      assertFalse(response.isError());
      assertEquals("abc123", response.accessToken);
      assertEquals("Bearer", response.tokenType);
      assertEquals(3600, response.expiresIn);
      assertTrue(response.refreshToken.isPresent());
      assertEquals("def456", response.refreshToken.get());
      assertEquals("read write", response.scope);
   }

   @Test
   public void testTokenResponseFromJsonError() {
      String json = "{\"error\":\"invalid_grant\",\"error_description\":\"Code expired\"}";

      TokenResponse response = TokenResponse.fromJson(json);
      assertTrue(response.isError());
      assertEquals("invalid_grant", response.error.get());
      assertEquals("Code expired", response.errorDescription.get());
      assertNull(response.accessToken);
   }

   @Test
   public void testTokenResponseFromJsonNoRefresh() {
      String json = "{\"access_token\":\"abc123\",\"token_type\":\"Bearer\",\"expires_in\":3600}";

      TokenResponse response = TokenResponse.fromJson(json);
      assertFalse(response.isError());
      assertEquals("abc123", response.accessToken);
      assertFalse(response.refreshToken.isPresent());
   }

   @Test
   public void testTokenResponseToString() {
      TokenResponse response = TokenResponse.fromJson(
              "{\"access_token\":\"abc\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
      String str = response.toString();
      assertNotNull(str);
      // Should not expose the actual token value
      assertTrue(str.contains("[present]"));
      assertFalse(str.contains("abc"));
   }
}
