package org.attribyte.snook.auth.oauth;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.attribyte.snook.auth.Authenticator;
import org.attribyte.snook.auth.oauth.model.AuthorizationCode;
import org.attribyte.snook.auth.oauth.model.OAuthClient;
import org.attribyte.snook.auth.oauth.model.OAuthRefreshToken;
import org.attribyte.snook.auth.oauth.store.InMemoryClientStore;
import org.attribyte.snook.auth.oauth.store.InMemoryCodeStore;
import org.attribyte.snook.auth.oauth.store.InMemoryTokenStore;
import org.attribyte.snook.test.TestHttpServletRequest;
import org.attribyte.snook.test.TestHttpServletResponse;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class TokenEndpointTest {

   private static final Gson GSON = new Gson();
   private InMemoryClientStore clientStore;
   private InMemoryCodeStore codeStore;
   private InMemoryTokenStore tokenStore;
   private TokenEndpoint endpoint;
   private String verifier;
   private String challenge;

   @Before
   public void setUp() {
      clientStore = new InMemoryClientStore();
      codeStore = new InMemoryCodeStore();
      tokenStore = new InMemoryTokenStore();

      clientStore.register(OAuthClient.publicClient("test-client", "Test App",
              ImmutableList.of("https://example.com/callback"),
              ImmutableSet.of("read", "write")));

      clientStore.register(OAuthClient.confidentialClient("conf-client",
              Authenticator.hashCredentials("client-secret-123"),
              "Conf App",
              ImmutableList.of("https://example.com/callback"),
              ImmutableSet.of("read", "write")));

      endpoint = new TokenEndpoint(clientStore, codeStore, tokenStore, 3600, 86400);

      verifier = PKCE.generateVerifier();
      challenge = PKCE.computeChallenge(verifier);
   }

   @Test
   public void testAuthorizationCodeExchange() throws Exception {
      AuthorizationCode code = AuthorizationCode.create("test-client", "testuser",
              "https://example.com/callback", challenge, ImmutableSet.of("read"), 600);
      codeStore.store(code);

      Map<String, String> params = new HashMap<>();
      params.put("grant_type", "authorization_code");
      params.put("code", code.code);
      params.put("redirect_uri", "https://example.com/callback");
      params.put("client_id", "test-client");
      params.put("code_verifier", verifier);

      TestHttpServletResponse response = new TestHttpServletResponse();
      endpoint.doPost(buildRequest(params, null), response);

      assertEquals(200, response.status);
      assertEquals("application/json;charset=UTF-8", response.getContentType());
      assertEquals("no-store", response.getHeader("Cache-Control"));

      Map<String, Object> json = parseJson(response);
      assertNotNull(json.get("access_token"));
      assertEquals("Bearer", json.get("token_type"));
      assertEquals(3600.0, json.get("expires_in"));
      assertNotNull(json.get("refresh_token"));
   }

   @Test
   public void testCodeOneTimeUse() throws Exception {
      AuthorizationCode code = AuthorizationCode.create("test-client", "testuser",
              "https://example.com/callback", challenge, ImmutableSet.of("read"), 600);
      codeStore.store(code);

      Map<String, String> params = new HashMap<>();
      params.put("grant_type", "authorization_code");
      params.put("code", code.code);
      params.put("redirect_uri", "https://example.com/callback");
      params.put("client_id", "test-client");
      params.put("code_verifier", verifier);

      // First use succeeds
      TestHttpServletResponse response1 = new TestHttpServletResponse();
      endpoint.doPost(buildRequest(params, null), response1);
      assertEquals(200, response1.status);

      // Second use fails
      TestHttpServletResponse response2 = new TestHttpServletResponse();
      endpoint.doPost(buildRequest(params, null), response2);
      assertEquals(400, response2.status);
      assertTrue(response2.outputStream.toString().contains("invalid_grant"));
   }

   @Test
   public void testPKCEValidationFailure() throws Exception {
      AuthorizationCode code = AuthorizationCode.create("test-client", "testuser",
              "https://example.com/callback", challenge, ImmutableSet.of("read"), 600);
      codeStore.store(code);

      Map<String, String> params = new HashMap<>();
      params.put("grant_type", "authorization_code");
      params.put("code", code.code);
      params.put("redirect_uri", "https://example.com/callback");
      params.put("client_id", "test-client");
      params.put("code_verifier", PKCE.generateVerifier()); // Wrong verifier

      TestHttpServletResponse response = new TestHttpServletResponse();
      endpoint.doPost(buildRequest(params, null), response);

      assertEquals(400, response.status);
      assertTrue(response.outputStream.toString().contains("PKCE validation failed"));
   }

   @Test
   public void testConfidentialClientBasicAuth() throws Exception {
      AuthorizationCode code = AuthorizationCode.create("conf-client", "testuser",
              "https://example.com/callback", challenge, ImmutableSet.of("read"), 600);
      codeStore.store(code);

      Map<String, String> params = new HashMap<>();
      params.put("grant_type", "authorization_code");
      params.put("code", code.code);
      params.put("redirect_uri", "https://example.com/callback");
      params.put("client_id", "conf-client");
      params.put("code_verifier", verifier);

      // With correct Basic auth
      String credentials = java.util.Base64.getEncoder()
              .encodeToString("conf-client:client-secret-123".getBytes());

      TestHttpServletResponse response = new TestHttpServletResponse();
      endpoint.doPost(buildRequest(params, "Basic " + credentials), response);

      assertEquals(200, response.status);
   }

   @Test
   public void testConfidentialClientAuthFailure() throws Exception {
      AuthorizationCode code = AuthorizationCode.create("conf-client", "testuser",
              "https://example.com/callback", challenge, ImmutableSet.of("read"), 600);
      codeStore.store(code);

      Map<String, String> params = new HashMap<>();
      params.put("grant_type", "authorization_code");
      params.put("code", code.code);
      params.put("redirect_uri", "https://example.com/callback");
      params.put("client_id", "conf-client");
      params.put("code_verifier", verifier);

      // No auth header, no client_secret param
      TestHttpServletResponse response = new TestHttpServletResponse();
      endpoint.doPost(buildRequest(params, null), response);

      assertEquals(401, response.status);
      assertTrue(response.outputStream.toString().contains("invalid_client"));
   }

   @Test
   public void testRefreshToken() throws Exception {
      // First do a code exchange to get tokens
      AuthorizationCode code = AuthorizationCode.create("test-client", "testuser",
              "https://example.com/callback", challenge, ImmutableSet.of("read"), 600);
      codeStore.store(code);

      Map<String, String> params = new HashMap<>();
      params.put("grant_type", "authorization_code");
      params.put("code", code.code);
      params.put("redirect_uri", "https://example.com/callback");
      params.put("client_id", "test-client");
      params.put("code_verifier", verifier);

      TestHttpServletResponse response1 = new TestHttpServletResponse();
      endpoint.doPost(buildRequest(params, null), response1);
      Map<String, Object> json1 = parseJson(response1);
      String refreshToken = (String)json1.get("refresh_token");
      assertNotNull(refreshToken);

      // Now refresh
      Map<String, String> refreshParams = new HashMap<>();
      refreshParams.put("grant_type", "refresh_token");
      refreshParams.put("refresh_token", refreshToken);
      refreshParams.put("client_id", "test-client");

      TestHttpServletResponse response2 = new TestHttpServletResponse();
      endpoint.doPost(buildRequest(refreshParams, null), response2);

      assertEquals(200, response2.status);
      Map<String, Object> json2 = parseJson(response2);
      assertNotNull(json2.get("access_token"));
      assertNotNull(json2.get("refresh_token"));
      // New refresh token should be different (token rotation)
      assertNotEquals(refreshToken, json2.get("refresh_token"));
   }

   @Test
   public void testRefreshTokenRotation() throws Exception {
      // Create a refresh token directly
      OAuthRefreshToken rt = OAuthRefreshToken.create("test-client", "testuser",
              ImmutableSet.of("read"), 86400);
      tokenStore.storeRefreshToken(rt);

      Map<String, String> params = new HashMap<>();
      params.put("grant_type", "refresh_token");
      params.put("refresh_token", rt.token);
      params.put("client_id", "test-client");

      TestHttpServletResponse response = new TestHttpServletResponse();
      endpoint.doPost(buildRequest(params, null), response);

      assertEquals(200, response.status);

      // Old refresh token should be revoked
      assertFalse(tokenStore.resolveRefreshToken(rt.tokenHash).isPresent());
   }

   @Test
   public void testUnsupportedGrantType() throws Exception {
      Map<String, String> params = new HashMap<>();
      params.put("grant_type", "client_credentials");
      params.put("client_id", "test-client");

      TestHttpServletResponse response = new TestHttpServletResponse();
      endpoint.doPost(buildRequest(params, null), response);

      assertEquals(400, response.status);
      assertTrue(response.outputStream.toString().contains("unsupported_grant_type"));
   }

   @Test
   public void testRedirectUriMismatch() throws Exception {
      AuthorizationCode code = AuthorizationCode.create("test-client", "testuser",
              "https://example.com/callback", challenge, ImmutableSet.of("read"), 600);
      codeStore.store(code);

      Map<String, String> params = new HashMap<>();
      params.put("grant_type", "authorization_code");
      params.put("code", code.code);
      params.put("redirect_uri", "https://other.com/callback");
      params.put("client_id", "test-client");
      params.put("code_verifier", verifier);

      TestHttpServletResponse response = new TestHttpServletResponse();
      endpoint.doPost(buildRequest(params, null), response);

      assertEquals(400, response.status);
      assertTrue(response.outputStream.toString().contains("Redirect URI mismatch"));
   }

   private TestHttpServletRequest buildRequest(final Map<String, String> params, final String authHeader) {
      return new TestHttpServletRequest() {
         @Override
         public String getParameter(final String name) {
            return params.get(name);
         }
         @Override
         public String getHeader(final String name) {
            if("Authorization".equalsIgnoreCase(name)) {
               return authHeader;
            }
            return null;
         }
      };
   }

   @SuppressWarnings("unchecked")
   private Map<String, Object> parseJson(final TestHttpServletResponse response) {
      return GSON.fromJson(response.outputStream.toString(),
              new TypeToken<Map<String, Object>>(){}.getType());
   }
}
