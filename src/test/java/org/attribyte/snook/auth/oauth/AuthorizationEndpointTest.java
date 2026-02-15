package org.attribyte.snook.auth.oauth;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import org.attribyte.snook.auth.Authenticator;
import org.attribyte.snook.auth.oauth.model.OAuthClient;
import org.attribyte.snook.auth.oauth.store.InMemoryClientStore;
import org.attribyte.snook.auth.oauth.store.InMemoryCodeStore;
import org.attribyte.snook.test.TestHttpServletRequest;
import org.attribyte.snook.test.TestHttpServletResponse;
import org.junit.Before;
import org.junit.Test;

import jakarta.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class AuthorizationEndpointTest {

   private InMemoryClientStore clientStore;
   private InMemoryCodeStore codeStore;
   private AuthorizationEndpoint endpoint;
   private String challenge;

   @Before
   public void setUp() {
      clientStore = new InMemoryClientStore();
      codeStore = new InMemoryCodeStore();

      clientStore.register(OAuthClient.publicClient("test-client", "Test App",
              ImmutableList.of("https://example.com/callback"),
              ImmutableSet.of("read", "write")));

      // Authenticator that always returns "testuser"
      Authenticator<Boolean> userAuth = new Authenticator<Boolean>() {
         @Override public String credentials(HttpServletRequest request) { return "testuser"; }
         @Override public String authorizedUsername(HttpServletRequest request) { return "testuser"; }
         @Override public String schemeName() { return "Test"; }
         @Override public Boolean authorized(HttpServletRequest request) { return true; }
      };

      endpoint = new AuthorizationEndpoint(userAuth, clientStore, codeStore,
              new AutoApproveConsentHandler(), 600);

      String verifier = PKCE.generateVerifier();
      challenge = PKCE.computeChallenge(verifier);
   }

   @Test
   public void testValidAuthorizationRequest() throws Exception {
      Map<String, String> params = new HashMap<>();
      params.put("response_type", "code");
      params.put("client_id", "test-client");
      params.put("redirect_uri", "https://example.com/callback");
      params.put("scope", "read");
      params.put("state", "xyz");
      params.put("code_challenge", challenge);
      params.put("code_challenge_method", "S256");

      TestHttpServletRequest request = buildRequest(params);
      TestHttpServletResponse response = new TestHttpServletResponse();

      // AutoApproveConsentHandler will redirect to approve URL, which is a GET to the endpoint itself
      // In test, sendRedirect just stores the redirect location
      endpoint.doGet(request, response);

      // AutoApproveConsentHandler calls sendRedirect to the approve URL
      // TestHttpServletResponse sets status to SC_MOVED_PERMANENTLY
      assertEquals(301, response.status);
   }

   @Test
   public void testMissingClientId() throws Exception {
      Map<String, String> params = new HashMap<>();
      params.put("response_type", "code");
      params.put("redirect_uri", "https://example.com/callback");
      params.put("code_challenge", challenge);

      TestHttpServletRequest request = buildRequest(params);
      TestHttpServletResponse response = new TestHttpServletResponse();

      endpoint.doGet(request, response);

      assertEquals(400, response.status);
      String body = response.outputStream.toString();
      assertTrue(body.contains("invalid_request"));
   }

   @Test
   public void testUnknownClient() throws Exception {
      Map<String, String> params = new HashMap<>();
      params.put("response_type", "code");
      params.put("client_id", "unknown-client");
      params.put("redirect_uri", "https://example.com/callback");
      params.put("code_challenge", challenge);

      TestHttpServletRequest request = buildRequest(params);
      TestHttpServletResponse response = new TestHttpServletResponse();

      endpoint.doGet(request, response);

      assertEquals(400, response.status);
      String body = response.outputStream.toString();
      assertTrue(body.contains("invalid_client"));
   }

   @Test
   public void testInvalidRedirectUri() throws Exception {
      Map<String, String> params = new HashMap<>();
      params.put("response_type", "code");
      params.put("client_id", "test-client");
      params.put("redirect_uri", "https://evil.com/callback");
      params.put("code_challenge", challenge);

      TestHttpServletRequest request = buildRequest(params);
      TestHttpServletResponse response = new TestHttpServletResponse();

      endpoint.doGet(request, response);

      assertEquals(400, response.status);
      String body = response.outputStream.toString();
      assertTrue(body.contains("invalid_request"));
   }

   @Test
   public void testMissingCodeChallenge() throws Exception {
      Map<String, String> params = new HashMap<>();
      params.put("response_type", "code");
      params.put("client_id", "test-client");
      params.put("redirect_uri", "https://example.com/callback");

      TestHttpServletRequest request = buildRequest(params);
      TestHttpServletResponse response = new TestHttpServletResponse();

      endpoint.doGet(request, response);

      // Should redirect to callback with error
      assertEquals(301, response.status);
   }

   @Test
   public void testUnsupportedResponseType() throws Exception {
      Map<String, String> params = new HashMap<>();
      params.put("response_type", "token");
      params.put("client_id", "test-client");
      params.put("redirect_uri", "https://example.com/callback");
      params.put("code_challenge", challenge);

      TestHttpServletRequest request = buildRequest(params);
      TestHttpServletResponse response = new TestHttpServletResponse();

      endpoint.doGet(request, response);

      // Should redirect with error since redirect_uri is present
      assertEquals(301, response.status);
   }

   @Test
   public void testPostApproval() throws Exception {
      Map<String, String> params = new HashMap<>();
      params.put("client_id", "test-client");
      params.put("redirect_uri", "https://example.com/callback");
      params.put("scope", "read");
      params.put("state", "xyz");
      params.put("code_challenge", challenge);

      TestHttpServletRequest request = buildRequest(params);
      TestHttpServletResponse response = new TestHttpServletResponse();

      endpoint.doPost(request, response);

      // Should redirect to callback with code
      assertEquals(301, response.status);
   }

   @Test
   public void testUnauthenticatedUser() throws Exception {
      // Create endpoint with authenticator that returns null
      Authenticator<Boolean> noAuth = new Authenticator<Boolean>() {
         @Override public String credentials(HttpServletRequest request) { return null; }
         @Override public String authorizedUsername(HttpServletRequest request) { return null; }
         @Override public String schemeName() { return "Test"; }
         @Override public Boolean authorized(HttpServletRequest request) { return false; }
      };

      AuthorizationEndpoint noAuthEndpoint = new AuthorizationEndpoint(noAuth, clientStore, codeStore,
              new AutoApproveConsentHandler(), 600);

      Map<String, String> params = new HashMap<>();
      params.put("response_type", "code");
      params.put("client_id", "test-client");
      params.put("redirect_uri", "https://example.com/callback");
      params.put("code_challenge", challenge);

      TestHttpServletRequest request = buildRequest(params);
      TestHttpServletResponse response = new TestHttpServletResponse();

      noAuthEndpoint.doGet(request, response);

      // Should redirect with access_denied error
      assertEquals(301, response.status);
   }

   @Test
   public void testParseScopes() {
      assertEquals(ImmutableSet.of("read", "write"), AuthorizationEndpoint.parseScopes("read write"));
      assertEquals(ImmutableSet.of("read"), AuthorizationEndpoint.parseScopes("read"));
      assertEquals(ImmutableSet.of(), AuthorizationEndpoint.parseScopes(""));
      assertEquals(ImmutableSet.of(), AuthorizationEndpoint.parseScopes(null));
   }

   private TestHttpServletRequest buildRequest(final Map<String, String> params) {
      return new TestHttpServletRequest() {
         @Override
         public String getParameter(final String name) {
            return params.get(name);
         }
         @Override
         public StringBuffer getRequestURL() {
            return new StringBuffer("https://auth.example.com/oauth/authorize");
         }
         @Override
         public String getQueryString() {
            return null;
         }
      };
   }
}
