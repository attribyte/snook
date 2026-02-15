package org.attribyte.snook.auth.oauth;

import org.attribyte.snook.test.TestHttpServletResponse;
import org.junit.Test;

import static org.junit.Assert.*;

public class OAuthErrorTest {

   @Test
   public void testWriteJsonError() throws Exception {
      TestHttpServletResponse response = new TestHttpServletResponse();
      OAuthError.writeJsonError(response, 400, OAuthError.INVALID_REQUEST, "Missing required parameter");
      assertEquals(400, response.status);
      assertEquals("application/json;charset=UTF-8", response.getContentType());
      assertEquals("no-store", response.getHeader("Cache-Control"));
      String body = response.outputStream.toString();
      assertTrue(body.contains("\"error\":\"invalid_request\""));
      assertTrue(body.contains("\"error_description\":\"Missing required parameter\""));
   }

   @Test
   public void testWriteJsonErrorNoDescription() throws Exception {
      TestHttpServletResponse response = new TestHttpServletResponse();
      OAuthError.writeJsonError(response, 401, OAuthError.INVALID_CLIENT, null);
      String body = response.outputStream.toString();
      assertTrue(body.contains("\"error\":\"invalid_client\""));
      assertFalse(body.contains("error_description"));
   }

   @Test
   public void testErrorRedirectUrl() {
      String url = OAuthError.errorRedirectUrl(
              "https://example.com/callback",
              OAuthError.ACCESS_DENIED,
              "User denied",
              "xyz123"
      );
      assertTrue(url.startsWith("https://example.com/callback?"));
      assertTrue(url.contains("error=access_denied"));
      assertTrue(url.contains("error_description=User+denied"));
      assertTrue(url.contains("state=xyz123"));
   }

   @Test
   public void testErrorRedirectUrlNoState() {
      String url = OAuthError.errorRedirectUrl(
              "https://example.com/callback",
              OAuthError.INVALID_REQUEST,
              "Bad request",
              null
      );
      assertTrue(url.contains("error=invalid_request"));
      assertFalse(url.contains("state="));
   }

   @Test
   public void testErrorRedirectUrlWithExistingQueryParams() {
      String url = OAuthError.errorRedirectUrl(
              "https://example.com/callback?foo=bar",
              OAuthError.SERVER_ERROR,
              null,
              "state1"
      );
      assertTrue(url.contains("callback?foo=bar&error=server_error"));
   }

   @Test
   public void testErrorConstants() {
      assertEquals("invalid_request", OAuthError.INVALID_REQUEST);
      assertEquals("invalid_client", OAuthError.INVALID_CLIENT);
      assertEquals("invalid_grant", OAuthError.INVALID_GRANT);
      assertEquals("unauthorized_client", OAuthError.UNAUTHORIZED_CLIENT);
      assertEquals("unsupported_grant_type", OAuthError.UNSUPPORTED_GRANT_TYPE);
      assertEquals("invalid_scope", OAuthError.INVALID_SCOPE);
      assertEquals("unsupported_response_type", OAuthError.UNSUPPORTED_RESPONSE_TYPE);
      assertEquals("server_error", OAuthError.SERVER_ERROR);
      assertEquals("temporarily_unavailable", OAuthError.TEMPORARILY_UNAVAILABLE);
      assertEquals("access_denied", OAuthError.ACCESS_DENIED);
   }
}
