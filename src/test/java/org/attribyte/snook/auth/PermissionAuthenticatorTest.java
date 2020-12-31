package org.attribyte.snook.auth;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableSet;
import org.attribyte.snook.test.TestHttpServletRequest;
import org.eclipse.jetty.http.HttpHeader;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;

import java.util.Set;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class PermissionAuthenticatorTest {

   static final HeaderAuthenticator<Boolean> basicAuthenticator = BasicAuthenticator.booleanAuthenticator(ImmutableSet.of(
           Authenticator.hashCredentials(BasicAuthenticator.buildCredentials("test_user", "test_password"))
   ), s -> null);

   @Test
   public void testAuthorized() {

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_password".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      PermissionAuthenticator permissionAuthenticator = new PermissionAuthenticator(basicAuthenticator) {
         @Override
         protected Set<Permission> authenticatedPermission(final String username, final String context) {
            return Permission.READ_WRITE;
         }
      };

      Set<Permission> permissions = permissionAuthenticator.permission(request, "");
      assertNotNull(permissions);
      assertTrue(permissions.contains(Permission.READ));
      assertTrue(permissions.contains(Permission.CREATE));
      assertTrue(permissions.contains(Permission.UPDATE));
      assertTrue(permissions.contains(Permission.DELETE));
   }

   @Test
   public void testUnauthorized() {

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_passwordx".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      PermissionAuthenticator permissionAuthenticator = new PermissionAuthenticator(basicAuthenticator) {
         @Override
         protected Set<Permission> authenticatedPermission(final String username, final String context) {
            return Permission.READ_WRITE;
         }
      };

      Set<Permission> permissions = permissionAuthenticator.permission(request, "");
      assertNotNull(permissions);
      assertTrue(permissions.isEmpty());
   }

   @Test
   public void testUnauthorizedOverride() {

      HttpServletRequest request = new TestHttpServletRequest() {
         @Override
         public String getHeader(final String s) {
            return s.equalsIgnoreCase(HttpHeader.AUTHORIZATION.asString()) ?
                    "Basic " + HeaderAuthenticator.base64Encoding.encode("test_user:test_passwordx".getBytes(Charsets.UTF_8))
                    : null;
         }
      };

      PermissionAuthenticator permissionAuthenticator = new PermissionAuthenticator(basicAuthenticator) {
         @Override
         protected Set<Permission> authenticatedPermission(final String username, final String context) {
            return Permission.READ_WRITE;
         }

         @Override
         protected Set<Permission> unauthenticatedPermission(final String context) {
            return Permission.READ_ONLY;
         }
      };

      Set<Permission> permissions = permissionAuthenticator.permission(request, "");
      assertNotNull(permissions);
      assertEquals(1, permissions.size());
      assertTrue(permissions.contains(Permission.READ));
   }
}
