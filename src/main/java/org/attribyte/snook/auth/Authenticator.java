package org.attribyte.snook.auth;

import java.nio.charset.StandardCharsets;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;

import jakarta.servlet.http.HttpServletRequest;

public interface Authenticator<T> {

   /**
    * Gets the credentials from the request.
    * @param request The request.
    * @return The credentials, or {@code null} if none.
    */
   public String credentials(final HttpServletRequest request);

   /**
    * Gets the authorized username.
    * @param request The request.
    * @return The authorized username or {@code null} if not authorized.
    */
   public String authorizedUsername(final HttpServletRequest request);

   /**
    * The authentication scheme name.
    * @return The scheme name.
    */
   public String schemeName();

   /**
    * Determine if a request is authorized.
    * @param request The request.
    * @return Non-null if the request is authorized.
    */
   public T authorized(final HttpServletRequest request);

   /**
    * The default hash function for credentials.
    */
   static final HashFunction credentialHasher = Hashing.sha256();

   /**
    * Base64 encoding.
    */
   static final BaseEncoding base64Encoding = BaseEncoding.base64();

   /**
    * Securely hash the credentials.
    * Note that Guava {@code HashCode} is implemented with constant-time equals.
    * @param credentials The credentials.
    * @return The hash code.
    */
   public static HashCode hashCredentials(final String credentials) {
      return credentialHasher.hashString(credentials, StandardCharsets.UTF_8);
   }
}
