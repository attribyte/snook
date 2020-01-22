/*
 * Copyright 2020 Attribyte, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

package org.attribyte.snook.auth;

import com.google.common.base.CharMatcher;
import com.google.common.base.Charsets;
import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.base.Splitter;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.io.BaseEncoding;
import com.google.common.primitives.Ints;

import java.util.Date;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;

public class HMACToken {

   /**
    * Validate a cookie value and create a token only if valid.
    * @param cookieValue The cookie value.
    * @param hmacFunction The (keyed) HMAC function.
    * @return The token or {@code null} if invalid.
    */
   public static HMACToken validate(final String cookieValue, final HashFunction hmacFunction) {

      if(cookieValue.length() < ENCODED_HMAC_SIZE) {
         return null;
      }

      HashCode sentCode = HashCode.fromBytes(BASE_64_ENCODING.decode(cookieValue.substring(0, 43)));
      String tokenValue = cookieValue.substring(ENCODED_HMAC_SIZE);
      HashCode expectedCode = hmacFunction.hashString(tokenValue, Charsets.UTF_8);
      if(!sentCode.equals(expectedCode)) {
         return null;
      }

      Iterator<String> iter = tokenSplitter.split(tokenValue).iterator();
      if(!iter.hasNext()) {
         return null;
      }

      Integer expireTimestamp = Ints.tryParse(iter.next());
      if(expireTimestamp == null) {
         return null;
      }

      if(!iter.hasNext()) {
         return null;
      }

      return new HMACToken(iter.next(), expireTimestamp);
   }

   /**
    * Creates a token with a lifetime.
    * @param username The username.
    * @param lifetime The lifetime.
    * @param lifetimeUnits The lifetime units.
    */
   public HMACToken(final String username,
                    final int lifetime,
                    final TimeUnit lifetimeUnits) {

      if(username == null) {
         throw new UnsupportedOperationException("The 'username' must not be null");
      }

      if(CharMatcher.whitespace().matchesAllOf(username)) {
         throw new UnsupportedOperationException("The 'username' must not be non-empty");
      }

      if(lifetime < 1) {
         throw new UnsupportedOperationException("The 'lifetime' must be > 0");
      }

      long lifeMillis = TimeUnit.MILLISECONDS.convert(lifetime, lifetimeUnits);
      this.username = username;
      this.expireTimestampSeconds = (int)(System.currentTimeMillis() + lifeMillis);
   }

   /**
    * Creates a token with an expire time in seconds.
    * @param username The username.
    * @param expireTimestampSeconds The expire time in seconds.
    */
   HMACToken(final String username,
             final int expireTimestampSeconds) {
      this.username = username;
      this.expireTimestampSeconds = expireTimestampSeconds;
   }

   /**
    * Generate the cookie value for this token.
    * @param hmacFunction The HMAC function.
    * @return The cookie value.
    */
   public String toCookieValue(final HashFunction hmacFunction) {
      String tokenValue = expireTimestampSeconds + "," + username;
      HashCode hmac = hmacFunction.hashString(tokenValue, Charsets.UTF_8);
      return BASE_64_ENCODING.encode(hmac.asBytes()) + tokenValue;
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("username", username)
              .add("expireTimestampSeconds", expireTimestampSeconds)
              .add("expires", new Date(expireTimestampSeconds * 1000L))
              .toString();
   }

   @Override
   public boolean equals(final Object o) {
      if(this == o) return true;
      if(o == null || getClass() != o.getClass()) return false;
      final HMACToken hmacToken = (HMACToken)o;
      return expireTimestampSeconds == hmacToken.expireTimestampSeconds &&
              Objects.equal(username, hmacToken.username);
   }

   @Override
   public int hashCode() {
      return Objects.hashCode(username, expireTimestampSeconds);
   }

   /**
    * The username.
    */
   public final String username;

   /**
    * The expiration timestamp.
    */
   public final int expireTimestampSeconds;

   /**
    * @return Is this token expired?
    */
   public final boolean isExpired() {
      return (expireTimestampSeconds * 1000L) < System.currentTimeMillis();
   }

   /**
    * The encoding to encode/decode the HMAC.
    */
   private static final BaseEncoding BASE_64_ENCODING = BaseEncoding.base64().omitPadding();

   /**
    * The size (in characters) of the encoded HMAC.
    */
   private static final int ENCODED_HMAC_SIZE = 43;

   /**
    * The token splitter.
    */
   private static Splitter tokenSplitter = Splitter.on(',').limit(2);
}