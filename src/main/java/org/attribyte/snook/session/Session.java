/*
 * Copyright 2018 Attribyte, LLC
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

package org.attribyte.snook.session;

import com.google.common.base.MoreObjects;
import com.google.common.collect.Maps;
import com.google.common.hash.HashCode;

import java.security.SecureRandom;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentMap;

/**
 * A thread-safe session.
 */
@SuppressWarnings("unchecked")
public class Session {

   /**
    * Creates an empty session with a random token.
    */
   public Session() {
      this(null);
   }

   /**
    * Creates a session a random token and data.
    * @param data The session data.
    */
   public Session(final Map<String, Object> data) {
      this(Session.randomToken(), data);
   }

   /**
    * Creates a session with a previously generated token and data.
    * @param token The token.
    * @param data The session data.
    */
   public Session(final HashCode token, final Map<String, Object> data) {
      this.token = token;
      this.createdMillis = System.currentTimeMillis();
      if(data != null) {
         this.data.putAll(data);
      }
   }

   /**
    * Gets a session value.
    * @param key The key.
    * @param <T> The expected return type.
    * @return The value, or {@code empty} if none.
    */
   public <T> Optional<T> get(final String key) {
      return Optional.ofNullable((T)data.get(key));
   }

   /**
    * Gets a session value or a default if none set.
    * @param key The key.
    * @param defaultValue The default value.
    * @param <T> The expected return type.
    * @return The session value or default value.
    */
   public <T> T get(final String key, final T defaultValue) {
      return (T)get(key).orElse(defaultValue);
   }

   /**
    * Puts a session value, replacing the existing, if any.
    * @param key The key.
    * @param value The value.
    * @param <T> The expected return type.
    * @return The previous value or {@code null} if none.
    */
   public <T> T put(final String key, Object value) {
      return (T)data.put(key, value);
   }

   /**
    * Removes a session value.
    * @param key The key.
    * @param <T> The expected return type.
    * @return The cleared value or {@code null} if none.
    */
   public <T> T remove(final String key) {
      return (T)data.remove(key);
   }

   /**
    * Clears all data.
    */
   public void clear() {
      data.clear();;
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("token", token)
              .add("createdMillis", createdMillis)
              .add("data", data)
              .toString();
   }

   /**
    * Generates a random token.
    * @return The token.
    */
   public static final HashCode randomToken() {
      byte[] tokenBytes = new byte[TOKEN_BYTES];
      rnd.nextBytes(tokenBytes);
      return HashCode.fromBytes(tokenBytes);
   }

   /**
    * The unique session token.
    */
   public final HashCode token;

   /**
    * The time the session was created.
    */
   public final long createdMillis;

   /**
    * The session data.
    */
   private final ConcurrentMap<String, Object> data = Maps.newConcurrentMap();

   /**
    * The secure random number generator.
    */
   private static final SecureRandom rnd = new SecureRandom();

   /**
    * The number of bytes in a token ({@value}).
    */
   public static final int TOKEN_BYTES = 16;
}
