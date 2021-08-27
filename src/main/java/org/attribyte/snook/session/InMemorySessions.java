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

import com.google.common.collect.Maps;
import com.google.common.hash.HashCode;
import org.attribyte.snook.Cookies;

import java.util.Collection;
import java.util.EnumSet;
import java.util.Optional;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;

/**
 * Sessions stored only in-memory.
 */
public class InMemorySessions extends Sessions {

   /**
    * Creates an in-memory session store with a specific same-site option.
    * @param cookieKey The key for the session cookie.
    * @param cookieOptions The cookie options when setting the session cookie.
    * @param sameSiteOption The same-site option for the session cookie.
    * @param maxAgeSeconds The maximum cookie age in seconds.
    * @param cleanIntervalSeconds The cookie clean interval in seconds. If &lt; 1, no cleaning is scheduled.
    */
   public InMemorySessions(final Cookies.CookieKey cookieKey,
                           final EnumSet<Cookies.Option> cookieOptions,
                           final Cookies.SameSiteOption sameSiteOption,
                           final int maxAgeSeconds,
                           final int cleanIntervalSeconds) {
      super(cookieKey, cookieOptions, sameSiteOption, maxAgeSeconds, cleanIntervalSeconds);
   }

   /**
    * Creates an in-memory session store with the default same-site option.
    * @param cookieKey The key for the session cookie.
    * @param cookieOptions The cookie options when setting the session cookie.
    * @param maxAgeSeconds The maximum cookie age in seconds.
    * @param cleanIntervalSeconds The cookie clean interval in seconds. If &lt; 1, no cleaning is scheduled.
    */
   public InMemorySessions(final Cookies.CookieKey cookieKey,
                           final EnumSet<Cookies.Option> cookieOptions,
                           final int maxAgeSeconds,
                           final int cleanIntervalSeconds) {
      super(cookieKey, cookieOptions, Sessions.DEFAULT_SAME_SITE_OPTION, maxAgeSeconds, cleanIntervalSeconds);
   }

   @Override
   protected Optional<Session> get(final HashCode token) {
      return Optional.ofNullable(sessions.get(token));
   }

   @Override
   protected boolean save(final Session session) {
      sessions.put(session.token, session);
      return true;
   }

   @Override
   protected int clearExpired(final int maxAgeSeconds) {
      final long minCreatedMillis = System.currentTimeMillis() - maxAgeSeconds * 1000L;
      Collection<HashCode> expired =
              sessions.values()
                      .stream()
                      .filter(session -> session.createdMillis < minCreatedMillis)
                      .map(session -> session.token)
                      .collect(Collectors.toList());
      expired.forEach(sessions::remove);
      return expired.size();
   }

   /**
    * The concurrent map for sessions.
    */
   private final ConcurrentMap<HashCode, Session> sessions = Maps.newConcurrentMap();
}
