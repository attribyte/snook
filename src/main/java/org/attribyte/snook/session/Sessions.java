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

import com.codahale.metrics.Meter;
import com.codahale.metrics.Metric;
import com.codahale.metrics.MetricSet;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;
import com.google.common.hash.HashCode;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.attribyte.snook.Cookies;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.EnumSet;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Manages sessions.
 */
public abstract class Sessions implements MetricSet {

   /**
    * Creates a sessions store.
    * @param cookieKey The key for the session cookie.
    * @param cookieOptions The cookie options when setting the session cookie.
    * @param maxAgeSeconds The maximum cookie age in seconds.
    * @param cleanIntervalSeconds The cookie clean interval in seconds. If &lt; 1, no cleaning is scheduled.
    */
   protected Sessions(final Cookies.CookieKey cookieKey,
                      final EnumSet<Cookies.Option> cookieOptions,
                      final int maxAgeSeconds,
                      final int cleanIntervalSeconds) {
      this.cookieKey = cookieKey;
      this.cookieOptions = Sets.immutableEnumSet(cookieOptions);
      if(cleanIntervalSeconds > 0) {
         this.cleaningService =
                 MoreExecutors.getExitingScheduledExecutorService(new ScheduledThreadPoolExecutor(1,
                         new ThreadFactoryBuilder().setNameFormat("sessions-cleaner-%d").build()));
         this.cleaningService.scheduleAtFixedRate(() ->
                 expiredSessions.mark(clearExpired(maxAgeSeconds)), cleanIntervalSeconds, cleanIntervalSeconds, TimeUnit.SECONDS);
      } else {
         this.cleaningService = null;
      }
   }

   /**
    * Gets the session for a request.
    * @param req The request.
    * @return The session or {@code empty} if none.
    */
   public Optional<Session> session(final HttpServletRequest req) {
      sessionRequests.mark();
      String tokenStr = Strings.nullToEmpty(Cookies.cookieValue(cookieKey.name, req));
      return tokenStr.isEmpty() ? Optional.empty() : get(HashCode.fromString(tokenStr));
   }

   /**
    * Gets the session for a request. If none, creates a new (empty) session and sets a
    * response cookie for the session.
    * @param req The request.
    * @param resp The response.
    * @return The existing or new session.
    */
   public Session sessionOrNew(final HttpServletRequest req, final HttpServletResponse resp) {
      return sessionOrNew(req, null, resp);
   }

   /**
    * Gets the session for a request. If none, creates a new session with data and sets a
    * response cookie for the session.
    * @param req The request.
    * @param data Session data.
    * @param resp The response.
    * @return The existing or new session.
    */
   public Session sessionOrNew(final HttpServletRequest req, final Map<String, Object> data,
                               final HttpServletResponse resp) {
      sessionRequests.mark();
      String tokenStr = Strings.nullToEmpty(Cookies.cookieValue(cookieKey.name, req));
      Optional<Session> maybeSession = tokenStr.isEmpty() ? Optional.empty() : get(HashCode.fromString(tokenStr));
      if(!maybeSession.isPresent()) {
         Session session = new Session(data);
         if(save(session)) {
            newSessions.mark();
            Cookies.setSessionCookie(cookieKey, session.token.toString(), Sets.newEnumSet(cookieOptions, Cookies.Option.class), resp);
         } else {
            failedSaves.mark();
         }
         return session;
      } else {
         return maybeSession.get();
      }
   }

   /**
    * Shutdown sessions.
    */
   public void shutdown() {
      if(cleaningService != null) {
         cleaningService.shutdownNow();
      }
   }

   /**
    * Gets a session for a token.
    * @param token The token.
    * @return The session or {@code empty} if none.
    */
   protected abstract Optional<Session> get(final HashCode token);

   /**
    * Saves a session.
    * @param session The session.
    * @return Was the session saved?
    */
   protected abstract boolean save(final Session session);

   /**
    * Clear expired tokens.
    * @param maxAgeSeconds The maximum session age in seconds.
    * @return The number of expired tokens.
    */
   protected abstract int clearExpired(final int maxAgeSeconds);

   /**
    * The session cookie key.
    */
   public final Cookies.CookieKey cookieKey;

   /**
    * The cookie options.
    */
   public final ImmutableSet<Cookies.Option> cookieOptions;

   @Override
   public final Map<String, Metric> getMetrics() {
      return ImmutableMap.of(
              "requests", sessionRequests,
              "expired", expiredSessions,
              "new", newSessions,
              "failed-save", failedSaves
      );
   }

   /**
    * Periodically cleans cookies.
    */
   private final ScheduledExecutorService cleaningService;

   /**
    * Meter for session save failures.
    */
   private final Meter failedSaves = new Meter();

   /**
    * Meter for new sessions.
    */
   private final Meter newSessions = new Meter();

   /**
    * Meter for session requests.
    */
   private final Meter sessionRequests = new Meter();

   /**
    * Meter for expired cookies.
    */
   private final Meter expiredSessions = new Meter();
}