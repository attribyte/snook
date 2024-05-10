package org.attribyte.snook.auth.webauthn;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.yubico.webauthn.data.ByteArray;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.security.SecureRandom;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.attribyte.snook.auth.webauthn.Util.randomBytes;

public class Sessions {

   public Sessions(final int maxSessions,
                   final int expireTimeMinutes) {
      idsForUsers =
              CacheBuilder.newBuilder()
                      .maximumSize(maxSessions)
                      .expireAfterAccess(expireTimeMinutes, TimeUnit.MINUTES)
                      .build();
      usersForIds =
              CacheBuilder.newBuilder()
                      .maximumSize(maxSessions)
                      .expireAfterAccess(expireTimeMinutes, TimeUnit.MINUTES)
                      .build();
   }

   /**
    * {@value }
    */
   public static final int SESSION_ID_LENGTH = 32;

   /**
    * @return A new session id.
    */
   private final ByteArray newSessionId() {
      return randomBytes(SESSION_ID_LENGTH);
   }

   /**
    * @return Create a new session for the given user, or return the existing one.
    */
   public ByteArray createSession(@NonNull ByteArray userHandle) throws ExecutionException {
      ByteArray sessionId = usersForIds.get(userHandle, this::newSessionId);
      idsForUsers.put(sessionId, userHandle);
      return sessionId;
   }

   /**
    * Get the session id for a user.
    * @return The user handle of the given session, if any.
    */
   public ByteArray getSession(@NonNull ByteArray token) {
      return idsForUsers.getIfPresent(token);
   }

   /**
    * Check the session for a user.
    * @param claimedUserHandle The user handle.
    * @param token The token.
    * @return Is this the session for the user?
    */
   public boolean isSessionForUser(@NonNull ByteArray claimedUserHandle,
                                   @Nullable ByteArray token) {
      return token != null && claimedUserHandle.equals(getSession(token));
   }

   /**
    * The secure random number generator.
    */
   private final SecureRandom random = new SecureRandom();
   private final Cache<ByteArray, ByteArray> idsForUsers;
   private final Cache<ByteArray, ByteArray> usersForIds;
}
