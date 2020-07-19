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

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.net.HostAndPort;

import java.net.URI;

/**
 * An immutable origin for a request.
 */
public class Origin {

   /**
    * The empty origin.
    */
   public static final Origin EMPTY = new Origin((HostAndPort)null, false);

   /**
    * Creates an origin from a string that must be a valid URI.
    * @param str A valid URI as a string.
    * @throws IllegalArgumentException if string is not a valid URI.
    */
   public Origin(final String str) {
      this(URI.create(str));
   }

   /**
    * Creates an origin from a parsed URI.
    * @param uri The URI.
    */
   public Origin(final URI uri) {
      this(HostAndPort.fromParts(
              preconditions(uri).getHost(), port(uri)),
              uri.getScheme() != null &&
                      (uri.getScheme().equalsIgnoreCase("https") ||
                       uri.getScheme().equalsIgnoreCase("wss"))
      );
   }

   private static URI preconditions(final URI uri) throws IllegalArgumentException {
      Preconditions.checkNotNull(uri);
      switch(Strings.nullToEmpty(uri.getScheme()).toLowerCase()) {
         case "http":
         case "https":
         case "ws":
         case "wss":
            break;
         default:
            throw new IllegalArgumentException("Scheme must be 'http', 'https', 'ws' or 'wss;");
      }
      Preconditions.checkArgument(!Strings.isNullOrEmpty(uri.getHost()), "URI must have a 'host'");
      return uri;
   }

   /**
    * Gets the port for a URI.
    * @param uri The URI.
    * @return The port or {@code -1}.
    */
   private static int port(final URI uri) {
      int port = uri.getPort();
      if(port > 0) {
         return port;
      }

      switch(Strings.nullToEmpty(uri.getScheme())) {
         case "http":
         case "ws":
            return 80;
         case "https":
         case "wss":
            return 443;
         default:
            return -1;
      }
   }

   /**
    * Create from a parsed host and port.
    * @param hostAndPort The host and port.
    * @param isSecure Is the host secure?
    */
   Origin(final HostAndPort hostAndPort, final boolean isSecure) {
      this.hostAndPort = hostAndPort;
      this.isSecure = isSecure;
   }

   /**
    * The host or an empty string if {@code EMPTY}.
    * @return The host or an empty string.
    */
   public final String host() {
      return hostAndPort != null ? hostAndPort.getHost() : "";
   }

   /**
    * @return The port or {@code -1}.
    */
   public final int port() {
      return hostAndPort != null ? hostAndPort.getPort() : 0;
   }

   /**
    * @return Is the origin secure (https)?
    */
   public final boolean isSecure() {
      return isSecure;
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("host", host())
              .add("port", port())
              .add("isSecure", isSecure)
              .toString();
   }

   @Override
   public boolean equals(final Object o) {
      if(this == o) return true;
      if(o == null || getClass() != o.getClass()) return false;
      final Origin origin = (Origin)o;
      return Objects.equal(hostAndPort, origin.hostAndPort);
   }

   @Override
   public int hashCode() {
      return Objects.hashCode(hostAndPort);
   }

   /**
    * The host and port.
    */
   private final HostAndPort hostAndPort;

   /**
    * Is the origin secure?
    */
   private final boolean isSecure;
}
