package org.attribyte.snook.auth;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Optional;
import java.util.Properties;

import static org.attribyte.snook.Util.domain;
import static org.attribyte.snook.Util.host;

public class CORSAuthenticator extends Authenticator {

   /**
    * A property name that for a comma-separated list of hosts to allow ({@value}).
    */
   public static final String ALLOW_ORIGIN_HOST_PROP = "allowOriginHost";

   /**
    * A property name that for a comma-separated list of domains to allow ({@value}).
    */
   public static final String ALLOW_ORIGIN_DOMAIN_PROP = "allowOriginDomain";

   /**
    * A property name that for a comma-separated list of hosts to deny ({@value}).
    */
   public static final String DENY_ORIGIN_HOST_PROP = "denyOriginHost";

   /**
    * A property name that for a comma-separated list of domains to deny ({@value}).
    */
   public static final String DENY_ORIGIN_DOMAIN_PROP = "denyOriginDomain";

   /**
    * A property name that indicates if a secure orgin is required ({@value}).
    */
   public static final String REQUIRE_SECURE_ORIGIN = "requireSecureOrigin";

   public static Optional<CORSAuthenticator> fromProperties(final Properties props) {
      if(props.containsKey(ALLOW_ORIGIN_HOST_PROP) ||
              props.containsKey(ALLOW_ORIGIN_DOMAIN_PROP) ||
              props.containsKey(DENY_ORIGIN_HOST_PROP) ||
              props.containsKey(DENY_ORIGIN_DOMAIN_PROP) ||
              props.containsKey(REQUIRE_SECURE_ORIGIN)) {
         return Optional.of(new CORSAuthenticator(props));
      } else {
         return Optional.empty();
      }
   }

   /**
    * Creates origin auth from properties.
    * @param props The properties.
    */
   public CORSAuthenticator(final Properties props) {
      this(
              ImmutableSet.copyOf(recordSplitter.split(props.getProperty(DENY_ORIGIN_DOMAIN_PROP, ""))),
              ImmutableSet.copyOf(recordSplitter.split(props.getProperty(DENY_ORIGIN_HOST_PROP, ""))),
              ImmutableSet.copyOf(recordSplitter.split(props.getProperty(ALLOW_ORIGIN_DOMAIN_PROP, ""))),
              ImmutableSet.copyOf(recordSplitter.split(props.getProperty(ALLOW_ORIGIN_HOST_PROP, ""))),
              Strings.nullToEmpty(props.getProperty(REQUIRE_SECURE_ORIGIN)).trim().equalsIgnoreCase("true")
      );
   }

   /**
    * Creates the origin auth.
    * @param denyDomain A set of domains to deny.
    * @param denyHost A set of hosts to deny.
    * @param allowDomain A set of domains to allow.
    * @param allowHost A set of hosts to allow.
    * @param secureOriginRequired Must the origin be secure?
    */
   public CORSAuthenticator(final Collection<String> denyDomain, final Collection<String> denyHost,
                            final Collection<String> allowDomain, final Collection<String> allowHost,
                            final boolean secureOriginRequired) {
      this.denyDomain = denyDomain == null ? ImmutableSet.of() : ImmutableSet.copyOf(denyDomain);
      this.denyHost = denyHost == null ? ImmutableSet.of() : ImmutableSet.copyOf(denyHost);
      this.allowDomain = allowDomain == null ? ImmutableSet.of() : ImmutableSet.copyOf(allowDomain);
      this.allowHost = allowHost == null ? ImmutableSet.of() : ImmutableSet.copyOf(allowHost);
      this.allowAll = this.allowHost.contains("*") || this.allowDomain.contains("*");
      this.secureOriginRequired = secureOriginRequired;
   }

   /**
    * Determine if an origin is allowed.
    * @param origin The origin.
    * @return Is the origin allowed?
    */
   public final boolean allowed(final String origin) {

      if(secureOriginRequired && !isSecureOrigin(origin)) {
         return false;
      }

      if(Strings.nullToEmpty(origin).isEmpty()) {
         return allowAll;
      }

      final String domain = domain(origin);
      if(domain == null) {
         return allowAll;
      } else if(denyDomain.contains(domain)) {
         return false;
      }

      final String host = host(origin);

      if(host == null) {
         return allowAll;
      } else if(denyHost.contains(host)) {
         return false;
      }

      return allowDomain.contains(domain) || allowHost.contains(host) || allowAll;
   }

   /**
    * Does the origin appear to be secure?
    * @param origin The origin.
    * @return Is the origin secure?
    */
   private boolean isSecureOrigin(final String origin) {
      return Strings.nullToEmpty(origin).trim().toLowerCase().startsWith("https://");
   }

   @Override
   public String scheme() {
      return "Origin";
   }

   @Override
   public boolean authorized(final HttpServletRequest request) {
      return false;
   }

   @Override
   public String authorizedUsername(final HttpServletRequest request) {
      return authorized(request) ? "" : null;
   }

   private final ImmutableSet<String> denyDomain;
   private final ImmutableSet<String> denyHost;
   private final ImmutableSet<String> allowDomain;
   private final ImmutableSet<String> allowHost;
   private final boolean allowAll;
   private final boolean secureOriginRequired;
   private static Splitter recordSplitter = Splitter.on(',').trimResults().omitEmptyStrings();
}