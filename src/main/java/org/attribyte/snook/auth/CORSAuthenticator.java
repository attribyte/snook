package org.attribyte.snook.auth;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import org.eclipse.jetty.http.HttpHeader;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

import static org.attribyte.snook.Util.domain;
import static org.attribyte.snook.Util.host;

/**
 * An authenticator for {@code CORS} (the {@code Origin} header value)
 * that returns the authorized host as the username, if authorized.
 */
public class CORSAuthenticator extends Authenticator {

   /**
    * CORS options.
    */
   public enum Option {

      /**
       * Is any origin allowed?
       */
      ALLOW_ANY_ORGIN,

      /**
       * Are credentials allowed?
       */
      ALLOW_CREDENTIALS;
   }

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
    * A property name that indicates if a secure origin is required ({@value}).
    */
   public static final String REQUIRE_SECURE_ORIGIN = "requireSecureOrigin";

   /**
    * The access control allow origin header ({@value}).
    */
   public static final String ACCESS_CONTROL_ALLOW_ORIGIN_HEADER = "Access-Control-Allow-Origin";

   /**
    * The access control allow credentials header ({@value}).
    */
   public static final String ACCESS_CONTROL_ALLOW_CREDENTIALS_HEADER = "Access-Control-Allow-Credentials";

   /**
    * Creates an authenticator from properties, if configured.
    * @param props The properties.
    * @return The optional authenticator.
    */
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
    * @return The host of the allowed origin or {@code null} if not allowed.
    */
   public final String allowed(final String origin) {

      if(secureOriginRequired && !isSecureOrigin(origin)) {
         return null;
      }

      if(Strings.nullToEmpty(origin).isEmpty()) {
         return allowAll ? "" : null;
      }

      final String domain = domain(origin);
      if(domain == null) {
         return null;
      } else if(denyDomain.contains(domain)) {
         return null;
      }

      final String host = host(origin);

      if(host == null) {
         return null;
      } else if(denyHost.contains(host)) {
         return null;
      }

      return (allowDomain.contains(domain) || allowHost.contains(host) || allowAll) ?
              host : null;
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
      return allowed(origin(request)) != null;
   }

   @Override
   public String authorizedUsername(final HttpServletRequest request) {
      return allowed(origin(request));
   }

   /**
    * Determine if a simple CORS request is allowed, set the response
    * headers and return the authorized host.
    * @param request The request.
    * @param response The response.
    * @param options The CORS options.
    * @return The authorized host or {@code null} if not authorized.
    */
   public String authorizeSimpleRequest(final HttpServletRequest request,
                                        final HttpServletResponse response,
                                        final Set<Option> options) {
      String authorizedUsername = authorizedUsername(request);
      if(authorizedUsername == null) {
         return null;
      } else {
         if(options.contains(Option.ALLOW_CREDENTIALS)) {
            response.setHeader(ACCESS_CONTROL_ALLOW_ORIGIN_HEADER, origin(request));
            response.setHeader(ACCESS_CONTROL_ALLOW_CREDENTIALS_HEADER, "true");
         } else if(options.contains(Option.ALLOW_ANY_ORGIN)){
            response.setHeader(ACCESS_CONTROL_ALLOW_ORIGIN_HEADER, "*");
         } else {
            response.setHeader(ACCESS_CONTROL_ALLOW_ORIGIN_HEADER, origin(request));
         }

         return authorizedUsername;
      }
   }

   /**
    * Gets the origin header value.
    * @param request The request.
    * @return The origin header value.
    */
   private String origin(final HttpServletRequest request) {
      return request.getHeader(HttpHeader.ORIGIN.name());
   }

   private final ImmutableSet<String> denyDomain;
   private final ImmutableSet<String> denyHost;
   private final ImmutableSet<String> allowDomain;
   private final ImmutableSet<String> allowHost;
   private final boolean allowAll;
   private final boolean secureOriginRequired;
   private static Splitter recordSplitter = Splitter.on(',').trimResults().omitEmptyStrings();
}