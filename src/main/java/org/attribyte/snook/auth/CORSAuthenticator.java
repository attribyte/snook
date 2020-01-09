package org.attribyte.snook.auth;

import com.google.common.base.Joiner;
import com.google.common.base.MoreObjects;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.primitives.Ints;
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
      ALLOW_CREDENTIALS
   }

   /**
    * A property with a comma-separated list of hosts to allow ({@value}).
    */
   public static final String ALLOW_ORIGIN_HOST_PROP = "allowOriginHost";

   /**
    * A property with a comma-separated list of domains to allow ({@value}).
    */
   public static final String ALLOW_ORIGIN_DOMAIN_PROP = "allowOriginDomain";

   /**
    * A property with a comma-separated list of hosts to deny ({@value}).
    */
   public static final String DENY_ORIGIN_HOST_PROP = "denyOriginHost";

   /**
    * A property with a comma-separated list of domains to deny ({@value}).
    */
   public static final String DENY_ORIGIN_DOMAIN_PROP = "denyOriginDomain";

   /**
    * A property that indicates if a secure origin is required ({@value}).
    */
   public static final String REQUIRE_SECURE_ORIGIN_PROP = "requireSecureOrigin";

   /**
    * A property with a comma-separated list of hosts to allow ({@value}).
    */
   public static final String ALLOW_HEADERS_PROP = "allowHeaders";

   /**
    * A property with a comma-separated list of hosts to expose ({@value}).
    */
   public static final String EXPOSE_HEADERS_PROP = "exposeHeaders";

   /**
    * A property with a comma-separated list of methods to allow ({@value}). Default {@code OPTIONS, GET, POST}.
    */
   public static final String ALLOW_METHODS_PROP = "allowMethods";

   /**
    * A property that sets the maximum age of a pre-flight request in seconds. Default 86400. ({@value}).
    */
   public static final String MAX_AGE_PROP = "maxAge";

   /**
    * The access control allow origin header ({@value}).
    */
   public static final String ACCESS_CONTROL_ALLOW_ORIGIN_HEADER = "Access-Control-Allow-Origin";

   /**
    * The access control allow credentials header ({@value}).
    */
   public static final String ACCESS_CONTROL_ALLOW_CREDENTIALS_HEADER = "Access-Control-Allow-Credentials";

   /**
    * The access control allow headers header ({@value}).
    */
   public static final String ACCESS_CONTROL_ALLOW_HEADERS_HEADER = "Access-Control-Allow-Headers";

   /**
    * The access control expose headers header ({@value}).
    */
   public static final String ACCESS_CONTROL_EXPOSE_HEADERS_HEADER = "Access-Control-Expose-Headers";

   /**
    * The access control request headers header ({@value}).
    */
   public static final String ACCESS_CONTROL_REQUEST_HEADERS_HEADER = "Access-Control-Request-Headers";

   /**
    * The access control allow methods header ({@value}).
    */
   public static final String ACCESS_CONTROL_ALLOW_METHODS_HEADER = "Access-Control-Allow-Methods";

   /**
    * The access control max age header.
    */
   public static final String ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age";

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
              props.containsKey(REQUIRE_SECURE_ORIGIN_PROP) ||
              props.containsKey(ALLOW_HEADERS_PROP) ||
              props.containsKey(ALLOW_METHODS_PROP) ||
              props.containsKey(MAX_AGE_PROP)) {
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
              props.getProperty(REQUIRE_SECURE_ORIGIN_PROP, "").trim().equalsIgnoreCase("true"),
              props.getProperty(ALLOW_HEADERS_PROP, ""),
              props.getProperty(ALLOW_METHODS_PROP, "OPTIONS, GET, POST"),
              props.getProperty(MAX_AGE_PROP, "86400"),
              props.getProperty(EXPOSE_HEADERS_PROP, "")
      );
   }

   /**
    * Creates the origin auth.
    * @param denyDomain A set of domains to deny.
    * @param denyHost A set of hosts to deny.
    * @param allowDomain A set of domains to allow.
    * @param allowHost A set of hosts to allow.
    * @param secureOriginRequired Must the origin be secure?
    * @param allowHeaders A comma-separated list of headers to allow.
    * @param allowMethods A comma-separated list of methods to allow.
    * @param maxAgeSeconds The maximum age in seconds for pre-flight requests.
    * @param exposeHeaders A comma-separated list of headers to expose.
    */
   public CORSAuthenticator(final Collection<String> denyDomain, final Collection<String> denyHost,
                            final Collection<String> allowDomain, final Collection<String> allowHost,
                            final boolean secureOriginRequired,
                            final String allowHeaders,
                            final String allowMethods,
                            final String maxAgeSeconds,
                            final String exposeHeaders) {
      this.denyDomain = denyDomain == null ? ImmutableSet.of() : ImmutableSet.copyOf(denyDomain);
      this.denyHost = denyHost == null ? ImmutableSet.of() : ImmutableSet.copyOf(denyHost);
      this.allowDomain = allowDomain == null ? ImmutableSet.of() : ImmutableSet.copyOf(allowDomain);
      this.allowHost = allowHost == null ? ImmutableSet.of() : ImmutableSet.copyOf(allowHost);
      this.allowAll = this.allowHost.contains("*") || this.allowDomain.contains("*");
      this.secureOriginRequired = secureOriginRequired;
      this.allowHeaders = Strings.nullToEmpty(allowHeaders).trim();
      this.allowMethods = Strings.nullToEmpty(allowMethods).trim();
      Integer checkMaxAgeSeconds = Ints.tryParse(maxAgeSeconds);
      this.maxAgeSeconds = checkMaxAgeSeconds == null || checkMaxAgeSeconds < 1 ? "-1" : maxAgeSeconds;
      this.exposeHeaders = Strings.nullToEmpty(exposeHeaders).trim();
   }

   /**
    * Creates the origin auth.
    * @param denyDomain A set of domains to deny.
    * @param denyHost A set of hosts to deny.
    * @param allowDomain A set of domains to allow.
    * @param allowHost A set of hosts to allow.
    * @param allowAll Are all origins allowed?
    * @param secureOriginRequired Must the origin be secure?
    * @param allowHeaders A comma-separated list of headers to allow.
    * @param allowMethods A comma-separated list of methods to allow.
    * @param maxAgeSeconds The maximum age in seconds for pre-flight requests.
    * @param exposeHeaders A comma-separated list of headers to expose.
    */
   private CORSAuthenticator(final Collection<String> denyDomain, final Collection<String> denyHost,
                             final Collection<String> allowDomain, final Collection<String> allowHost,
                             final boolean allowAll,
                             final boolean secureOriginRequired,
                             final String allowHeaders,
                             final String allowMethods,
                             final String maxAgeSeconds,
                             final String exposeHeaders) {
      this.denyDomain = denyDomain == null ? ImmutableSet.of() : ImmutableSet.copyOf(denyDomain);
      this.denyHost = denyHost == null ? ImmutableSet.of() : ImmutableSet.copyOf(denyHost);
      this.allowDomain = allowDomain == null ? ImmutableSet.of() : ImmutableSet.copyOf(allowDomain);
      this.allowHost = allowHost == null ? ImmutableSet.of() : ImmutableSet.copyOf(allowHost);
      this.allowAll = allowAll;
      this.secureOriginRequired = secureOriginRequired;
      this.allowHeaders = Strings.nullToEmpty(allowHeaders).trim();
      this.allowMethods = Strings.nullToEmpty(allowMethods).trim();
      Integer checkMaxAgeSeconds = Ints.tryParse(maxAgeSeconds);
      this.maxAgeSeconds = checkMaxAgeSeconds == null || checkMaxAgeSeconds < 1 ? "-1" : maxAgeSeconds;
      this.exposeHeaders = Strings.nullToEmpty(exposeHeaders).trim();
   }

   /**
    * Adds a collection of exposed headers.
    * @param exposeHeaders The collection of headers.
    * @return A new authenticator.
    */
   public CORSAuthenticator withExposeHeaders(final Collection<String> exposeHeaders) {
      return withExposeHeaders(recordJoiner.join(exposeHeaders));
   }

   /**
    * Adds a comma-separated list of exposed headers.
    * @param exposeHeaders The list of headers.
    * @return A new authenticator.
    */
   public CORSAuthenticator withExposeHeaders(final String exposeHeaders) {
      return new CORSAuthenticator(denyDomain, denyHost, allowDomain, allowHost, allowAll,
              secureOriginRequired,
              allowHeaders, allowMethods, maxAgeSeconds, exposeHeaders);
   }


   /**
    * Adds a collection of allow headers.
    * @param allowHeaders The collection of headers.
    * @return A new authenticator.
    */
   public CORSAuthenticator withAllowHeaders(final Collection<String> allowHeaders) {
      return withAllowHeaders(recordJoiner.join(allowHeaders));
   }

   /**
    * Adds a comma-separated list of allow headers.
    * @param allowHeaders The list of headers.
    * @return A new authenticator.
    */
   public CORSAuthenticator withAllowHeaders(final String allowHeaders) {
      return new CORSAuthenticator(denyDomain, denyHost, allowDomain, allowHost, allowAll, secureOriginRequired,
              allowHeaders, allowMethods, maxAgeSeconds, exposeHeaders);
   }

   /**
    * Adds a collection of allow headers.
    * @param allowMethods The collection of headers.
    * @return A new authenticator.
    */
   public CORSAuthenticator withAllowMethods(final Collection<String> allowMethods) {
      return withAllowMethods(recordJoiner.join(allowMethods));
   }

   /**
    * Adds a comma-separated list of allow headers.
    * @param allowMethods The list of headers.
    * @return A new authenticator.
    */
   public CORSAuthenticator withAllowMethods(final String allowMethods) {
      return new CORSAuthenticator(denyDomain, denyHost, allowDomain, allowHost, allowAll, secureOriginRequired,
              allowHeaders, allowMethods, maxAgeSeconds, exposeHeaders);
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
   protected String scheme() {
      return null;
   }

   @Override
   public String schemeName() {
      return "CORS";
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
    * Authorize (or not) a CORS request. May be a "simple" request
    * or the response to a pre-flight request.
    * @param request The request.
    * @param response The response.
    * @param options The CORS options.
    * @return The authorized host or {@code null} if not authorized.
    */
   public String authorizeRequest(final HttpServletRequest request,
                                  final HttpServletResponse response,
                                  final Set<Option> options) {
      return authorize(request, response, options);
   }

   /**
    * Authorize (or not) a pre-flight request.
    * @param request The request.
    * @param response The response.
    * @param options The CORS options.
    * @return The authorized host or {@code null} if not authorized.
    */
   public String authorizePreFlightRequest(final HttpServletRequest request,
                                           final HttpServletResponse response,
                                           final Set<Option> options) {

      String authorizedUsername = authorize(request, response, options);
      if(authorizedUsername == null) {
         return null;
      }

      if(!allowMethods.isEmpty()) {
         response.setHeader(ACCESS_CONTROL_ALLOW_METHODS_HEADER, allowMethods);
      }

      if(!allowHeaders.isEmpty()) {
         response.setHeader(ACCESS_CONTROL_ALLOW_HEADERS_HEADER, allowHeaders);
      }

      response.setHeader(ACCESS_CONTROL_MAX_AGE, maxAgeSeconds);

      return authorizedUsername;
   }

   private String authorize(final HttpServletRequest request,
                            final HttpServletResponse response,
                            final Set<Option> options) {
      String authorizedUsername = authorizedUsername(request);
      if(authorizedUsername == null) {
         return null;
      } else {
         if(options.contains(Option.ALLOW_CREDENTIALS)) {
            /*
               When responding to a credentialed request, the server must specify an origin in the value of the
               Access-Control-Allow-Origin header, instead of specifying the "*" wildcard.
             */
            response.setHeader(ACCESS_CONTROL_ALLOW_ORIGIN_HEADER, origin(request));
            response.setHeader(ACCESS_CONTROL_ALLOW_CREDENTIALS_HEADER, "true");
         } else if(options.contains(Option.ALLOW_ANY_ORGIN)){
            response.setHeader(ACCESS_CONTROL_ALLOW_ORIGIN_HEADER, "*");
         } else {
            response.setHeader(ACCESS_CONTROL_ALLOW_ORIGIN_HEADER, origin(request));
         }

         if(!exposeHeaders.isEmpty()) {
            response.setHeader(ACCESS_CONTROL_EXPOSE_HEADERS_HEADER, exposeHeaders);
         }

         return authorizedUsername;
      }
   }

   /**
    * Gets the origin header value.
    * @param request The request.
    * @return The origin header value.
    */
   public String origin(final HttpServletRequest request) {
      return request.getHeader(HttpHeader.ORIGIN.name());
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("denyDomain", denyDomain)
              .add("denyHost", denyHost)
              .add("allowDomain", allowDomain)
              .add("allowHost", allowHost)
              .add("allowAll", allowAll)
              .add("secureOriginRequired", secureOriginRequired)
              .add("allowHeaders", allowHeaders)
              .add("exposeHeaders", exposeHeaders)
              .add("allowMethods", allowMethods)
              .add("maxAgeSeconds", maxAgeSeconds)
              .toString();
   }

   private final ImmutableSet<String> denyDomain;
   private final ImmutableSet<String> denyHost;
   private final ImmutableSet<String> allowDomain;
   private final ImmutableSet<String> allowHost;
   private final boolean allowAll;
   private final boolean secureOriginRequired;
   private final String allowHeaders;
   private final String exposeHeaders;
   private final String allowMethods;
   private final String maxAgeSeconds;
   private static Splitter recordSplitter = Splitter.on(',').trimResults().omitEmptyStrings();
   private static Joiner recordJoiner = Joiner.on(',').skipNulls();
}
