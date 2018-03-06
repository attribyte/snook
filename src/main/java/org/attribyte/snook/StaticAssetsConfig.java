package org.attribyte.snook;

import org.attribyte.api.InitializationException;
import org.attribyte.util.InitUtil;

import java.util.Properties;

/**
 * Configuration for a servlet that handles static files.
 */
public class StaticAssetsConfig {

   /**
    * Creates the default configuration.
    * @param resourceDirectory The directory containing static resources.
    */
   public StaticAssetsConfig(final String resourceDirectory) {
      this.resourceDirectory = resourceDirectory;
      this.directoryAllowed = false;
      this.gzip = true;
      this.etags = false;
      this.cacheControl = "";
   }

   /**
    * Creates file servlet configuration from properties.
    * @param namePrefix A prefix to be applied to names in the properties {@code server.} for example.
    * @param props The properties.
    * @throws InitializationException on invalid configuration.
    */
   public StaticAssetsConfig(final String namePrefix, final Properties props) throws InitializationException {
      InitUtil init = new InitUtil(namePrefix, props, true);
      this.resourceDirectory = init.getProperty(RESOURCE_DIRECTORY_PROPERTY, "").trim();
      if(this.resourceDirectory.isEmpty()) {
         throw new InitializationException("A 'resourceDirectory' must be specified");
      }
      this.directoryAllowed = init.getProperty(DIRECTORY_ALLOWED_PROPERTY, "false").equalsIgnoreCase("true");
      this.gzip = init.getProperty(GZIP_PROPERTY, "true").equalsIgnoreCase("true");
      this.etags = init.getProperty(ETAGS_PROPERTY, "false").equalsIgnoreCase("true");
      this.cacheControl = init.getProperty(CACHE_CONTROL_HEADER_PROPERTY, "");
   }

   /**
    * The property name for the directory containing static resources ({@value}).
    */
   public static final String RESOURCE_DIRECTORY_PROPERTY = "resourceDirectory";

   /**
    * The property that indicates if directory listing is allowed ({@value}).
    */
   public static final String DIRECTORY_ALLOWED_PROPERTY = "directoryAllowed";

   /**
    * The property that indicates if gzip is enabled by default ({@value}).
    */
   public static final String GZIP_PROPERTY = "gzip";

   /**
    * The property that indicates if weak Etags are enabled by default ({@value}).
    */
   public static final String ETAGS_PROPERTY = "etags";

   /**
    * The property that configures the cache control header value ({@value}).
    */
   public static final String CACHE_CONTROL_HEADER_PROPERTY = "cacheControl";

   /**
    * The path to the directory containing static resources.
    */
   public final String resourceDirectory;

   /**
    * Are directory listings allowed? Default {@code false}.
    */
   public final boolean directoryAllowed;

   /**
    * Is gzip enabled? Default {@code true}.
    */
   public final boolean gzip;

   /**
    * Are weak ETags generated and handled? Default {@code false}.
    */
   public final boolean etags;

   /**
    * If non-empty, this {@code Cache-Control} header added to every response.
    */
   public final String cacheControl;
}