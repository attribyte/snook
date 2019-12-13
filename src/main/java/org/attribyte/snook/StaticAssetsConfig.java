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

   private StaticAssetsConfig(final String resourceDirectory, final boolean directoryAllowed,
                              final boolean gzip, final boolean etags,
                              final String cacheControl) {
      this.resourceDirectory = resourceDirectory;
      this.directoryAllowed = directoryAllowed;
      this.gzip = gzip;
      this.etags = etags;
      this.cacheControl = cacheControl;
   }

   /**
    * Create a new config with a new directory allowed setting.
    * @param directoryAllowed Is directory listing allowed?
    * @return Config with directory allowed changed.
    */
   public StaticAssetsConfig withDirectoryAllowed(boolean directoryAllowed) {
      return new StaticAssetsConfig(resourceDirectory, directoryAllowed, gzip, etags, cacheControl);
   }

   /**
    * Create a new config with a new gzip setting.
    * @param gzip Is gzip enabled?
    * @return Config with gzip changed.
    */
   public StaticAssetsConfig withGzip(boolean gzip) {
      return new StaticAssetsConfig(resourceDirectory, directoryAllowed, gzip, etags, cacheControl);
   }

   /**
    * Create a new config with a new etags setting.
    * @param etags Are etags enabled?
    * @return Config with etags changed.
    */
   public StaticAssetsConfig withETags(boolean etags) {
      return new StaticAssetsConfig(resourceDirectory, directoryAllowed, gzip, etags, cacheControl);
   }

   /**
    * Create a new config with a cache control header value.
    * @param cacheControl The cache control header value.
    * @return Config with cache control header changed.
    */
   public StaticAssetsConfig withCacheControl(String cacheControl) {
      return new StaticAssetsConfig(resourceDirectory, directoryAllowed, gzip, etags, cacheControl);
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
    * If non-empty, this {@code Cache-Control} header is added to every response.
    */
   public final String cacheControl;
}
