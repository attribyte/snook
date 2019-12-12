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

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.net.InternetDomainName;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class Util {

   /**
    * The default string that starts a parameter ({@value}).
    */
   public static final String DEFAULT_PARAMETER_START = "-";

   /**
    * Removes arguments like -username=test from a command line and adds them to a map.
    * <p>
    *   Adds a version of every key that is all lower-case.
    * </p>
    * @param args The input arguments.
    * @param parameterMap The map to which parameters are added.
    * @return The input array with parameters removed.
    */
   public static String[] commandLineParameters(String[] args, Map<String, String> parameterMap) {
      return commandLineParameters(DEFAULT_PARAMETER_START, args, parameterMap);
   }

   /**
    * Removes arguments like --debug=true from a command line and adds them to a map.
    * <p>
    *   Adds a version of every key that is all lower-case.
    *   If a parameter has no value, "true" is added to the map as the value.
    * </p>
    * @param parameterStartPrefix The prefix that starts parameters (default is '-' but you might want '--').
    * @param args The input arguments.
    * @param parameterMap The map to which parameters are added.
    * @return The input array with parameters removed.
    */
   public static String[] commandLineParameters(final String parameterStartPrefix, String[] args, Map<String, String> parameterMap) {

      if(args == null || args.length == 0) {
         return args;
      }

      List<String> argList = Lists.newArrayListWithExpectedSize(8);
      for(String arg : args) {
         if(arg.isEmpty()) {
            continue;
         }

         arg = arg.trim();

         if(arg.startsWith(parameterStartPrefix)) {
            String nameVal = arg.substring(parameterStartPrefix.length());
            int index = nameVal.indexOf('=');
            if(index == -1) {
               parameterMap.put(nameVal, "true");
            } else {
               String name = nameVal.substring(0, index).trim();
               String val = nameVal.substring(index+1).trim();
               parameterMap.put(name, val);
               parameterMap.put(name.toLowerCase(), val);
            }

         } else {
            argList.add(arg);
         }
      }

      return argList.toArray(new String[0]);
   }

   /**
    * Examines configuration keys for those that represent files/directories to add
    * system install path if not absolute. Keys that end with {@code .file} or {@code .dir}
    * are treated as files/directories for this purpose.
    * @param props The properties.
    * @return The properties with modified values.
    * @throws IOException on filesystem error.
    */
   public static Properties resolveRelativeFiles(final Properties props) throws IOException {

      Properties filteredProps = new Properties();
      File systemInstallDir = systemInstallDir();

      for(String key : props.stringPropertyNames()) {
         if(key.toLowerCase().endsWith(".file") || key.toLowerCase().endsWith(".dir")) {
            String filename = props.getProperty(key).trim();
            if(filename.isEmpty() || filename.startsWith("/")) {
               filteredProps.put(key, filename);
            } else {
               filteredProps.put(key, new File(systemInstallDir, filename).getCanonicalPath());
            }
         } else {
            filteredProps.put(key, props.getProperty(key));
         }
      }
      return filteredProps;
   }

   /**
    * The system property name that holds the install directory ({@value}).
    */
   public static final String INSTALL_DIR_SYSTEM_PROP = "server.install.dir";

   /**
    * Gets the system install directory.
    * @return The directory.
    */
   public static File systemInstallDir() {
      String systemInstallDir = System.getProperty(INSTALL_DIR_SYSTEM_PROP, "../config").trim();
      return new File(systemInstallDir);
   }

   /**
    * Examines configuration values for possible environment variables.
    * If a value starts with {@code $} and there is a matching variable
    * with that name in the environment, the value will be replaced by
    * the value from the environment. A default value to be used if
    * the environment variable is not set, e.g. {@code $DB_HOST||127.0.0.1}.
    * @param props The properties.
    * @return The properties with modified values.
    */
   public static Properties resolveEnvironmentVariables(final Properties props) {
      Map<String, String> envVariables = System.getenv();
      Properties filteredProps = new Properties();
      props.forEach((key, origVal) -> {
         if(origVal.toString().startsWith("$")) {
            String envName = origVal.toString().substring(1).trim();
            String defaultValue = origVal.toString().trim();
            List<String> envNameDefault = ENV_DEFAULT_VALUE_SPLITTER.splitToList(envName);
            if(envNameDefault.size() > 1) {
               envName = envNameDefault.get(0);
               defaultValue = envNameDefault.get(1);
            }

            String val = envVariables.getOrDefault(envName, defaultValue);
            filteredProps.setProperty(key.toString(), val);
         } else {
            filteredProps.setProperty(key.toString(), origVal.toString());
         }
      });

      return filteredProps;
   }

   /**
    * Split default values specified with environment variables.
    */
   static final Splitter ENV_DEFAULT_VALUE_SPLITTER = Splitter.on("||").trimResults().limit(2);

   /**
    * Gets the host for a link.
    * @param link The link.
    * @return The host or {@code null} if link is an invalid URL.
    */
   public static String host(String link) {

      if(Strings.isNullOrEmpty(link)) {
         return null;
      }

      if(!link.contains("://")) {
         link = "http://" + link;
      }

      try {
         return new URL(link).getHost();
      } catch(MalformedURLException mue) {
         return null;
      }
   }


   /**
    * Gets the path for a link, excluding the query string, if any.
    * @param link The link.
    * @return The path, or empty string if none.
    */
   public static String path(String link) {

      if(Strings.isNullOrEmpty(link)) {
         return "";
      }

      boolean relative = false;
      if(!link.contains("://")) {
         if(!link.startsWith("/")) {
            link = "/" + link;
            relative = true;
         }
         link = "https://broken.com" + link;
      }

      try {
         return !relative ? new URL(link).getPath() : new URL(link).getPath().substring(1);
      } catch(MalformedURLException mue) {
         return "";
      }
   }

   /**
    * Gets the (top, private) domain for the link.
    * <p>
    *    For example: {@code test.attribyte.com -> attribyte.com, test.blogspot.com -> test.blogspot.com}.
    * </p>
    * @param link The link.
    * @return The domain or {@code null} if invalid.
    */
   public static String domain(final String link) {
      final String host = host(link);
      if(host == null) {
         return null;
      }

      try {
         InternetDomainName idn = InternetDomainName.from(host);
         if(idn.isPublicSuffix()) {
            return idn.toString();
         } else if(idn.isUnderPublicSuffix()) {
            return idn.topPrivateDomain().toString();
         } else {
            return host;
         }
      } catch(IllegalArgumentException ie) {
         return null;
      }
   }
}
