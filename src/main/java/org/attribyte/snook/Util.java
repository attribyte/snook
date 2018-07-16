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

import com.google.common.collect.Lists;

import java.util.List;
import java.util.Map;

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

      return argList.toArray(new String[argList.size()]);
   }
}
