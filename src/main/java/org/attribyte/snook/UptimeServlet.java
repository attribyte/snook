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

import com.google.common.collect.ImmutableList;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * An example command servlet that calls the "uptime" command.
 */
@SuppressWarnings("serial")
public class UptimeServlet extends CommandServlet {

   @Override
   protected List<String> command(HttpServletRequest request) {
      return ImmutableList.of("/usr/bin/uptime", "--pretty");
   }
}
