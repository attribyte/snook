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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * An example servlet that always throws a {@code RuntimeException}.
 */
@SuppressWarnings("serial")
public class FailServlet extends HttpServlet {

   @Override
   protected void service(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
      throw new RuntimeException("Fail - 0", new UnsupportedOperationException("Fail - 1", new Exception("<p>Fail - 2</p>")));
   }
}
