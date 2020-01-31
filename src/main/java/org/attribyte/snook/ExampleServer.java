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

import org.attribyte.api.ConsoleLogger;
import org.eclipse.jetty.servlet.ServletHolder;

public class ExampleServer extends Server {

   public ExampleServer(String[] args) throws Exception {
      super(args, "", "example", true, new ErrorHandler());
   }

   public static void main(String[] args) throws Exception {
      ExampleServer server = new ExampleServer(args);
      server.rootContext.addServlet(new ServletHolder(new UptimeServlet()), "/uptime/*");
      server.rootContext.addServlet(new ServletHolder(new FailServlet()), "/fail/*");
      server.httpServer.start();
      server.httpServer.join();
   }

   protected void shutdown() {
   }

   private static ErrorHandler customErrorHandler() {
      ErrorHandler handler = new ErrorHandler();
      handler.setShowStacks(true);
      return handler;
   }
}
