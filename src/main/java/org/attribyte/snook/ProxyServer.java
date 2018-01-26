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

import org.eclipse.jetty.servlet.ServletHolder;

public class ProxyServer extends Server {

   public ProxyServer(String[] args) throws Exception {
      super(args, "", "proxy", true);
   }

   public static void main(String[] args) throws Exception {
      ProxyServer server = new ProxyServer(args);
      server.rootContext.addServlet(new ServletHolder(new CommandProxyServlet()), "/*");
      server.httpServer.setDumpBeforeStop(true);
      server.httpServer.setStopAtShutdown(true);
      server.httpServer.start();
      server.httpServer.join();
   }

   protected void shutdown() {
   }
}