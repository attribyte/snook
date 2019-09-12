/*
 * Copyright 2019 Attribyte, LLC
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

import com.google.common.base.MoreObjects;
import org.attribyte.api.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * A thread that listens for a shutdown signal on a specified port.
 * <p>
 *    Create an instance with that {@code shutdown} method defined and call {@code start} to listen.
 * </p>
 */
public abstract class ShutdownMonitor extends Thread {

   /**
    * Sends the shutdown signal to the default address and port.
    * @throws IOException on signal error.
    * @return The elapsed time in milliseconds for shutdown to be acknowledged.
    */
   public static long sendShutdownSignal() throws IOException {
      return sendShutdownSignal(DEFAULT_ADDRESS, DEFAULT_PORT);
   }

   /**
    * Sends the shutdown signal.
    * @param mgmtAddress The management listen address.
    * @param mgmtPort The management port.
    * @throws IOException on signal error.
    * @return The elapsed time in milliseconds for shutdown to be acknowledged.
    */
   public static long sendShutdownSignal(final InetAddress mgmtAddress, final int mgmtPort) throws IOException {
      Socket s = new Socket(mgmtAddress, mgmtPort);
      OutputStream out = s.getOutputStream();
      out.write(("\r\n").getBytes());
      out.flush();
      InputStream is = s.getInputStream();
      long start = System.currentTimeMillis();
      is.read(); //Wait for one byte to be sent...
      s.close();
      return System.currentTimeMillis() - start;
   }

   /**
    * Creates a server monitor with defaults and a logger.
    * @param logger A message logger.
    */
   protected ShutdownMonitor(final Logger logger) {
      this(null, -1, logger);
   }

   /**
    * Creates a server monitor with defaults and no logger.
    */
   protected ShutdownMonitor() {
      this(null, -1, null);
   }

   /**
    * Creates the server monitor.
    * @param mgmtAddress The management listen address. If {@code null}, listens on 127.0.0.1.
    * @param mgmtPort The management port. If {@code 0}, default port is used.
    * @param logger A message logger.
    */
   protected ShutdownMonitor(final InetAddress mgmtAddress, final int mgmtPort, final Logger logger) {
      this.logger = logger;
      setName("Shutdown Monitor");
      setDaemon(true);
      try {
         socket = new ServerSocket(mgmtPort < 1 ? DEFAULT_PORT : mgmtPort, 1, mgmtAddress == null ? DEFAULT_ADDRESS :
                 mgmtAddress);
      } catch (Throwable t) {
         if(t instanceof RuntimeException) {
            throw (RuntimeException) t;
         } else {
            throw new RuntimeException(t);
         }
      }
   }

   @Override
   public void run() {
      final Socket accept;
      try {
         if(logger != null) {
            logger.info(String.format("Starting shutdown monitor on %s, Port:%d", socket.getInetAddress().getHostAddress(), socket.getLocalPort()));
         }
         accept = socket.accept();
         BufferedReader reader = new BufferedReader(new InputStreamReader(accept.getInputStream()));
         reader.readLine();
         if(logger != null) {
            logger.info(String.format("Shutdown accepted on %s, Port:%d", socket.getInetAddress().getHostAddress(), socket.getLocalPort()));
         }
         shutdown();
         accept.getOutputStream().write(0);
         accept.close();
         socket.close();
      } catch(Error e) {
         throw e;
      } catch(Throwable t) {
         if(logger != null) {
            logger.error("Shutdown failed with exception", t);
         }
      }
   }

   @Override
   public String toString() {
      return MoreObjects.toStringHelper(this)
              .add("address", socket.getInetAddress())
              .add("port", socket.getLocalPort())
              .toString();
   }

   /**
    * Called on shutdown.
    */
   protected abstract void shutdown();

   /**
    * The listening server socket.
    */
   private final ServerSocket socket;

   /**
    * A logger.
    */
   protected final Logger logger;

   /**
    * The default port {@value}.
    */
   public static final int DEFAULT_PORT = 8079;

   /**
    * The default listen address {@code loopback}.
    */
   public static final InetAddress DEFAULT_ADDRESS = InetAddress.getLoopbackAddress();
}