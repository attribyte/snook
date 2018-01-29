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

import com.google.common.io.ByteStreams;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * A servlet that executes commands and returns the console output as the response.
 * <p>
 *    Responds to {@code GET} or {@code POST} methods.
 * </p>
 */
@SuppressWarnings("serial")
public abstract class CommandServlet extends HttpServlet {

   /**
    * Gets the content type sent with the response.
    * @return The content type.
    */
   protected String contentType() {
      return DEFAULT_CONTENT_TYPE;
   }

   /**
    * The default content type ({@value}).
    */
   public static final String DEFAULT_CONTENT_TYPE = "text/plain";

   /**
    * The maximum number of seconds to wait for the command to complete.
    * @return The number of seconds.
    */
   protected int maxWaitSeconds() {
      return DEFAULT_MAX_WAIT_SECONDS;
   }

   /**
    * The default number of seconds to wait for the command to finish ({@value}).
    */
   public static final int DEFAULT_MAX_WAIT_SECONDS = 15;

   /**
    * The command followed by a list of arguments.
    * @param request The HTTP request.
    * @return The command followed by arguments.
    */
   protected abstract List<String> command(HttpServletRequest request);

   @Override
   protected final void doGet(final HttpServletRequest request,
                              final HttpServletResponse response) throws IOException {
      request(request, response);
   }

   @Override
   protected final void doPost(final HttpServletRequest request,
                               final HttpServletResponse response) throws IOException {
      request(request, response);
   }

   protected final void request(final HttpServletRequest request,
                                final HttpServletResponse response) throws IOException {
      ProcessBuilder processBuilder = new ProcessBuilder();
      processBuilder.command(command(request));
      processBuilder.redirectErrorStream();
      Process process = processBuilder.start();
      try(InputStream is = new BufferedInputStream(process.getInputStream())) {
         boolean complete = process.waitFor(maxWaitSeconds(), TimeUnit.SECONDS);
         response.setStatus(complete ? 200 : 500);
         response.setContentType(contentType());
         ByteStreams.copy(is, response.getOutputStream());
         response.getOutputStream().flush();
      } catch(InterruptedException ie) {
         response.sendError(500, "Interrupted");
      } finally {
         process.destroyForcibly();
      }
   }
}