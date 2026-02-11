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

import com.codahale.metrics.InstrumentedExecutorService;
import com.codahale.metrics.Meter;
import com.codahale.metrics.Metric;
import com.codahale.metrics.MetricRegistry;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.ByteStreams;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.SimpleTimeLimiter;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.attribyte.api.http.Header;
import org.attribyte.essem.metrics.Timer;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * A servlet that executes commands and returns the console output as the response.
 * <p>
 *    Responds to {@code GET} or {@code POST} methods.
 * </p>
 */
@SuppressWarnings("serial")
public abstract class CommandServlet extends HttpServlet {

   /**
    * Creates a command servlet with defaults.
    * @param maxConcurrentCommands The maximum number of concurrently running commands.
    */
   protected CommandServlet(final int maxConcurrentCommands) {
      this(DEFAULT_CONTENT_TYPE, DEFAULT_MAX_WAIT_SECONDS, maxConcurrentCommands);
   }


   /**
    * Creates a command servlet.
    * @param contentType The content type returned with the response.
    * @param maxWaitSeconds The maximum number of seconds to wait for a command
    * to complete before aborting and returning an error.
    * @param maxConcurrentCommands The maximum number of concurrently running commands.
    */
   protected CommandServlet(final String contentType,
                            final int maxWaitSeconds,
                            final int maxConcurrentCommands) {
      this.contentType = contentType;
      this.maxWaitSeconds = maxWaitSeconds;
      this.executorRegistry = new MetricRegistry();
      this.commandExecutor =
              new InstrumentedExecutorService(MoreExecutors.getExitingExecutorService(
                      new ThreadPoolExecutor(1, maxConcurrentCommands,
                              30, TimeUnit.SECONDS,
                              new LinkedBlockingQueue<>(),
                              new ThreadFactoryBuilder().setNameFormat("command-servlet-%d").build(),
                              new ThreadPoolExecutor.AbortPolicy()
                      )), executorRegistry, "executor"
              );
      this.timeLimiter = SimpleTimeLimiter.create(this.commandExecutor);
   }

   /**
    * The command followed by a list of arguments.
    * @param request The HTTP request.
    * @return The command followed by arguments.
    */
   protected abstract List<String> command(HttpServletRequest request);

   /**
    * A list of headers to add to the response.
    * <p>
    *    Override to add custom response headers.
    * </p>
    * @param request The HTTP request.
    * @return A list of headers.
    */
   protected List<Header> responseHeaders(HttpServletRequest request) {
      return ImmutableList.of();
   }

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
      final Timer.Context ctx = commands.time();
      try {
         final CommandResult result = timeLimiter.callWithTimeout(new Callable<CommandResult>() {
            @Override
            public CommandResult call() {
               try {
                  Process process = processBuilder.start();
                  try(InputStream is = new BufferedInputStream(process.getInputStream());
                      InputStream es = new BufferedInputStream(process.getErrorStream())) {
                     byte[] input = ByteStreams.toByteArray(is);
                     byte[] err = ByteStreams.toByteArray(es);
                     int exitCode = process.waitFor();
                     return new CommandResult(input, err, exitCode);
                  } catch(IOException ioe) {
                     failedCommands.mark();
                     return new CommandResult(ioe);
                  } catch(InterruptedException ie) {
                     Thread.currentThread().interrupt();
                     failedCommands.mark();
                     return new CommandResult(ie);
                  } finally {
                     process.destroyForcibly();
                  }
               } catch(IOException ioe) {
                  failedCommands.mark();
                  return new CommandResult(ioe);
               }
            }
         }, maxWaitSeconds, TimeUnit.SECONDS);

         if(result.exception == null) {
            response.setStatus(result.exitCode == 0 ? 200 : 500);
            response.setContentType(contentType);
            response.setContentLength(result.response.length);
            for(Header header : responseHeaders(request)) {
               if(!response.containsHeader(header.name)) {
                  response.setHeader(header.name, header.getValue());
               }
            }
            response.getOutputStream().write(result.response);
            response.getOutputStream().flush();
         } else {
            response.sendError(500, result.exception.getMessage());
         }
      } catch(TimeoutException te) {
         timedOutCommands.mark();
         failedCommands.mark();
         response.sendError(500, String.format("Execution time exceeded %s seconds", maxWaitSeconds));
      } catch(ExecutionException ee) {
         failedCommands.mark();
         response.sendError(500, ee.getMessage());
      } catch(InterruptedException ie) {
         response.sendError(500, "Interrupted during execution");
         Thread.currentThread().interrupt();
      } finally {
         ctx.stop();
      }
   }

   /**
    * The result of running a command.
    */
   private static final class CommandResult {

      /**
       * Creates a result with a response.
       * @param response The response.
       * @param err The error stream output.
       * @param exitCode The process exit code.
       */
      public CommandResult(final byte[] response,
                           final byte[] err,
                           final int exitCode) {
         this.response = response;
         this.err = err;
         this.exitCode = exitCode;
         this.exception = null;
      }

      /**
       * Creates an error result.
       * @param exception The exception.
       */
      public CommandResult(Throwable exception) {
         this.response = null;
         this.err = null;
         this.exitCode = 0;
         this.exception = exception;
      }

      /**
       * The command output (bytes).
       */
      final byte[] response;

      /**
       * The error stream output (bytes).
       */
      final byte[] err;

      /**
       * The command exit code.
       */
      final int exitCode;

      /**
       * An exception, if any.
       */
      final Throwable exception;
   }

   @Override
   public void destroy() {
      this.commandExecutor.shutdown();
   }

   /**
    * Gets metrics recorded for this servlet.
    * @return The map of metrics vs name.
    */
   public Map<String, Metric> metrics() {
      return ImmutableMap.of(
              "commands", commands,
              "timedOutCommands", timedOutCommands,
              "failedCommands", failedCommands,
              "commandService", executorRegistry
      );
   }

   /**
    * The default content type ({@value}).
    */
   public static final String DEFAULT_CONTENT_TYPE = "text/plain";

   /**
    * The default number of seconds to wait for the command to finish ({@value}).
    */
   public static final int DEFAULT_MAX_WAIT_SECONDS = 15;

   /**
    * The content type.
    */
   private final String contentType;

   /**
    * The maximum wait in seconds.
    */
   private final int maxWaitSeconds;

   /**
    * The time limiter.
    */
   private final SimpleTimeLimiter timeLimiter;

   /**
    * The executor for commands.
    */
   private final ExecutorService commandExecutor;

   /**
    * Time all commands.
    */
   private final Timer commands = new Timer();

   /**
    * Record all commands that time-out.
    */
   private final Meter timedOutCommands = new Meter();

   /**
    * Record all commands that fail due to exception or other error, including time-out.
    */
   private final Meter failedCommands = new Meter();

   /**
    * A registry holding executor instrumentation.
    */
   private final MetricRegistry executorRegistry;
}