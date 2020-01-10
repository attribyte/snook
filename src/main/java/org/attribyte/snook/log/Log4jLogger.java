/*
 * Copyright 2020 Attribyte, LLC
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

package org.attribyte.snook.log;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;

public class Log4jLogger implements org.attribyte.api.Logger {

   /**
    * Creates a logger from a named log4j logger with {@code INFO} as the minimum level.
    * @param loggerName The logger name.
    */
   public Log4jLogger(final String loggerName) {
      this(LogManager.getLogger(loggerName), Level.INFO);
   }

   /**
    * Creates a logger from a named log4j logger.
    * @param loggerName The logger name.
    * @param minimumLevel The minimum level to log.
    */
   public Log4jLogger(final String loggerName, final Level minimumLevel) {
      this(LogManager.getLogger(loggerName), minimumLevel);
   }

   /**
    * Create a logger from an existing log4j logger.
    * @param log4jLogger The log4j logger.
    * @param minimumLevel The minimum level to log.
    */
   public Log4jLogger(final org.apache.logging.log4j.Logger log4jLogger, final Level minimumLevel) {
      this.log4jLogger = log4jLogger;
      this.minimumLevel = minimumLevel;
   }

   /**
    * Create a logger from an existing log4j logger with minimum level {@code INFO}.
    * @param log4jLogger The log4j logger.
    */
   public Log4jLogger(final org.apache.logging.log4j.Logger log4jLogger) {
      this(log4jLogger, Level.INFO);
   }

   @Override
   public void debug(String msg) {
      if(minimumLevel.isLessSpecificThan(Level.DEBUG)) {
         log4jLogger.debug(msg);
      }
   }

   @Override
   public void info(String msg) {
      if(minimumLevel.isLessSpecificThan(Level.INFO)) {
         log4jLogger.info(msg);
      }
   }

   @Override
   public void warn(String msg) {
      if(minimumLevel.isLessSpecificThan(Level.WARN)) {
         log4jLogger.warn(msg);
      }
   }

   @Override
   public void warn(String msg, Throwable t) {
      if(minimumLevel.isLessSpecificThan(Level.WARN)) {
         log4jLogger.warn(msg, t);
      }
   }

   @Override
   public void error(String msg) {
      if(minimumLevel.isLessSpecificThan(Level.ERROR)) {
         log4jLogger.error(msg);
      }
   }

   @Override
   public void error(String msg, Throwable t) {
      if(minimumLevel.isLessSpecificThan(Level.ERROR)) {
         log4jLogger.error(msg, t);
      }
   }

   /**
    * The target logger.
    */
   private final org.apache.logging.log4j.Logger log4jLogger;

   /**
    * The minimum level.
    */
   private final Level minimumLevel;
}
