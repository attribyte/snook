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

import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import org.attribyte.api.Logger;

import java.io.File;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Monitors the key store for changes and reloads.
 */
public class KeyStoreMonitor {

   /**
    * Starts the key store monitor.
    * @param serverConfiguration The server configuration.
    * @param logger The logger.
    */
   public void start(final ServerConfiguration serverConfiguration, final Logger logger) throws UnsupportedOperationException {
      if(started.compareAndSet(false, true)) {
         if(serverConfiguration.keyStoreCheckIntervalMillis > 0L && serverConfiguration.sslContextFactory.isPresent()) {
            this.scheduledExecutorService =
                    MoreExecutors.getExitingScheduledExecutorService(
                            new ScheduledThreadPoolExecutor(1,
                                    new ThreadFactoryBuilder().setNameFormat("KeyStoreMonitor-Thread-%d").build())
                    );
            final File checkFile = new File(serverConfiguration.keyStorePath);
            this.lastKeystoreModTime.set(checkFile.exists() ? checkFile.lastModified() : 0L);
            this.scheduledExecutorService.schedule(() -> {
               long lastModTimestamp = checkFile.exists() ? checkFile.lastModified() : 0L;
               if(lastModTimestamp > lastKeystoreModTime.get()) {
                  try {
                     serverConfiguration.sslContextFactory.get().reload(scf -> logger.info("Reloading ssl context..."));
                     this.lastKeystoreModTime.set(lastModTimestamp);
                  } catch(Exception e) {
                     logger.error("Keystore reload failed", e);
                  }
               }

            }, serverConfiguration.keyStoreCheckIntervalMillis, TimeUnit.MILLISECONDS);
         }
      }
   }

   /**
    * Shutdown the key store monitor.
    */
   public void shutdown() {
      if(this.scheduledExecutorService != null) {
         this.scheduledExecutorService.shutdownNow();
      }
      this.started.set(false);
   }

   /**
    * Executor service for scheduled tasks.
    */
   private ScheduledExecutorService scheduledExecutorService;

   /**
    * Was the monitor started?
    */
   private final AtomicBoolean started = new AtomicBoolean(false);


   /**
    * The last time the keystore was modified.
    */
   private final AtomicLong lastKeystoreModTime = new AtomicLong(0L);

}
