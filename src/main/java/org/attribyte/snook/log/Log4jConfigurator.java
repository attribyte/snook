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

package org.attribyte.snook.log;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.builder.api.AppenderComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.api.LayoutComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.LoggerComponentBuilder;
import org.apache.logging.log4j.core.config.builder.api.ComponentBuilder;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;
import org.attribyte.util.InitUtil;

import java.util.Map;
import java.util.Properties;

/**
 * Configures log4j2 programmatically from snook properties.
 * <p>
 *    If {@code logger.*} properties are present, builds and applies a log4j2 configuration.
 *    If none are found, returns {@code false} and log4j's normal XML/classpath discovery stays active.
 * </p>
 * <h3>Global Properties</h3>
 * <ul>
 *    <li>{@code log.Dir} - Log file directory (resolved relative to {@code server.install.dir})</li>
 *    <li>{@code log.rootLevel} - Root logger level (default: {@code ERROR})</li>
 *    <li>{@code log.maxFileSize} - Max size before rolling (default: {@code 250 MB})</li>
 *    <li>{@code log.consolePattern} - Console PatternLayout (default: {@code %d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n})</li>
 *    <li>{@code log.filePattern} - File PatternLayout (default: {@code %d %p %c{1.} [%t] %m%n})</li>
 * </ul>
 * <h3>Per-Logger Properties (prefix: logger.&lt;key&gt;.)</h3>
 * <ul>
 *    <li>{@code name} - Logger name (required)</li>
 *    <li>{@code level} - TRACE/DEBUG/INFO/WARN/ERROR/OFF (default: {@code INFO})</li>
 *    <li>{@code appender} - {@code console} or {@code file} (default: {@code file})</li>
 *    <li>{@code fileName} - File name relative to {@code log.Dir} (default: {@code <key>.log})</li>
 * </ul>
 */
public class Log4jConfigurator {

   /**
    * Default console pattern layout.
    */
   static final String DEFAULT_CONSOLE_PATTERN = "%d{HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n";

   /**
    * Default file pattern layout.
    */
   static final String DEFAULT_FILE_PATTERN = "%d %p %c{1.} [%t] %m%n";

   /**
    * Default root logger level.
    */
   static final String DEFAULT_ROOT_LEVEL = "ERROR";

   /**
    * Default max file size before rolling.
    */
   static final String DEFAULT_MAX_FILE_SIZE = "250 MB";

   /**
    * Configures log4j2 from properties.
    * @param props The properties.
    * @return {@code true} if logger properties were found and configuration was applied.
    */
   public static boolean configure(final Properties props) {

      InitUtil loggerInit = new InitUtil("logger.", props, false);
      Map<String, Properties> loggerConfigs = loggerInit.split();

      if(loggerConfigs.isEmpty()) {
         return false;
      }

      String logDir = props.getProperty("log.Dir", "").trim();
      String rootLevel = props.getProperty("log.rootLevel", DEFAULT_ROOT_LEVEL).trim();
      String maxFileSize = props.getProperty("log.maxFileSize", DEFAULT_MAX_FILE_SIZE).trim();
      String consolePattern = props.getProperty("log.consolePattern", DEFAULT_CONSOLE_PATTERN);
      String filePattern = props.getProperty("log.filePattern", DEFAULT_FILE_PATTERN);

      ConfigurationBuilder<BuiltConfiguration> builder = ConfigurationBuilderFactory.newConfigurationBuilder();
      builder.setStatusLevel(Level.WARN);
      builder.setConfigurationName("SnookPropsConfig");

      // Console appender (shared)
      LayoutComponentBuilder consoleLayout = builder.newLayout("PatternLayout")
              .addAttribute("pattern", consolePattern);
      AppenderComponentBuilder consoleAppender = builder.newAppender("Console", "CONSOLE")
              .addAttribute("target", "SYSTEM_OUT")
              .add(consoleLayout);
      builder.add(consoleAppender);

      // Root logger
      builder.add(builder.newRootLogger(Level.getLevel(rootLevel.toUpperCase()))
              .add(builder.newAppenderRef("Console")));

      // Per-logger configuration
      for(Map.Entry<String, Properties> entry : loggerConfigs.entrySet()) {
         String key = entry.getKey();
         Properties loggerProps = entry.getValue();

         String loggerName = loggerProps.getProperty("name", "").trim();
         if(loggerName.isEmpty()) {
            continue;
         }

         String level = loggerProps.getProperty("level", "INFO").trim().toUpperCase();
         String appenderType = loggerProps.getProperty("appender", "file").trim().toLowerCase();
         String fileName = loggerProps.getProperty("fileName", key + ".log").trim();

         String appenderRef;

         if("console".equals(appenderType)) {
            appenderRef = "Console";
         } else {
            // Create a RollingFile appender for this logger
            String appenderName = "RollingFile-" + key;
            String baseName = fileName.endsWith(".log") ? fileName.substring(0, fileName.length() - 4) : fileName;

            String fullPath = logDir.isEmpty() ? fileName : logDir + "/" + fileName;
            String rollingPattern = logDir.isEmpty()
                    ? "$${date:yyyy-MM}/" + baseName + "-%d{MM-dd-yyyy}-%i.log"
                    : logDir + "/$${date:yyyy-MM}/" + baseName + "-%d{MM-dd-yyyy}-%i.log";

            LayoutComponentBuilder fileLayout = builder.newLayout("PatternLayout")
                    .addAttribute("pattern", filePattern);

            ComponentBuilder<?> triggeringPolicy = builder.newComponent("Policies")
                    .addComponent(builder.newComponent("TimeBasedTriggeringPolicy"))
                    .addComponent(builder.newComponent("SizeBasedTriggeringPolicy")
                            .addAttribute("size", maxFileSize));

            AppenderComponentBuilder rollingAppender = builder.newAppender(appenderName, "RollingFile")
                    .addAttribute("fileName", fullPath)
                    .addAttribute("filePattern", rollingPattern)
                    .add(fileLayout)
                    .addComponent(triggeringPolicy);
            builder.add(rollingAppender);
            appenderRef = appenderName;
         }

         LoggerComponentBuilder loggerBuilder = builder.newLogger(loggerName, Level.getLevel(level))
                 .addAttribute("additivity", false)
                 .add(builder.newAppenderRef(appenderRef));
         builder.add(loggerBuilder);
      }

      Configurator.reconfigure(builder.build());
      return true;
   }
}
