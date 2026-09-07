/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.activemq.artemis.core.server.embedded;

import java.io.File;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.CountDownLatch;

import org.apache.activemq.artemis.core.config.FileDeploymentManager;
import org.apache.activemq.artemis.core.config.impl.ConfigurationImpl;
import org.apache.activemq.artemis.core.config.impl.FileConfiguration;
import org.apache.activemq.artemis.core.config.impl.LegacyJMSConfiguration;
import org.apache.activemq.artemis.core.server.ActivateCallback;
import org.apache.activemq.artemis.core.server.ActiveMQServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

   private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

   private static String workDir = "/app";
   private static String propertiesConfigPath = "";
   private static volatile EmbeddedActiveMQ embeddedServer;

   public static void main(String[] args) throws Exception {

      Path customXmlPath = null;

      if (args.length >= 1) {
         if (args[0] == null || args[0].trim().isEmpty()) {
            throw new IllegalArgumentException("Work directory cannot be empty");
         }
         workDir = args[0];
         logger.debug("User supplied work dir {}", workDir);
      }

      if (args.length >= 2) {
         if (args[1] == null || args[1].trim().isEmpty()) {
            throw new IllegalArgumentException("Properties/Config path cannot be empty");
         }

         String rawPath = args[1].trim();

         // Convert to Path for existence check
         if (rawPath.startsWith("file:")) {
            customXmlPath = Paths.get(URI.create(rawPath));
            propertiesConfigPath = rawPath;
         } else {
            customXmlPath = Paths.get(rawPath);
            propertiesConfigPath = customXmlPath.toUri().toString();
         }

         // Validate file existence on disk
         if (!Files.exists(customXmlPath)) {
            throw new IllegalArgumentException("Config path does not exist: " + args[1]);
         }

         logger.debug("User supplied properties config path {}", propertiesConfigPath);
      } else {
         propertiesConfigPath = "/config/," + workDir + "/etc/";
      }

      if (args.length >= 3) {
         throw new IllegalArgumentException("Maximum number of expected arguments is 2");
      }

      embeddedServer = new EmbeddedActiveMQ();

      FileConfiguration configuration = new FileConfiguration();

      String dataDir = workDir + "/data";
      configureDataDirectory(configuration, dataDir);

      // Determine XML file to load
      File xmlToLoad = null;

      if (customXmlPath != null && propertiesConfigPath.toLowerCase().endsWith(".xml")) {
         xmlToLoad = customXmlPath.toFile();
      } else {
         File bringYourOwnXml = new File(workDir + "/etc/broker.xml");
         if (bringYourOwnXml.exists()) {
            xmlToLoad = bringYourOwnXml;
         }
      }

      // Load configuration, can overwrite configureDataDirectory
      if (xmlToLoad != null && xmlToLoad.exists()) {
         logger.debug("Loading XML configuration from {}", xmlToLoad);
         configuration = loadFromXmlFile(xmlToLoad, configuration);
      } else if (propertiesConfigPath != null && !propertiesConfigPath.toLowerCase().endsWith(".xml")) {
         embeddedServer.setPropertiesResourcePath(propertiesConfigPath);
      }

      embeddedServer.setConfiguration(configuration);
      embeddedServer.createActiveMQServer();

      final ActiveMQServer activeMQServer = embeddedServer.getActiveMQServer();
      final CountDownLatch serverStopped = new CountDownLatch(1);
      registerCallbackToTriggerLatchOnStopped(activeMQServer, serverStopped);
      exitWithErrorOnStartFailure(activeMQServer);
      addShutdownHookForServerStop(embeddedServer);

      logger.debug("starting server");
      embeddedServer.start();

      logger.debug("await server stop");
      serverStopped.await();
      embeddedServer = null;
   }

   private static void exitWithErrorOnStartFailure(ActiveMQServer activeMQServer) {
      activeMQServer.registerActivationFailureListener(exception -> {
         logger.error("server failed to start {}, exit(1) in thread", exception);
         new Thread("exit(1)-on-start-failure") {
            @Override
            public void run() {
               logger.error("exit(1)");
               Runtime.getRuntime().exit(1);
            }
         }.start();
      });
   }

   private static void registerCallbackToTriggerLatchOnStopped(ActiveMQServer activeMQServer, CountDownLatch serverStopped) {
      activeMQServer.registerActivateCallback(new ActivateCallback() {

         @Override
         public void stop(ActiveMQServer server) {
            logger.trace("server stop, state {}", server.getState());
            serverStopped.countDown();
         }

         @Override
         public void shutdown(ActiveMQServer server) {
            logger.trace("server shutdown, state {}", server.getState());
            serverStopped.countDown();
         }
      });
   }

   private static void addShutdownHookForServerStop(final EmbeddedActiveMQ server) {
      Runtime.getRuntime().addShutdownHook(new Thread("shutdown-hook") {
         @Override
         public void run() {
            try {
               logger.trace("stop via shutdown hook");
               server.stop();
            } catch (Exception ignored) {
               logger.trace("Error on stop {}", ignored);
            }
         }
      });
   }

   public static FileConfiguration loadFromXmlFile(File bringYourOwnXml, FileConfiguration base) throws Exception {
      FileDeploymentManager deploymentManager = new FileDeploymentManager(bringYourOwnXml.toURI().toASCIIString());
      LegacyJMSConfiguration legacyJMSConfiguration = new LegacyJMSConfiguration(base);
      deploymentManager.addDeployable(base).addDeployable(legacyJMSConfiguration);
      deploymentManager.readConfiguration();
      return base;
   }

   public static void configureDataDirectory(ConfigurationImpl configuration, String dataDir) {
      configuration.setJournalDirectory(dataDir + "/journal");
      configuration.setBindingsDirectory(dataDir + "/bindings");
      configuration.setLargeMessagesDirectory(dataDir + "/large-messages");
      configuration.setPagingDirectory(dataDir + "/paging");
   }

   public static EmbeddedActiveMQ getEmbeddedServer() {
      return embeddedServer;
   }
}