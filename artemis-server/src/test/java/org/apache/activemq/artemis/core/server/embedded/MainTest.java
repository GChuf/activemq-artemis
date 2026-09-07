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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.invoke.MethodHandles;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MainTest {

   private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

   /*
    * Test what happens when no workdir arg is given, expect to throw IllegalArgumentException.
    */
   @Test
   @Timeout(5)
   public void testNull() throws Exception {
      try {
         Main.main(new String[] {""});
         fail("Should have thrown an IllegalArgumentException");
      } catch (IllegalArgumentException expected) {
         // Expected
         logger.info("Caught expected IllegalArgumentException: " + expected.getMessage());
      } finally {
         EmbeddedActiveMQ server = Main.getEmbeddedServer();
         if (server != null) {
            // Happens if the startup succeeds unexpectedly, but is
            // interrupted before return, e.g during a test timeout.
            // Clean up to avoid impacting later tests.
            try {
               server.stop();
            } catch (Throwable t) {
               // Log but suppress, allowing original issue be reported as failure.
               logger.warn("Caught issue while stopping the unexpectedly-present server", t);
            }
         }
      }
   }

   /*
    * Test what happens when 3 arguments are given, expect to throw IllegalArgumentException.
    */   
   @Test
   @Timeout(5)
   public void testInvalidNumberOfArguments() throws Exception {
      try {
         Main.main(new String[] {"a", "b", "c"});
         fail("Should have thrown an IllegalArgumentException");
      } catch (IllegalArgumentException expected) {
         // Expected
         logger.info("Caught expected IllegalArgumentException: " + expected.getMessage());
      } finally {
         EmbeddedActiveMQ server = Main.getEmbeddedServer();
         if (server != null) {
            // Happens if the startup succeeds unexpectedly, but is
            // interrupted before return, e.g during a test timeout.
            // Clean up to avoid impacting later tests.
            try {
               server.stop();
            } catch (Throwable t) {
               // Log but suppress, allowing original issue be reported as failure.
               logger.warn("Caught issue while stopping the unexpectedly-present server", t);
            }
         }
      }
   }

   /*
    * Test valid workDir argument
    */   
   @Test
   @Timeout(15)
   public void testWorkdir(@TempDir Path tempDir) throws Exception {
      Path workDirPath = tempDir.resolve("workDir");

      Files.createDirectories(workDirPath);

      String customWorkDir = workDirPath.toAbsolutePath().toString();

      Thread serverThread = new Thread(() -> {
         try {
            Main.main(new String[] {customWorkDir});
         } catch (Exception e) {
            logger.error("Error executing Main.main", e);
         }
      }, "artemis-main-workdir-test");

      serverThread.start();

      try {
         EmbeddedActiveMQ server = null;
         for (int i = 0; i < 20; i++) {
            server = Main.getEmbeddedServer();
            if (server != null && server.getActiveMQServer() != null && server.getActiveMQServer().isStarted()) {
               break;
            }
            Thread.sleep(500);
         }
         assertNotNull(server, "EmbeddedActiveMQ server instance was never initialized");
         assertNotNull(server.getActiveMQServer(), "ActiveMQServer was never initialized");
         assertTrue(server.getActiveMQServer().isStarted(), "Server failed to reach started state");

         var config = server.getActiveMQServer().getConfiguration();

         // verify directories from default configuration
         // use absolute paths
         String expectedDataDir = customWorkDir;
         assertEquals(expectedDataDir + "/data/journal", config.getJournalDirectory());
         assertEquals(expectedDataDir + "/data/bindings", config.getBindingsDirectory());
         assertEquals(expectedDataDir + "/data/paging", config.getPagingDirectory());
         assertEquals(expectedDataDir + "/data/large-messages", config.getLargeMessagesDirectory());

      } finally {
         EmbeddedActiveMQ server = Main.getEmbeddedServer();
         if (server != null) {
            try {
               server.stop();
            } catch (Throwable t) {
               logger.warn("Failed to stop EmbeddedActiveMQ server during test cleanup", t);
            }
         }
         serverThread.join(3000);
      }
   }

   /*
    * Test valid workDir and propertiesConfigPath arguments
    */   
   @Test
   @Timeout(15)
   public void testConfigFile(@TempDir Path tempDir) throws Exception {
      Path workDirPath = tempDir.resolve("workDir");
      Path configDirPath = tempDir.resolve("configDir");

      Files.createDirectories(workDirPath);
      Files.createDirectories(configDirPath);

      Path sourceXml = Path.of("src/test/resources/broker-embedded-minimal.xml");
      assertTrue(Files.exists(sourceXml), "broker-embedded-minimal.xml should exist in source tree");

      // Copy into temp directory
      Path targetXml = configDirPath.resolve("broker.xml");
      Files.copy(sourceXml, targetXml, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

      String customWorkDir = workDirPath.toAbsolutePath().toString();
      
      // FIX: Must use .toUri().toString() -> yields "file:///C:/Users/..."
      String customConfigPath = targetXml.toUri().toString();

      Thread serverThread = new Thread(() -> {
         try {
            Main.main(new String[] {customWorkDir, customConfigPath});
         } catch (Exception e) {
            logger.error("Error executing Main.main", e);
         }
      }, "artemis-main-args-test");

      serverThread.start();

      try {
         EmbeddedActiveMQ server = null;
         for (int i = 0; i < 20; i++) {
            server = Main.getEmbeddedServer();
            if (server != null && server.getActiveMQServer() != null && server.getActiveMQServer().isStarted()) {
               break;
            }
            Thread.sleep(500);
         }
         assertNotNull(server, "EmbeddedActiveMQ server instance was never initialized");
         assertNotNull(server.getActiveMQServer(), "ActiveMQServer was never initialized");
         assertTrue(server.getActiveMQServer().isStarted(), "Server failed to reach started state");

         var config = server.getActiveMQServer().getConfiguration();

         // verify directories from XML
         // use relative paths
         assertEquals("data/journal-embedded", config.getJournalDirectory());
         assertEquals("data/bindings-embedded", config.getBindingsDirectory());
         assertEquals("data/paging-embedded", config.getPagingDirectory());
         assertEquals("data/large-messages-embedded", config.getLargeMessagesDirectory());

         // Verify settings applied from broker.xml
         assertFalse(config.isPersistenceEnabled(), "Persistence setting from broker.xml was not applied");
         assertTrue(config.getName().equals("embedded-broker"), "Name setting from broker.xml was not applied");

      } finally {
         EmbeddedActiveMQ server = Main.getEmbeddedServer();
         if (server != null) {
            try {
               server.stop();
            } catch (Throwable t) {
               logger.warn("Failed to stop EmbeddedActiveMQ server during test cleanup", t);
            }
         }
         serverThread.join(3000);
      }
   }

}
