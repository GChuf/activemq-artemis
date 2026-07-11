/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.activemq.artemis.tests.performance.jmh;

import org.apache.activemq.artemis.api.core.JsonUtil;
import org.apache.activemq.artemis.json.JsonArrayBuilder;
import org.apache.activemq.artemis.json.JsonObjectBuilder;
import org.apache.activemq.artemis.utils.JsonLoader;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Benchmarks JsonUtil.addToObject() and JsonUtil.addToArray() across all
 * supported types. Each benchmark exercises one type to isolate dispatch cost.
 *
 * Run before and after the instanceof-chain → class-equality optimization
 * to measure the improvement per type.
 */
@State(Scope.Benchmark)
@Fork(2)
@Warmup(iterations = 4, time = 1)
@Measurement(iterations = 8, time = 1)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class JsonUtilPerfTest {

   // test values
   private static final String VAL_STRING1 = "hello-world1";
   private static final String VAL_STRING2 = "hello-world22222";
   private static final String VAL_STRING3 = "hello-world3333333333333";
   private static final String VAL_STRING4 = "hello-world4444444444444444444444444";
   private static final Long VAL_LONG1 = 0L;
   private static final Integer VAL_INT1 = 4;
   private static final Long VAL_LONG2 = 123456789L;
   private static final Integer VAL_INT2 = 1000000;
   private static final Double VAL_DOUBLE = 3.14159;
   private static final Boolean VAL_BOOL = Boolean.TRUE;
   private static final Boolean VAL_BOOL2 = Boolean.FALSE;
   private static final Boolean VAL_BOOL3 = Boolean.TRUE;
   private static final Boolean VAL_BOOL4 = Boolean.FALSE;
   private static final Short VAL_SHORT = (short) 7;
   private static final Byte VAL_BYTE = (byte) 3;
   private static final Byte VAL_BYTE2 = (byte) 2;
   private static final Byte VAL_BYTE3 = (byte) 1;
   private static final Byte VAL_BYTE4 = (byte) 0;
   private static final byte[] VAL_BYTES = new byte[]{1, 2, 3, 4, 5};
   private static final byte[] VAL_BYTES2 = new byte[]{1, 2, 3, 4, 5};
   private static final Object[] VAL_ARRAY = new Object[]{"a", 1L, true};
   private static final Map<String, Object> VAL_MAP;

   static {
      VAL_MAP = new LinkedHashMap<>();
      VAL_MAP.put("key1", "value1");
      VAL_MAP.put("key2", 42L);
      VAL_MAP.put("key3", true);
      VAL_MAP.put("key4", 123456);
      VAL_MAP.put("key5", (byte) 0);
      VAL_MAP.put("key6", 3.14159);
   }

   // --- realistic mixed map: models a typical Artemis message property map ---
   private static final Map<String, Object> MIXED_MAP;
   static {
      MIXED_MAP = new LinkedHashMap<>();
      MIXED_MAP.put("_AMQ_ROUTING_TYPE", (byte) 1);
      MIXED_MAP.put("_AMQ_ACTUAL_EXPIRY", 1234567890L);
      MIXED_MAP.put("correlationId", "abc-123-def-456");
      MIXED_MAP.put("priority", 4);
      MIXED_MAP.put("durable", true);
      MIXED_MAP.put("messageId", "ID:producer-001");
      MIXED_MAP.put("replyTo", "queue://reply");
      MIXED_MAP.put("ttl", 60000L);
      MIXED_MAP.put("timestamp", System.currentTimeMillis());
      MIXED_MAP.put("type", "TextMessage");
   }

   // -------------------------------------------------------------------------
   // addToObject benchmarks — one per type
   // -------------------------------------------------------------------------

   @Benchmark
   public JsonObjectBuilder testAddToObjectString() {
      JsonObjectBuilder b = JsonLoader.createObjectBuilder();
      JsonUtil.addToObject("key", VAL_STRING1, b);
      return b;
   }

   @Benchmark
   public JsonObjectBuilder testAddToObjectLong() {
      JsonObjectBuilder b = JsonLoader.createObjectBuilder();
      JsonUtil.addToObject("key", VAL_LONG1, b);
      return b;
   }

   @Benchmark
   public JsonObjectBuilder testAddToObjectInteger() {
      JsonObjectBuilder b = JsonLoader.createObjectBuilder();
      JsonUtil.addToObject("key", VAL_INT1, b);
      return b;
   }

   @Benchmark
   public JsonObjectBuilder testAddToObjectDouble() {
      JsonObjectBuilder b = JsonLoader.createObjectBuilder();
      JsonUtil.addToObject("key", VAL_DOUBLE, b);
      return b;
   }

   @Benchmark
   public JsonObjectBuilder testAddToObjectBoolean() {
      JsonObjectBuilder b = JsonLoader.createObjectBuilder();
      JsonUtil.addToObject("key", VAL_BOOL, b);
      return b;
   }

   @Benchmark
   public JsonObjectBuilder testAddToObjectShort() {
      JsonObjectBuilder b = JsonLoader.createObjectBuilder();
      JsonUtil.addToObject("key", VAL_SHORT, b);
      return b;
   }

   @Benchmark
   public JsonObjectBuilder testAddToObjectByte() {
      JsonObjectBuilder b = JsonLoader.createObjectBuilder();
      JsonUtil.addToObject("key", VAL_BYTE, b);
      return b;
   }

   @Benchmark
   public JsonObjectBuilder testAddToObjectBytes() {
      JsonObjectBuilder b = JsonLoader.createObjectBuilder();
      JsonUtil.addToObject("key", VAL_BYTES, b);
      return b;
   }

   @Benchmark
   public JsonObjectBuilder testAddToObjectNull() {
      JsonObjectBuilder b = JsonLoader.createObjectBuilder();
      JsonUtil.addToObject("key", null, b);
      return b;
   }

   @Benchmark
   public JsonObjectBuilder testAddToObjectMap() {
      JsonObjectBuilder b = JsonLoader.createObjectBuilder();
      JsonUtil.addToObject("key", VAL_MAP, b);
      return b;
   }

   /**
    * Most realistic benchmark — converts a full Artemis message property map
    * to JSON. Exercises all types in a single call, weighted by real usage.
    */
   @Benchmark
   public String testToJsonObjectMixedMap() {
      return JsonUtil.toJsonObject(MIXED_MAP).toString();
   }

   // -------------------------------------------------------------------------
   // addToArray benchmarks — one per type
   // -------------------------------------------------------------------------

   @Benchmark
   public JsonArrayBuilder testAddToArrayString() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(VAL_STRING1, b);
      return b;
   }

   @Benchmark
   public JsonArrayBuilder testAddToArrayLong() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(VAL_LONG1, b);
      return b;
   }

   @Benchmark
   public JsonArrayBuilder testAddToArrayInteger() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(VAL_INT1, b);
      return b;
   }

   @Benchmark
   public JsonArrayBuilder testAddToArrayDouble() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(VAL_DOUBLE, b);
      return b;
   }

   @Benchmark
   public JsonArrayBuilder testAddToArrayBoolean() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(VAL_BOOL, b);
      return b;
   }

   @Benchmark
   public JsonArrayBuilder testAddToArrayShort() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(VAL_SHORT, b);
      return b;
   }

   @Benchmark
   public JsonArrayBuilder testAddToArrayByte() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(VAL_BYTE, b);
      return b;
   }

   @Benchmark
   public JsonArrayBuilder testAddToArrayBytes() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(VAL_BYTES, b);
      return b;
   }

   @Benchmark
   public JsonArrayBuilder testAddToArrayNull() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(null, b);
      return b;
   }

   @Benchmark
   public JsonArrayBuilder testAddToArrayObjectArray() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(VAL_ARRAY, b);
      return b;
   }

   @Benchmark
   public JsonArrayBuilder testAddToArrayMap() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(VAL_MAP, b);
      return b;
   }

   /**
    * Adds all supported types into a single array in one benchmark iteration.
    * Models a realistic mixed-type array — e.g. a JMX operation parameter list
    * or a message body with heterogeneous fields.
    *
    * This is the primary benchmark for comparing before/after the optimization —
    * it exercises the full dispatch path for every type in one measurement.
    */
   @Benchmark
   public JsonArrayBuilder testAddToArrayAllTypes() {
      JsonArrayBuilder b = JsonLoader.createArrayBuilder();
      JsonUtil.addToArray(VAL_STRING1, b);
      JsonUtil.addToArray(VAL_STRING2, b);
      JsonUtil.addToArray(VAL_STRING3, b);
      JsonUtil.addToArray(VAL_STRING4, b);
      JsonUtil.addToArray(VAL_LONG1, b);
      JsonUtil.addToArray(VAL_LONG2, b);
      JsonUtil.addToArray(VAL_INT1, b);
      JsonUtil.addToArray(VAL_INT2, b);
      JsonUtil.addToArray(VAL_DOUBLE, b);
      JsonUtil.addToArray(VAL_BOOL, b);
      JsonUtil.addToArray(VAL_BOOL2, b);
      JsonUtil.addToArray(VAL_BOOL3, b);
      JsonUtil.addToArray(VAL_BOOL4, b);
      JsonUtil.addToArray(VAL_SHORT, b);
      JsonUtil.addToArray(VAL_BYTE, b);
      JsonUtil.addToArray(VAL_BYTE2, b);
      JsonUtil.addToArray(VAL_BYTE3, b);
      JsonUtil.addToArray(VAL_BYTE4, b);
      JsonUtil.addToArray(VAL_BYTES, b);
      JsonUtil.addToArray(VAL_BYTES2, b);
      JsonUtil.addToArray(VAL_ARRAY, b);
      JsonUtil.addToArray(VAL_MAP, b);
      JsonUtil.addToArray(null, b);
      return b;
   }

   @Benchmark
   public JsonObjectBuilder testAddToObjectAllTypes() {
      JsonObjectBuilder b = JsonLoader.createObjectBuilder();
      JsonUtil.addToObject("k1", VAL_STRING1, b);
      JsonUtil.addToObject("k2", VAL_STRING2, b);
      JsonUtil.addToObject("k3", VAL_STRING3, b);
      JsonUtil.addToObject("k4", VAL_STRING4, b);
      JsonUtil.addToObject("k5", VAL_LONG1, b);
      JsonUtil.addToObject("k6", VAL_LONG1, b);
      JsonUtil.addToObject("k7", VAL_INT2, b);
      JsonUtil.addToObject("k8", VAL_INT2, b);
      JsonUtil.addToObject("k9", VAL_DOUBLE, b);
      JsonUtil.addToObject("k10", VAL_BOOL, b);
      JsonUtil.addToObject("k11", VAL_BOOL2, b);
      JsonUtil.addToObject("k12", VAL_BOOL3, b);
      JsonUtil.addToObject("k13", VAL_BOOL4, b);
      JsonUtil.addToObject("k14", VAL_SHORT, b);
      JsonUtil.addToObject("k15", VAL_BYTE, b);
      JsonUtil.addToObject("k16", VAL_BYTE2, b);
      JsonUtil.addToObject("k17", VAL_BYTE3, b);
      JsonUtil.addToObject("k18", VAL_BYTE4, b);
      JsonUtil.addToObject("k19", VAL_BYTES, b);
      JsonUtil.addToObject("k20", VAL_BYTES2, b);
      JsonUtil.addToObject("k21", VAL_ARRAY, b);
      JsonUtil.addToObject("k22", VAL_MAP, b);
      JsonUtil.addToObject("k23", null, b);
      return b;
   }
}