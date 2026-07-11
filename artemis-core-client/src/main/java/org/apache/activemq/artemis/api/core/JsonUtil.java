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
package org.apache.activemq.artemis.api.core;

import javax.management.openmbean.CompositeData;
import javax.management.openmbean.CompositeDataSupport;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.activemq.artemis.json.JsonArray;
import org.apache.activemq.artemis.json.JsonArrayBuilder;
import org.apache.activemq.artemis.json.JsonNumber;
import org.apache.activemq.artemis.json.JsonObject;
import org.apache.activemq.artemis.json.JsonObjectBuilder;
import org.apache.activemq.artemis.json.JsonString;
import org.apache.activemq.artemis.json.JsonValue;
import org.apache.activemq.artemis.utils.Base64;
import org.apache.activemq.artemis.utils.JsonLoader;
import org.apache.activemq.artemis.utils.ObjectInputStreamWithClassLoader;
import org.apache.activemq.artemis.utils.StringEscapeUtils;

public final class JsonUtil {

   public static JsonArray toJSONArray(final Object[] array) throws Exception {
      JsonArrayBuilder jsonArray = JsonLoader.createArrayBuilder();

      for (Object parameter : array) {
         addToArray(parameter, jsonArray);
      }
      return jsonArray.build();
   }

   public static Object[] fromJsonArray(final JsonArray jsonArray) throws Exception {
      Object[] array = new Object[jsonArray.size()];

      for (int i = 0; i < jsonArray.size(); i++) {
         Object val = jsonArray.get(i);

         if (val instanceof JsonArray jsonArrayValue) {
            Object[] inner = fromJsonArray(jsonArrayValue);

            array[i] = inner;
         } else if (val instanceof JsonObject jsonObject) {

            Map<String, Object> map = new HashMap<>();

            Set<String> keys = jsonObject.keySet();

            for (String key : keys) {
               Object innerVal = jsonObject.get(key);

               if (innerVal instanceof JsonArray jsonArrayValue) {
                  innerVal = fromJsonArray(jsonArrayValue);
               } else if (innerVal instanceof JsonString jsonString) {
                  innerVal = jsonString.getString();
               } else if (innerVal == JsonValue.FALSE) {
                  innerVal = Boolean.FALSE;
               } else if (innerVal == JsonValue.TRUE) {
                  innerVal = Boolean.TRUE;
               } else if (innerVal instanceof JsonNumber jsonNumber) {
                  if (jsonNumber.isIntegral()) {
                     innerVal = jsonNumber.longValue();
                  } else {
                     innerVal = jsonNumber.doubleValue();
                  }
               } else if (innerVal instanceof JsonObject innerJsonObject) {
                  Map<String, Object> innerMap = new HashMap<>();
                  Set<String> innerKeys = innerJsonObject.keySet();
                  for (String k : innerKeys) {
                     innerMap.put(k, innerJsonObject.get(k));
                  }
                  innerVal = innerMap;
               }
               if (CompositeData.class.getName().equals(key)) {
                  Object[] data = (Object[]) innerVal;
                  CompositeData[] cds = new CompositeData[data.length];
                  for (int i1 = 0; i1 < data.length; i1++) {
                     String dataConverted = convertJsonValue(data[i1], String.class).toString();
                     try (ObjectInputStreamWithClassLoader ois = new ObjectInputStreamWithClassLoader(new ByteArrayInputStream(Base64.decode(dataConverted)))) {
                        ois.setAllowList("java.util,java.lang,javax.management");
                        cds[i1] = (CompositeDataSupport) ois.readObject();
                     }
                  }
                  innerVal = cds;
               }

               map.put(key, innerVal);
            }

            array[i] = map;
         } else if (val instanceof JsonString jsonString) {
            array[i] = jsonString.getString();
         } else if (val == JsonValue.FALSE) {
            array[i] = Boolean.FALSE;
         } else if (val == JsonValue.TRUE) {
            array[i] = Boolean.TRUE;
         } else if (val instanceof JsonNumber jsonNumber) {
            if (jsonNumber.isIntegral()) {
               array[i] = jsonNumber.longValue();
            } else {
               array[i] = jsonNumber.doubleValue();
            }
         } else {
            if (val == JsonValue.NULL) {
               array[i] = null;
            } else {
               array[i] = val;
            }
         }
      }

      return array;
   }

   public static JsonValue nullSafe(String input) {
      return new NullableJsonString(input);
   }

   public static void addToObject(final String key, final Object param, final JsonObjectBuilder jsonObjectBuilder) {
      if (param == null) {
         jsonObjectBuilder.addNull(key);
      } else {
         Class<?> paramClass = param.getClass();
         if (paramClass == String.class) {
            jsonObjectBuilder.add(key, (String) param);
         } else if (param instanceof Number n) {
            if (paramClass == Long.class) {
               jsonObjectBuilder.add(key, n.longValue());
            } else if (paramClass == Integer.class) {
               jsonObjectBuilder.add(key, n.intValue());
            } else if (paramClass == Double.class) {
               jsonObjectBuilder.add(key, n.doubleValue());
            } else if (paramClass == Short.class) {
               jsonObjectBuilder.add(key, n.shortValue());
            } else if (paramClass == Byte.class) {
               jsonObjectBuilder.add(key, n.shortValue());
            } else {
               jsonObjectBuilder.add(key, n.doubleValue());
            }
         } else if (paramClass == Boolean.class) {
            jsonObjectBuilder.add(key, (Boolean) param);
         } else if (param instanceof SimpleString s) {
            jsonObjectBuilder.add(key, s.toString());
         } else if (paramClass == byte[].class) {
            jsonObjectBuilder.add(key, toJsonArrayBuilder((byte[]) param));
         } else if (param instanceof Map<?, ?> m) {
            jsonObjectBuilder.add(key, toJsonObject((Map<String, ?>) m));
         } else if (param instanceof Object[] objs) {
            JsonArrayBuilder arr = JsonLoader.createArrayBuilder();
            for (Object o : objs) {
               addToArray(o, arr);
            }
            jsonObjectBuilder.add(key, arr);
         } else if (param instanceof JsonValue jv) {
            jsonObjectBuilder.add(key, jv);
         } else {
            jsonObjectBuilder.add(key, param.toString());
         }
      }
   }

   public static void addToArray(final Object param, final JsonArrayBuilder jsonArrayBuilder) {
      if (param == null) {
         jsonArrayBuilder.addNull();
         return;
      }
      Class<?> clazz = param.getClass();
      if (clazz == String.class) {
         jsonArrayBuilder.add((String) param);
      } else if (param instanceof Number) {
         if (clazz == Long.class) {
            jsonArrayBuilder.add((Long) param);
         } else if (clazz == Integer.class) {
            jsonArrayBuilder.add((Integer) param);
         } else if (clazz == Double.class) {
            jsonArrayBuilder.add((Double) param);
         } else if (clazz == Short.class) {
            jsonArrayBuilder.add((Short) param);
         } else if (clazz == Byte.class) {
            jsonArrayBuilder.add(((Byte) param).shortValue());
         } else {
            jsonArrayBuilder.add(((Number) param).doubleValue());
         }
      } else if (clazz == Boolean.class) {
         jsonArrayBuilder.add((Boolean) param);
      } else if (clazz == byte[].class) {
         jsonArrayBuilder.add(toJsonArrayBuilder((byte[]) param));
      } else if (param instanceof CompositeData[]) {
         CompositeData[] compositeData = (CompositeData[]) param;
         JsonArrayBuilder innerJsonArray = JsonLoader.createArrayBuilder();
         for (Object data : compositeData) {
            innerJsonArray.add(Base64.encodeObject((CompositeDataSupport) data));
         }
         JsonObjectBuilder jsonObject = JsonLoader.createObjectBuilder();
         jsonObject.add(CompositeData.class.getName(), innerJsonArray);
         jsonArrayBuilder.add(jsonObject);
      } else if (param instanceof Object[]) {
         JsonArrayBuilder objectArrayBuilder = JsonLoader.createArrayBuilder();
         for (Object parameter : (Object[]) param) {
            addToArray(parameter, objectArrayBuilder);
         }
         jsonArrayBuilder.add(objectArrayBuilder);
      } else if (param instanceof Map) {
         jsonArrayBuilder.add(toJsonObject((Map<String, ?>) param));
      } else if (param instanceof JsonValue) {
         jsonArrayBuilder.add((JsonValue) param);
      } else {
         jsonArrayBuilder.add(param.toString());
      }
   }

   public static JsonArray toJsonArray(List<String> strings) {
      JsonArrayBuilder array = JsonLoader.createArrayBuilder();
      if (strings != null) {
         for (String connector : strings) {
            array.add(connector);
         }
      }
      return array.build();
   }

   public static JsonObject toJsonObject(Map<String, ?> map) {
      JsonObjectBuilder jsonObjectBuilder = JsonLoader.createObjectBuilder();
      if (map != null) {
         for (Map.Entry<String, ?> entry : map.entrySet()) {
            addToObject(entry.getKey(), entry.getValue(), jsonObjectBuilder);
         }
      }
      return jsonObjectBuilder.build();
   }

   public static JsonArrayBuilder toJsonArrayBuilder(byte[] byteArray) {
      JsonArrayBuilder jsonArrayBuilder = JsonLoader.createArrayBuilder();
      if (byteArray != null) {
         for (int i = 0; i < byteArray.length; i++) {
            jsonArrayBuilder.add(((Byte) byteArray[i]).shortValue());
         }
      }
      return jsonArrayBuilder;
   }

   public static JsonArray readJsonArray(String jsonString) {
      return JsonLoader.readArray(new StringReader(jsonString));
   }

   public static JsonObject readJsonObject(String jsonString) {
      return JsonLoader.readObject(new StringReader(jsonString));
   }

   public static Map<String, String> readJsonProperties(String jsonString) {
      Map<String, String> properties = new HashMap<>();
      if (jsonString != null) {
         JsonUtil.readJsonObject(jsonString).entrySet().forEach(e -> properties.put(e.getKey(), e.getValue().toString()));
      }
      return properties;
   }

   public static Object convertJsonValue(Object jsonValue, Class desiredType) {
      if (jsonValue instanceof JsonNumber number) {

         if (desiredType == null || desiredType == Long.class || desiredType == Long.TYPE) {
            return number.longValue();
         } else if (desiredType == Integer.class || desiredType == Integer.TYPE) {
            return number.intValue();
         } else if (desiredType == Double.class || desiredType == Double.TYPE) {
            return number.doubleValue();
         } else {
            return number.longValue();
         }
      } else if (jsonValue instanceof JsonString jsonString) {
         return jsonString.getString();
      } else if (jsonValue instanceof JsonValue) {
         if (jsonValue == JsonValue.TRUE) {
            return true;
         } else if (jsonValue == JsonValue.FALSE) {
            return false;
         } else {
            return jsonValue.toString();
         }
      } else if (jsonValue instanceof Number jsonNumber) {
         if (desiredType == Integer.TYPE || desiredType == Integer.class) {
            return jsonNumber.intValue();
         } else if (desiredType == Long.TYPE || desiredType == Long.class) {
            return jsonNumber.longValue();
         } else if (desiredType == Double.TYPE || desiredType == Double.class) {
            return jsonNumber.doubleValue();
         } else if (desiredType == Short.TYPE || desiredType == Short.class) {
            return jsonNumber.shortValue();
         } else {
            return jsonValue;
         }
      } else if (jsonValue instanceof Object[] objects) {
         Object[] result;
         if (desiredType != null) {
            result = (Object[]) Array.newInstance(desiredType, objects.length);
         } else {
            result = objects;
         }
         for (int i = 0; i < objects.length; i++) {
            result[i] = convertJsonValue(objects[i], desiredType);
         }
         return result;
      } else {
         return jsonValue;
      }
   }

   private JsonUtil() {
   }

   public static String truncateString(final String str, final int valueSizeLimit) {
      int stringLength = str.length();
      if (valueSizeLimit >= 0 && stringLength > valueSizeLimit) {
         return str.substring(0, valueSizeLimit) + ", + " + (stringLength - valueSizeLimit) + " more";
      } else {
         return str;
      }
   }

   public static Object truncate(final Object value, final int valueSizeLimit) {
      if (value == null) {
         return "";
      }
      if (valueSizeLimit >= 0) {
         if (value instanceof String str) {
            return truncateString(str, valueSizeLimit);
         }
         if (value.getClass().isArray()) {
            if (value instanceof byte[] bytes) {
               if (bytes.length > valueSizeLimit) {
                  byte[] result = new byte[valueSizeLimit];
                  System.arraycopy(bytes, 0, result, 0, valueSizeLimit);
                  return result;
               }
            } else if (value instanceof char[] chars) {
               if (chars.length > valueSizeLimit) {
                  char[] result = new char[valueSizeLimit];
                  System.arraycopy(chars, 0, result, 0, valueSizeLimit);
                  return result;
               }
            }
         }
      }
      return value;
   }   

   public static JsonObject mergeAndUpdate(JsonObject source, JsonObject update) {
      // all immutable so we need to create new merged instance
      JsonObjectBuilder jsonObjectBuilder = JsonLoader.createObjectBuilder();
      for (Map.Entry<String, JsonValue> entry : source.entrySet()) {
         jsonObjectBuilder.add(entry.getKey(), entry.getValue());
      }
      // apply any updates
      for (String updateKey : update.keySet()) {
         JsonValue updatedValue = update.get(updateKey);
         if (updatedValue != null) {
            if (!source.containsKey(updateKey)) {
               jsonObjectBuilder.add(updateKey, updatedValue);
            } else {
               // recursively merge into new value
               if (updatedValue.getValueType() == JsonValue.ValueType.OBJECT) {
                  jsonObjectBuilder.add(updateKey, mergeAndUpdate(source.getJsonObject(updateKey), updatedValue.asJsonObject()));

               } else if (updatedValue.getValueType() == JsonValue.ValueType.ARRAY) {
                  JsonArrayBuilder jsonArrayBuilder = JsonLoader.createArrayBuilder();

                  // update wins
                  JsonArray updatedArrayValue = update.getJsonArray(updateKey);
                  JsonArray sourceArrayValue = source.getJsonArray(updateKey);

                  for (int i = 0; i < updatedArrayValue.size(); i++) {
                     if (i < sourceArrayValue.size()) {
                        JsonValue element = updatedArrayValue.get(i);
                        if (element.getValueType() == JsonValue.ValueType.OBJECT) {
                           jsonArrayBuilder.add(mergeAndUpdate(sourceArrayValue.getJsonObject(i), updatedArrayValue.getJsonObject(i)));
                        } else {
                           // take the update
                           jsonArrayBuilder.add(element);
                        }
                     } else {
                        jsonArrayBuilder.add(updatedArrayValue.get(i));
                     }
                  }
                  jsonObjectBuilder.add(updateKey, jsonArrayBuilder.build());
               } else {
                  // update wins!
                  jsonObjectBuilder.add(updateKey, updatedValue);
               }
            }
         }
      }

      return jsonObjectBuilder.build();
   }

   // component path, may contain x/y/z as a pointer to a nested object
   public static JsonObjectBuilder objectBuilderWithValueAtPath(String componentPath, JsonValue componentStatus) {
      JsonObjectBuilder jsonObjectBuilder = JsonLoader.createObjectBuilder();
      String[] nestedComponents = componentPath.split("/", 0);
      // may need to nest this status in objects
      for (int i = nestedComponents.length - 1; i > 0; i--) {
         JsonObjectBuilder nestedBuilder = JsonLoader.createObjectBuilder();
         nestedBuilder.add(nestedComponents[i], componentStatus);
         componentStatus = nestedBuilder.build();
      }
      jsonObjectBuilder.add(nestedComponents[0], componentStatus);
      return jsonObjectBuilder;
   }


   private static class NullableJsonString implements JsonValue, JsonString {

      private final String value;
      private String escape;

      NullableJsonString(String value) {
         if (value == null || value.isEmpty()) {
            this.value = null;
         } else {
            this.value = value;
         }
      }

      @Override
      public ValueType getValueType() {
         return value == null ? ValueType.NULL : ValueType.STRING;
      }

      @Override
      public String getString() {
         return this.value;
      }

      @Override
      public CharSequence getChars() {
         return getString();
      }

      @Override
      public String toString() {
         if (this.value == null) {
            return null;
         }
         String s = this.escape;
         if (s == null) {
            s = '\"' + StringEscapeUtils.escapeString(this.value) + '\"';
            this.escape = s;
         }
         return s;
      }
   }

   /**
    * Converts a JSON array from the specified key in a JsonObject into a comma-separated string. If the key does not
    * exist or if its value is not a JSON array, then an empty string is returned.
    *
    * @param jsonObject the JsonObject from which to retrieve the array
    * @param key        the key associated with the JSON array in the JsonObject
    * @return a comma-separated string representation of the array's elements, or an empty string if the key does not
    * exist or the value is not an array
    */
   public static String arrayToString(JsonObject jsonObject, String key) {
      JsonValue value = jsonObject.get(key);
      if (value == null || value.getValueType() != JsonValue.ValueType.ARRAY) {
         return "";
      }
      return jsonObject.getJsonArray(key).stream().map((s) -> ((JsonString) s).getString()).collect(Collectors.joining(", "));
   }
}
