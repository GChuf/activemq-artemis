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
package org.apache.activemq.artemis.core.server.management;

import javax.management.ObjectName;

import org.apache.activemq.artemis.core.server.management.JMXAccessControlList.Access;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;
import java.util.HashSet;

import java.util.Set;
public class JMXAccessControlList {
   private static final String WILDCARD = "*";

   private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

   /*
   private final Map<ObjectName, Map<String, String>> keyPropertyCache = 
      Collections.synchronizedMap(new LinkedHashMap<ObjectName, Map<String, String>>(1024, 0.75f, true) {
         @Override
         protected boolean removeEldestEntry(Map.Entry<ObjectName, Map<String, String>> eldest) {
               return size() > 30000;
         }
      });
*/
   private final Map<String, Map<String, String>> keyPropertyCache = 
      Collections.synchronizedMap(new LinkedHashMap<String, Map<String, String>>(128, 0.75f, true) {
         @Override
         protected boolean removeEldestEntry(Map.Entry<String, Map<String, String>> eldest) {
               return size() > 5000; 
         }
      });

private final Map<String, TreeMap<String, Access>> domainCache = 
    Collections.synchronizedMap(new LinkedHashMap<String, TreeMap<String, Access>>(128, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, TreeMap<String, Access>> eldest) {
            return size() > 5000;
        }
    });


// Cache Key: Domain Name
// Cache Value: Map where Key is "prefix" (e.g. "address") and Value is List of matching Access objects
private final Map<String, Map<String, List<Access>>> bucketedDomainCache = 
    Collections.synchronizedMap(new LinkedHashMap<String, Map<String, List<Access>>>(128, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Map<String, List<Access>>> eldest) {
            return size() > 10000; // Smaller limit as this is a more complex object
        }
    });


   private Access defaultAccess = new Access(WILDCARD);
   private ConcurrentMap<String, TreeMap<String, Access>> domainAccess = new ConcurrentHashMap<>();
   private ConcurrentMap<String, TreeMap<String, Access>> allowList = new ConcurrentHashMap<>();
   private Comparator<String> keyComparator = (key1, key2) -> {
      boolean key1ContainsWildCard = key1.contains(WILDCARD);
      boolean key2ContainsWildcard = key2.contains(WILDCARD);
      if (key1ContainsWildCard && !key2ContainsWildcard) {
         return +1;
      } else if (!key1ContainsWildCard && key2ContainsWildcard) {
         return -1;
      } else if (key1.length() == key2.length()) {
         return key1.compareTo(key2);
      }

      return key2.length() - key1.length();
   };

   public void addToAllowList(String domain, String key) {
      TreeMap<String, Access> domainMap = new TreeMap<>(keyComparator);
      domainMap = allowList.putIfAbsent(domain, domainMap);
      if (domainMap == null) {
         domainMap = allowList.get(domain);
      }
      Access access = new Access(domain, normalizeKey(key));
      domainMap.putIfAbsent(access.getKey(), access);
   }






   public boolean getRolesForObject2(ObjectName objectName, String methodName, Set<String> userRoles) {
      //logger.warn("getRolesForObject called with object name {}", objectName);
      long t0 = System.nanoTime();
      //TreeMap<String, Access> domainMap = domainAccess.get(objectName.getDomain());
      //logger.warn("getRolesForObject domain map lookup time: {} ns", (t1 - t0)); //500ns
      String domainKey = objectName.getDomain();

      // computeIfAbsent is atomic and more efficient than manual null checks
      /*
      TreeMap<String, Access> domainMap = domainCache.computeIfAbsent(domainKey, key -> 
         domainAccess.get(key)
      );
*/
      TreeMap<String, Access> domainMap = domainCache.computeIfAbsent(objectName.getDomain(), key -> 
         domainAccess.get(key)
      );


// 1. Get or Build the Bucketed Map for this domain
    Map<String, List<Access>> bucketedMap = bucketedDomainCache.computeIfAbsent(domainKey, d -> {
        TreeMap<String, Access> rawMap = domainAccess.get(d);
        if (rawMap == null) return null;

        Map<String, List<Access>> grouped = new HashMap<>();
        for (Access access : rawMap.values()) {
            String pattern = access.getKeyPattern().pattern();
            // Extract prefix (e.g., "address" from "address=QUEUE.A")
            int eqIndex = pattern.indexOf('=');
            String prefix = (eqIndex != -1) ? pattern.substring(0, eqIndex) : "";
            
            grouped.computeIfAbsent(prefix, k -> new ArrayList<>()).add(access);
        }
        return grouped;
    });





      if (bucketedMap != null) {
         //Map<String, String> keyPropertyList = objectName.getKeyPropertyList();
         // 1. CACHE LOOKUP: Avoid the expensive objectName.getKeyPropertyList() clone
         // SynchronizedMap handles thread safety; LinkedHashMap handles the LRU logic.
         //Map<String, String> keyPropertyList = keyPropertyCache.computeIfAbsent(objectName, name -> name.getKeyPropertyList());
         String cacheKey = objectName.getCanonicalName();
         Map<String, String> keyPropertyList = keyPropertyCache.computeIfAbsent(cacheKey, k -> 
            objectName.getKeyPropertyList()
         );

         long t1 = System.nanoTime();

         //logger.warn("keyPropertyCache retrieval time: {} ns", (t1 - t0)); //4000 ns -> to 200ns with cache

         for (Map.Entry<String, String> keyEntry : keyPropertyList.entrySet()) {


            // filter out "prefixes"

            // accessEntry.getKeyPattern().pattern() should start with keyEntry.getKey() (queue, address, ...) 
            // only after that check for keyEntry.getValue() match
            String prefixFilter = keyEntry.getKey() + "="; // e.g., "address="



            //filter out relevant access entries based on prefix 

            List<Access> relevantAccessEntries = bucketedMap.get(keyEntry.getKey());


            if (relevantAccessEntries != null) {
               String key = normalizeKey(prefixFilter + keyEntry.getValue()); //gasperc todo save this together with keyPropertyCache
               
               for (Access access : relevantAccessEntries) {
                  String rawPattern = access.getKeyPattern().pattern();
                  
                  // Still need to check specific value, but only for the correct prefix
                     if (key.equals(rawPattern)) { 
                        //logger.warn("exact match");
                        return true;
                     }

                     // regexp check if previous did not return true
                     if (access.getKeyPattern().matcher(key).matches()) {
                        //logger.warn("regex match");
                        return true;
                     }
               }
            }

            //2026-04-25 12:14:16,759 WARN  [org.apache.activemq.artemis.core.server.management.JMXAccessControlList] DEBUG: Testing Pair [address=QUEUE.ADDRESS619] against Pattern [queue=DLQ.QUEUE.ADDRESS110]

         }

         Access access = domainMap.get("");
         if (access != null) {
            return access.getMatchingRolesForMethod2(methodName, userRoles);
         }
      }

      return defaultAccess.getMatchingRolesForMethod2(methodName, userRoles);
   }


   public boolean isInAllowList(ObjectName objectName) {
      TreeMap<String, Access> domainMap = allowList.get(objectName.getDomain());

      if (domainMap == null) {
         domainMap = allowList.get(WILDCARD);
      }

      if (domainMap != null) {
         if (domainMap.containsKey("")) {
            return true;
         }

         Map<String, String> keyPropertyList = objectName.getKeyPropertyList();
         for (Map.Entry<String, String> keyEntry : keyPropertyList.entrySet()) {
            String key = normalizeKey(keyEntry.getKey() + "=" + keyEntry.getValue());
            for (Access accessEntry : domainMap.values()) {
               if (accessEntry.getKeyPattern().matcher(key).matches()) {
                  return true;
               }
            }
         }
      }

      return false;
   }

   public void addToDefaultAccess(String method, String... roles) {
      if (roles != null) {
         if (method.equals(WILDCARD)) {
            defaultAccess.addCatchAll(roles);
         } else if (method.endsWith(WILDCARD)) {
            String prefix = method.replace(WILDCARD, "");
            defaultAccess.addMethodsPrefixes(prefix, roles);
         } else {
            defaultAccess.addMethods(method, roles);
         }
      }
   }

   public void addToRoleAccess(String domain, String key, String method, String... roles) {
      TreeMap<String, Access> domainMap = new TreeMap<>(keyComparator);
      domainMap = domainAccess.putIfAbsent(domain, domainMap);
      if (domainMap == null) {
         domainMap = domainAccess.get(domain);
      }

      String accessKey = normalizeKey(key);
      Access access = domainMap.get(accessKey);
      if (access == null) {
         access = new Access(domain, accessKey);
         domainMap.put(accessKey, access);
      }

      if (method.equals(WILDCARD)) {
         access.addCatchAll(roles);
      } else if (method.endsWith(WILDCARD)) {
         String prefix = method.replace(WILDCARD, "");
         access.addMethodsPrefixes(prefix, roles);
      } else {
         access.addMethods(method, roles);
      }
   }

   private String normalizeKey(final String key) {
      if (key == null) {
         return "";
      } else if (key.endsWith("\"")) {
         return key.replace("\"", "");
      }
      return key;
   }

   static class Access {
      private final String id;
      private final String key;
      private final Pattern keyPattern;
      List<String> catchAllRoles = new ArrayList<>();
      Map<String, List<String>> methodRoles = new HashMap<>();
      Map<String, List<String>> methodPrefixRoles = new LinkedHashMap<>();

      Access(String id) {
         this(id, "");
      }

      Access(String id, String key) {
         this.id = id;
         this.key = key;
         this.keyPattern = Pattern.compile(key.replace(WILDCARD, ".*"));
      }

      public synchronized void addMethods(String prefix, String... roles) {
         List<String> rolesList = methodRoles.get(prefix);
         if (rolesList == null) {
            rolesList = new ArrayList<>();
            methodRoles.put(prefix, rolesList);
         }
         for (String role : roles) {
            rolesList.add(role);
         }
      }

      public synchronized void addMethodsPrefixes(String prefix, String... roles) {
         List<String> rolesList = methodPrefixRoles.get(prefix);
         if (rolesList == null) {
            rolesList = new ArrayList<>();
            methodPrefixRoles.put(prefix, rolesList);
         }
         for (String role : roles) {
            rolesList.add(role);
         }
      }

      public void addCatchAll(String... roles) {
         for (String role : roles) {
            catchAllRoles.add(role);
         }
      }

      public String getId() {
         return id;
      }

      public String getKey() {
         return key;
      }

      public Pattern getKeyPattern() {
         return keyPattern;
      }

      public List<String> getMatchingRolesForMethod(String methodName) {
         List<String> roles = methodRoles.get(methodName);
         if (roles != null) {
            return roles;
         }
         for (Map.Entry<String, List<String>> entry : methodPrefixRoles.entrySet()) {
            if (methodName.startsWith(entry.getKey())) {
               return entry.getValue();
            }
         }
         return catchAllRoles;
      }

      public boolean getMatchingRolesForMethod2(String methodName, Set<String> userRoles) {
         //gasperc use hashset insteadf of list for userRoles
         List<String> roles = methodRoles.get(methodName);

         if (roles != null) {
            for (String role : roles) {
               if (userRoles.contains(role)) {
                  return true;
               }
            }
         }

         /*
         if (roles != null) {
            boolean contains = !Collections.disjoint(roles, userRoles); //for list




            return contains;
         }
         */


         for (Map.Entry<String, List<String>> entry : methodPrefixRoles.entrySet()) {
            if (methodName.startsWith(entry.getKey())) {
               return true;
            }
         }
         return false;
      }

   }

   public static JMXAccessControlList createDefaultList() {
      JMXAccessControlList accessControlList = new JMXAccessControlList();

      accessControlList.addToAllowList("hawtio", "type=*");

      accessControlList.addToRoleAccess("org.apache.activemq.artemis", null, "list*", "view", "update", "amq");
      accessControlList.addToRoleAccess("org.apache.activemq.artemis", null, "get*", "view", "update", "amq");
      accessControlList.addToRoleAccess("org.apache.activemq.artemis", null, "is*", "view", "update", "amq");
      accessControlList.addToRoleAccess("org.apache.activemq.artemis", null, "set*", "update", "amq");
      accessControlList.addToRoleAccess("org.apache.activemq.artemis", null, WILDCARD, "amq");

      accessControlList.addToDefaultAccess("list*", "view", "update", "amq");
      accessControlList.addToDefaultAccess("get*", "view", "update", "amq");
      accessControlList.addToDefaultAccess("is*", "view", "update", "amq");
      accessControlList.addToDefaultAccess("set*", "update", "amq");
      accessControlList.addToDefaultAccess(WILDCARD, "amq");

      return accessControlList;
   }
}
