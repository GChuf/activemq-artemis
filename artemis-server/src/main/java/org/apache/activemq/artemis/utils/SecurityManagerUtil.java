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
package org.apache.activemq.artemis.utils;

import javax.security.auth.Subject;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import org.apache.activemq.artemis.core.security.CheckType;
import org.apache.activemq.artemis.core.security.Role;
import org.apache.activemq.artemis.core.server.ActiveMQServerLogger;
import org.apache.activemq.artemis.spi.core.security.jaas.RolePrincipal;
import org.apache.activemq.artemis.core.server.ActiveMQMessageBundle;
import org.apache.activemq.artemis.core.server.ActiveMQServerLogger;
import org.apache.activemq.artemis.spi.core.protocol.RemotingConnection;
import org.apache.activemq.artemis.spi.core.security.jaas.RolePrincipal;
import org.apache.activemq.artemis.spi.core.security.jaas.UserPrincipal;
import org.apache.activemq.artemis.utils.ClassloadingUtil;
import org.apache.activemq.artemis.utils.SecurityManagerUtil;
import org.slf4j.Logger;
import java.lang.invoke.MethodHandles;
import org.slf4j.LoggerFactory;
import java.util.Iterator;


public class SecurityManagerUtil {

   private static final String WILDCARD = "*";
   private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

   public static Set<RolePrincipal> getPrincipalsInRole(final CheckType checkType, final Set<Role> roles, final Class rolePrincipalClass) {
      Set principals = new HashSet<>();
      for (Role role : roles) {
         if (checkType.hasRole(role)) {
            try {
               principals.add(SecurityManagerUtil.createGroupPrincipal(role.getName(), rolePrincipalClass));
            } catch (Exception e) {
               ActiveMQServerLogger.LOGGER.failedAddRolePrincipal(e);
            }
         }
      }
      return principals;
   }

   public static String getUserFromSubject(Subject subject, Class<? extends Principal> principalClass) {
      if (subject != null) {
         for (Principal candidate : subject.getPrincipals(principalClass)) {
            return candidate.getName();
         }
      }
      return null;
   }

   public static Object createGroupPrincipal(String name, Class cls) throws Exception {
      if (WILDCARD.equals(name)) {
         // simple match all group principal - match any name and class
         return new Principal() {
            @Override
            public String getName() {
               return WILDCARD;
            }

            @Override
            public boolean equals(Object other) {
               return true;
            }

            @Override
            public int hashCode() {
               return WILDCARD.hashCode();
            }
         };
      }
      Object[] param = new Object[]{name};

      Constructor<?>[] constructors = cls.getConstructors();
      int i;
      Object instance;
      for (i = 0; i < constructors.length; i++) {
         Class<?>[] paramTypes = constructors[i].getParameterTypes();
         if (paramTypes.length != 0 && paramTypes[0].equals(String.class)) {
            break;
         }
      }
      if (i < constructors.length) {
         instance = constructors[i].newInstance(param);
      } else {
         instance = cls.getDeclaredConstructor().newInstance();
         Method[] methods = cls.getMethods();
         i = 0;
         for (i = 0; i < methods.length; i++) {
            Class<?>[] paramTypes = methods[i].getParameterTypes();
            if (paramTypes.length != 0 && methods[i].getName().equals("setName") && paramTypes[0].equals(String.class)) {
               break;
            }
         }

         if (i < methods.length) {
            methods[i].invoke(instance, param);
         } else {
            throw new NoSuchMethodException();
         }
      }

      return instance;
   }

   /**
    * This method tries to match the RolePrincipals in the Subject with the provided Set of Roles and CheckType
    */
   public static boolean authorize(final Subject subject, final Set<Role> roles, final CheckType checkType, final Class rolePrincipalClass) {

      logger.warn("authorizing");
      /*
      if (subject != null) {
         Set<RolePrincipal> rolesWithPermission = getPrincipalsInRole(checkType, roles, rolePrincipalClass);

         // Check the caller's roles
         Set<Principal> rolesForSubject;
         try {
            rolesForSubject = subject.getPrincipals(rolePrincipalClass);
         } catch (Exception e) {
            ActiveMQServerLogger.LOGGER.failedToFindRolesForTheSubject(e);
            return false;
         }
         if (!rolesForSubject.isEmpty() && !rolesWithPermission.isEmpty()) {
            for (Principal subjectRole : rolesForSubject) {
               if (rolesWithPermission.contains(subjectRole)) {
                     return true;
               }
            }
         }
      }
      */


//logging
      boolean authorized2 = false;

      long f0 = System.nanoTime();
      if (authorized2) {
         logger.trace("user is authorized");
      } else {
         logger.trace("user is NOT authorized");
      }
      long f1 = System.nanoTime();
      if (logger.isTraceEnabled()) {
         logger.trace("user is authorized: {}", authorized2);
      }
      long f2 = System.nanoTime();

      logger.warn(
         "Logging: old {}ns | new {}ns",
         (f1 - f0),
         (f2 - f1)
      );


   long t0 = System.nanoTime();

   if (subject != null) {

      // --- getPrincipalsInRole ---
      long t1 = System.nanoTime();
      Set<RolePrincipal> rolesWithPermission =
         getPrincipalsInRole(checkType, roles, rolePrincipalClass);
         //41k
      long t2 = System.nanoTime();

      // --- getPrincipals ---
      Set<Principal> rolesForSubject;
      //31k
      long t3 = System.nanoTime();
      try {
         rolesForSubject = subject.getPrincipals(rolePrincipalClass);
      } catch (Exception e) {
         ActiveMQServerLogger.LOGGER.failedToFindRolesForTheSubject(e);

         long tEnd = System.nanoTime();
         logger.warn("authorize FAILED (exception) total={}ns", (tEnd - t0));
         return false;
      }
      long t4 = System.nanoTime();

long t000 = System.nanoTime();
      boolean authorized = false;
      if (!rolesForSubject.isEmpty() && !rolesWithPermission.isEmpty()) {
         Iterator<Principal> rolesForSubjectIter = rolesForSubject.iterator();
         while (!authorized && rolesForSubjectIter.hasNext()) {
            Iterator<RolePrincipal> rolesWithPermissionIter = rolesWithPermission.iterator();
            Principal subjectRole = rolesForSubjectIter.next();
            while (!authorized && rolesWithPermissionIter.hasNext()) {
               Principal roleWithPermission = rolesWithPermissionIter.next();
               authorized = subjectRole.equals(roleWithPermission);
            }
         }
      }
long t001 = System.nanoTime();
 logger.warn("old loop is={}ns", (t001 - t000));


      // --- loop ---
      long loopStart = System.nanoTime();

      if (!rolesForSubject.isEmpty() && !rolesWithPermission.isEmpty()) {
         for (Principal subjectRole : rolesForSubject) {
            if (rolesWithPermission.contains(subjectRole)) {

               long loopEnd = System.nanoTime();
               long tEnd = loopEnd;

               logger.warn(
                  "authorize SUCCESS total={}ns [perm={}ns, principals={}ns, loop={}ns]",
                  (tEnd - t0),
                  (t2 - t1),
                  (t4 - t3),
                  (loopEnd - loopStart)
               );

               return true;
            }
         }
      }

      long loopEnd = System.nanoTime();
      long tEnd = loopEnd;





      logger.warn(
         "authorize FAIL total={}ns [perm={}ns, principals={}ns, loop={}ns]",
         (tEnd - t0),
         (t2 - t1),
         (t4 - t3),
         (loopEnd - loopStart)
      );
   } else {
      long tEnd = System.nanoTime();
      logger.warn("authorize FAIL (no subject) total={}ns", (tEnd - t0));
   }

      return false;
   }
}
