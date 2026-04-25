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
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.*;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 10, time = 1)
@Fork(1)
@State(Scope.Thread)
public class RBACAuthorizePerfTest {

    @Param({"5", "2000"})
    int size;

    private Subject subject;
    private Set<Role> roles;
    private CheckType checkType;
    private Class<RolePrincipal> rolePrincipalClass;

    @Setup(Level.Trial)
    public void setup() {
        rolePrincipalClass = RolePrincipal.class;
        checkType = CheckType.SEND;

        roles = new HashSet<>(size);
        subject = new Subject();

        // create roles
        for (int i = 0; i < size; i++) {
            roles.add(new Role("role" + i, true, true, true, true, true, true, true, true));
        }

        // give subject same roles (full overlap case)
        for (int i = 0; i < size; i++) {
            subject.getPrincipals().add(new RolePrincipal("role" + i));
        }
    }

    @Benchmark
    public boolean authorize(Blackhole bh) {
        boolean result = SecurityManagerUtil.authorize(
                subject,
                roles,
                checkType,
                rolePrincipalClass
        );

        bh.consume(result);
        return result;
    }
}