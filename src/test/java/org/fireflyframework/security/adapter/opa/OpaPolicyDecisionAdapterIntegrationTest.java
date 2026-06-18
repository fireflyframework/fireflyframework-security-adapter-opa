/*
 * Copyright 2024-2026 Firefly Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.fireflyframework.security.adapter.opa;

import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.Set;

/**
 * Real integration test of the OPA adapter against a live Open Policy Agent server (Docker).
 * Loads a Rego policy that permits the {@code read} action or any subject holding {@code admin},
 * then verifies permit/deny outcomes and fail-closed behaviour for an undefined decision path.
 */
@Testcontainers
class OpaPolicyDecisionAdapterIntegrationTest {

    private static final String POLICY = """
            package firefly

            default allow = false

            allow {
                input.action == "read"
            }

            allow {
                input.subject.authorities[_] == "admin"
            }
            """;

    @Container
    static final GenericContainer<?> OPA = new GenericContainer<>("openpolicyagent/opa:0.70.0")
            .withExposedPorts(8181)
            .withCommand("run", "--server", "--addr=0.0.0.0:8181")
            .waitingFor(Wait.forHttp("/health").forPort(8181).forStatusCode(200));

    static WebClient webClient;

    @BeforeAll
    static void loadPolicy() {
        String baseUrl = "http://" + OPA.getHost() + ":" + OPA.getMappedPort(8181);
        webClient = WebClient.create(baseUrl);
        webClient.put().uri("/v1/policies/firefly")
                .contentType(MediaType.TEXT_PLAIN)
                .bodyValue(POLICY)
                .retrieve()
                .toBodilessEntity()
                .block();
    }

    private SecurityPrincipal principal(Set<String> authorities) {
        return SecurityPrincipal.builder().subject("u1").authorities(authorities).build();
    }

    @Test
    void permitsAllowedActionForAnySubject() {
        OpaPolicyDecisionAdapter adapter = new OpaPolicyDecisionAdapter(webClient, "firefly/allow");
        StepVerifier.create(adapter.authorize(principal(Set.of("teller")), "read", "doc:1", Map.of()))
                .expectNextMatches(d -> d.granted())
                .verifyComplete();
    }

    @Test
    void permitsAdminForAnyAction() {
        OpaPolicyDecisionAdapter adapter = new OpaPolicyDecisionAdapter(webClient, "firefly/allow");
        StepVerifier.create(adapter.authorize(principal(Set.of("admin")), "write", "doc:1", Map.of()))
                .expectNextMatches(d -> d.granted())
                .verifyComplete();
    }

    @Test
    void deniesDisallowedActionForNonAdmin() {
        OpaPolicyDecisionAdapter adapter = new OpaPolicyDecisionAdapter(webClient, "firefly/allow");
        StepVerifier.create(adapter.authorize(principal(Set.of("teller")), "write", "doc:1", Map.of()))
                .expectNextMatches(d -> !d.granted())
                .verifyComplete();
    }

    @Test
    void failsClosedForUndefinedDecisionPath() {
        OpaPolicyDecisionAdapter adapter = new OpaPolicyDecisionAdapter(webClient, "firefly/does_not_exist");
        StepVerifier.create(adapter.authorize(principal(Set.of("admin")), "read", "doc:1", Map.of()))
                .expectNextMatches(d -> !d.granted())
                .verifyComplete();
    }
}
