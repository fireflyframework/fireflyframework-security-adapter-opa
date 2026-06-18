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

import org.fireflyframework.security.api.domain.Decision;
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.fireflyframework.security.spi.PolicyDecisionPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

/**
 * {@link PolicyDecisionPort} backed by Open Policy Agent. Posts the authorization request as OPA
 * {@code input} to a data document (e.g. {@code /v1/data/firefly/allow}) and maps the boolean
 * result to a {@link Decision}. <strong>Fail-closed</strong>: a transport error, a missing result,
 * or {@code false} all deny.
 */
public class OpaPolicyDecisionAdapter implements PolicyDecisionPort {

    private static final Logger log = LoggerFactory.getLogger(OpaPolicyDecisionAdapter.class);

    private final WebClient webClient;
    private final String decisionPath;

    /**
     * @param webClient    a WebClient whose base URL points at the OPA server
     * @param decisionPath the OPA data path of the boolean allow rule, e.g. {@code "firefly/allow"}
     */
    public OpaPolicyDecisionAdapter(WebClient webClient, String decisionPath) {
        this.webClient = webClient;
        this.decisionPath = decisionPath.startsWith("/") ? decisionPath.substring(1) : decisionPath;
    }

    @Override
    public Mono<Decision> authorize(SecurityPrincipal principal, String action, String resource, Map<String, Object> context) {
        Map<String, Object> subject = new HashMap<>();
        subject.put("subject", principal.subject());
        subject.put("authorities", principal.authorities());
        subject.put("scopes", principal.scopes());
        subject.put("tenantId", principal.tenantId());

        Map<String, Object> input = new HashMap<>();
        input.put("subject", subject);
        input.put("action", action);
        input.put("resource", resource);
        input.put("context", context == null ? Map.of() : context);

        return webClient.post()
                .uri("/v1/data/" + decisionPath)
                .bodyValue(Map.of("input", input))
                .retrieve()
                .bodyToMono(OpaResult.class)
                .map(result -> Boolean.TRUE.equals(result.result())
                        ? Decision.permit()
                        : Decision.deny("denied by OPA policy"))
                .onErrorResume(error -> {
                    log.warn("OPA evaluation failed; failing closed: {}", error.getMessage());
                    return Mono.just(Decision.indeterminate("OPA error: " + error.getMessage()));
                });
    }

    /** Subset of the OPA data API response ({@code {"result": <bool>}}). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record OpaResult(Boolean result) {
    }
}
