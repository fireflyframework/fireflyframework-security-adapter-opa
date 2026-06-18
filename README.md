# Firefly Framework - Security OPA Adapter

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21%2B-orange.svg)](https://openjdk.org)
[![Reactor](https://img.shields.io/badge/Reactor-WebClient-purple.svg)](https://projectreactor.io)
[![OPA](https://img.shields.io/badge/Open%20Policy%20Agent-Rego-7B68EE.svg)](https://www.openpolicyagent.org)

> An Open Policy Agent adapter that externalizes the Firefly security platform's authorization decisions to a real OPA server. It implements the `PolicyDecisionPort` driven port by POSTing each request to OPA's Data API and mapping the Rego result to a `Decision` — **fail-closed**, so any transport error or undefined policy denies.

---

## Table of Contents

- [Overview](#overview)
- [Where it sits in the platform](#where-it-sits-in-the-platform)
- [What it provides](#what-it-provides)
- [Key types](#key-types)
- [The request contract](#the-request-contract)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Testing](#testing)
- [License](#license)

## Overview

This module is a **policy-decision adapter** for the Firefly hexagonal security platform. It moves the ABAC decision out of the application process and into an externally managed Open Policy Agent server, where authorization rules are authored in Rego and versioned independently of the services they govern.

The whole adapter is a single class — `OpaPolicyDecisionAdapter` — implementing the `PolicyDecisionPort` driven port from `security-spi`. For each `authorize(...)` call it builds an OPA `input` document from the `SecurityPrincipal`, the requested `action`, the target `resource`, and the request `context`, POSTs it to a boolean rule under OPA's Data API (`/v1/data/<path>`), and translates the JSON result into a framework `Decision`.

Authorization is **fail-closed by construction**, exactly as `PolicyDecisionPort` mandates. A Rego rule that evaluates to `false`, a policy path whose result is absent (e.g. an undefined or misnamed decision path), and any transport-level failure all resolve to a non-granting `Decision` — `Decision.deny(...)` for an explicit `false`, and `Decision.indeterminate(...)` for an OPA error, both of which callers treat as a denial since only `Effect.PERMIT` grants access. The adapter never throws the error up the chain and never defaults to permit.

It imports no OPA SDK: the only client is a reactive Spring `WebClient`, so the adapter stays non-blocking end to end and carries a minimal dependency surface.

## Where it sits in the platform

The security platform is layered hexagonally; dependencies point inward, and providers attach as outboard adapters:

```
security-api  →  security-spi  →  security-core  →  security-webflux  →  adapters
 (ports +         (driven           (neutral          (reactive             (this module:
  domain)          ports)            engine +          Spring Security        OPA policy-decision
                                     embedded PDP)     bindings)              adapter, + Vault, KMS,
                                                                              Keycloak, Cerbos, …)
```

- **`security-api`** defines the domain this adapter speaks in: `SecurityPrincipal` (the subject) and `Decision` (the outcome, with its `Effect` enum).
- **`security-spi`** defines the driven port this module implements: `PolicyDecisionPort`.
- **`security-core`** ships the in-process default, `EmbeddedPolicyDecisionAdapter`, which this module replaces.
- **`security-webflux`** consumes whichever `PolicyDecisionPort` bean is present through its `PolicyAuthorizationManager`, so swapping the embedded engine for OPA is transparent to the filter chain.
- **This module** is an outboard adapter: contribute an `OpaPolicyDecisionAdapter` bean and every non-permitted exchange is authorized by your OPA server instead of in-process rules.

This adapter depends only on `security-api`, `security-spi`, `spring-webflux`, and `jackson-databind`. It pulls in no vendor SDK and no Spring Boot auto-configuration — it is a plain port implementation you wire as a bean.

## What it provides

`OpaPolicyDecisionAdapter` contributes a single capability: a `PolicyDecisionPort` whose decisions come from a live OPA server.

- **Reactive, SDK-free transport.** Construction takes a `WebClient` whose base URL points at the OPA server plus a `decisionPath` (the OPA data path of the boolean allow rule, e.g. `firefly/allow`). A leading slash on the path is tolerated and stripped. The call is issued against `/v1/data/<decisionPath>` and is non-blocking throughout.
- **A stable `input` shape.** Every request sends OPA an `input` document with a nested `subject` (`subject`, `authorities`, `scopes`, `tenantId` drawn from the `SecurityPrincipal`), plus top-level `action`, `resource`, and `context` (a `null` context is sent as an empty object). Rego policies bind against this contract.
- **Boolean-result mapping.** OPA's `{"result": <bool>}` envelope is deserialized into the internal `OpaResult` record (ignoring unknown fields). `true` maps to `Decision.permit()`; anything else maps to `Decision.deny("denied by OPA policy")`.
- **Fail-closed error handling.** A transport error or any failure during evaluation is logged at WARN and resolved to `Decision.indeterminate("OPA error: …")` rather than propagated — a denial to every caller, never an exception and never a permit.

## Key types

| Type | Role |
| --- | --- |
| `OpaPolicyDecisionAdapter` | `PolicyDecisionPort` implementation; POSTs the `input` document to OPA's Data API and maps the boolean result to a `Decision`, fail-closed. |
| `OpaPolicyDecisionAdapter.OpaResult` | Package-private `record OpaResult(Boolean result)` — the deserialized subset of OPA's data response (`{"result": <bool>}`), `@JsonIgnoreProperties(ignoreUnknown = true)`. |

Port implemented (from `security-spi`): `PolicyDecisionPort`. Domain types consumed (from `security-api`): `SecurityPrincipal`, `Decision` (and its `Decision.Effect`).

## The request contract

For a call `authorize(principal, action, resource, context)`, the adapter POSTs to `/v1/data/<decisionPath>`:

```json
{
  "input": {
    "subject": {
      "subject": "u1",
      "authorities": ["teller"],
      "scopes": ["reports.read"],
      "tenantId": "acme"
    },
    "action": "read",
    "resource": "doc:1",
    "context": {}
  }
}
```

A Rego policy binds against this `input` and exposes a boolean rule at the decision path. For the path `firefly/allow`:

```rego
package firefly

default allow = false

allow {
    input.action == "read"
}

allow {
    input.subject.authorities[_] == "admin"
}
```

OPA replies `{"result": true}` or `{"result": false}`; a path with no defined rule yields a response with no `result`, which the adapter treats as a denial.

## Requirements

- Java 21+
- A reactive web stack (Spring WebFlux / Reactor `WebClient`)
- A reachable Open Policy Agent server exposing the Data API (`/v1/data/...`) and loaded with the Rego policy that exposes your boolean decision path

## Installation

The version is managed by the Firefly parent/BOM, so you can usually omit it. Add the adapter only in deployments that externalize authorization to OPA:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-adapter-opa</artifactId>
</dependency>
```

If you are not inheriting the Firefly parent, pin the version explicitly:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-adapter-opa</artifactId>
    <version>26.06.01</version>
</dependency>
```

## Usage

Contribute an `OpaPolicyDecisionAdapter` as your `PolicyDecisionPort`. Because `security-webflux` selects whatever `PolicyDecisionPort` bean is present, this single bean replaces the in-process `EmbeddedPolicyDecisionAdapter` for every non-permitted exchange — no other wiring required:

```java
import org.fireflyframework.security.adapter.opa.OpaPolicyDecisionAdapter;
import org.fireflyframework.security.spi.PolicyDecisionPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
class OpaPolicyConfiguration {

    @Bean
    PolicyDecisionPort policyDecisionPort() {
        WebClient opa = WebClient.create("http://opa:8181");
        return new OpaPolicyDecisionAdapter(opa, "firefly/allow");
    }
}
```

The decision is consumed reactively and is permit-only:

```java
adapter.authorize(principal, "read", "doc:1", Map.of())
        .map(Decision::granted); // true only when OPA returns result == true
```

## Testing

The module is verified against a **real Open Policy Agent server**, not a mock. `OpaPolicyDecisionAdapterIntegrationTest` is a `@Testcontainers` test that starts the official `openpolicyagent/opa:0.70.0` image (`run --server --addr=0.0.0.0:8181`), waits for OPA's `/health` to return `200`, then uploads a Rego policy through the live Policy API (`PUT /v1/policies/firefly`). The policy permits the `read` action or any subject holding the `admin` authority. Tests drive the adapter with `StepVerifier` and assert every branch of the fail-closed contract:

- **Permit (allowed action).** A non-admin subject performing `read` is granted — `Decision.granted()` is `true`.
- **Permit (admin override).** An `admin` subject performing `write` is granted, proving the second Rego rule fires.
- **Deny (explicit `false`).** A non-admin subject performing `write` evaluates to `false` and is denied.
- **Fail-closed (undefined path).** Pointing the adapter at a non-existent decision path (`firefly/does_not_exist`) returns a non-granting `Decision` even for an `admin` subject — an absent result denies, exactly as production transport errors must.

This exercises the genuine HTTP round-trip, Rego evaluation, and JSON envelope against a containerized OPA, so the permit, explicit-deny, and undefined-path branches are proven, not assumed.

## License

Copyright 2024-2026 Firefly Software Foundation.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
