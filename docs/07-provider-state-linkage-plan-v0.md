# CarbonStackComms Provider-State Linkage Plan v0

Status: component-local linkage plan
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/172-v0.5.6-provider-state-linkage-plan-v0.md

## 1. Purpose

This document records the CarbonStackComms-local provider-state linkage plan.

The current implementation already has:

    internal/protocol/provider_events.go
    internal/protocol/provider_trust.go
    internal/protocol/provider_events_test.go
    internal/protocol/provider_trust_test.go
    internal/trust/trust.go
    docs/06-trust-state-model-v0.md

Current provider-trust policy is pure and pre-integration.

It does not mutate:

    trust.json
    trust-events.jsonl

## 2. Current boundary

Current OpenMLS bootstrap wrappers do not mutate Comms trust state.

Current OpenMLS runtime commands may consult Comms trust state for send policy.

Current provider event descriptors and provider trust decisions classify events, but do not perform user-facing CLI behavior.

This is intentional.

## 3. Local linkage rules

Provider events should not directly rewrite trust state without explicit mapping.

Current default rules:

    normal identity-created / identity-loaded events stay provider-only;
    normal public-bundle events stay setup/history-only;
    normal conversation events stay membership/history-only;
    normal message-protected / message-opened events do not mutate trust;
    trust-security events should become loud;
    terminal-fatal events should stop operations and show recovery path;
    provider identity mismatch should eventually map to changed / reverify-required when a device mapping is known.

## 4. What may mutate trust later

Future trust mutation should be limited to:

    explicit verification;
    explicit revocation;
    explicit recovery/re-enrollment;
    mapped provider identity mismatch;
    mapped provider reverify-required event.

Not enough by itself:

    Cypher device lookup;
    envelope receipt;
    KeyPackage receipt;
    Welcome receipt;
    sidecar label existence;
    provider identity-created;
    provider identity-loaded;
    conversation-created;
    message-opened.

## 5. What should block

Provider decisions should eventually block:

    send when mapped identity changed or reverify is required;
    send when local identity/provider storage is missing in a mature stateful path;
    open when signature invalid, tamper, replay, stale epoch, or group unrecoverable events occur;
    ack when open fails or message is quarantined.

## 6. First implementation spike

Recommended first implementation spike:

    provider-trust decision report.

Requirements:

    non-mutating;
    test-backed;
    reports actions from protocol.DecideProviderTrust;
    does not import provider identity;
    does not write trust.json;
    does not append trust-events.jsonl;
    does not replace send/inbox;
    does not create local-backbone.

Possible implementation shapes:

    formatter/helper for ProviderTrustDecision;
    tests for representative events;
    optional dev-only command later after helper is stable.

## 7. Nonclaims

This document does not claim:

    provider-state linkage implementation;
    production identity safety;
    secure vault storage;
    mature UX;
    local-backbone;
    hostile-server safety;
    PQ/hybrid security;
    audit or certification.
