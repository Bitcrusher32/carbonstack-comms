# CarbonStackComms Provider Live-Flow Boundary v0

Status: component-local provider live-flow planning boundary
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/186-v0.5.32-provider-live-flow-boundary-v0.md

## 1. Purpose

This document records the Comms-side provider/OpenMLS live-flow boundary after Relay Space join/invite/member planning.

This is planning only.

No Comms runtime flow is changed by this document.

## 2. Core decision

Do not broadly wire provider live-flow yet.

Provider live-flow should wait for:

    Relay Space schema/API substrate;
    validation profile boundary planning;
    local-backbone go/no-go reassessment;
    honest cleanup/reset boundaries.

## 3. Current Comms authority

Comms owns:

    local identity state;
    local trust state;
    local trust history;
    identity-candidates.json;
    candidate review/update;
    mapped mismatch classification;
    recovery classification/orchestration;
    provider trust reports/history;
    send/open/ack policy;
    future verification ceremony.

Provider live-flow must stay under this local policy.

## 4. What provider live-flow may do later

A future narrow provider live-flow may:

    call OpenMLS sidecar commands;
    process provider events;
    build provider trust reports;
    build provider trust-history/event drafts;
    append selected trust-history events;
    observe candidate identity material;
    classify candidate vs known-device mismatch;
    classify recovery state;
    block or warn on unsafe state;
    preserve ack-after-open.

## 5. What provider live-flow must not do

Provider live-flow must not:

    verify identity;
    silently replace known key material;
    mutate trust.json from provider observation alone;
    bypass candidate review;
    bypass mismatch classification;
    bypass recovery classification;
    trust Cypher routing membership;
    trust Relay Space membership;
    treat provider/OpenMLS membership as local verification;
    ack before sidecar message-open/consume succeeds.

## 6. Candidate / mismatch / recovery handoff

Provider-observed identity material should enter candidate and review flows.

It may become:

    candidate identity;
    continuity observation;
    review-required conflict;
    reverify-required state;
    changed-candidate state;
    revoked/compromised block.

It must not become verified trust without local verification.

## 7. Relay Space dependency

Relay Space is the routing/conversation container and vector to OpenMLS join.

Comms provider live-flow should not assume Relay Space exists until Cypher schema/API and Comms client wrappers exist.

First implementation should likely be Cypher Relay Space schema/API before broad Comms live-flow.

## 8. Ack boundary

Ack remains sidecar-open/consume gated.

Not enough:

    Relay Space routing membership;
    invite claim;
    envelope retrieval;
    artifact write;
    provider report;
    trust-history append;
    candidate observation;
    recovery classification.

Only successful sidecar message-open/consume may permit ack unless a later negative-ack/quarantine design is explicitly created.

## 9. Future implementation split

Do not combine Relay Space, provider live-flow, validation profile, CLI, and local-backbone into one rung.

Future Comms implementation should likely split:

    Relay Space client wrapper;
    candidate handoff;
    provider/OpenMLS join wiring;
    send/open/ack preservation tests;
    no-trust-mutation tests;
    validation profile integration.

## 10. Nonclaims

This document does not claim:

    provider live-flow implementation;
    Relay Space implementation;
    OpenMLS join automation;
    verified identity import;
    trust.json mutation;
    local-backbone readiness;
    CLI/registry exposure;
    production readiness.
