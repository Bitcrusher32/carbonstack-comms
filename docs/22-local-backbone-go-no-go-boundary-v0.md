# CarbonStackComms Local-Backbone Go/No-Go Boundary v0

Status: component-local go/no-go boundary
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/188-v0.5.34-local-backbone-go-no-go-v0.md

## 1. Purpose

This document records Comms-side implications of the v0.5.34 local-backbone go/no-go reassessment.

This is planning only.

No Comms runtime flow is changed by this document.

## 2. Decision

Local-backbone receives a conditional GO for first narrow implementation planning.

This is not a GO for Comms broad provider live-flow.

The preferred first implementation target is Cypher Relay Space schema/API substrate.

## 3. Comms boundary

Comms must keep:

    local trust authority;
    candidate/review authority;
    recovery classification/orchestration authority;
    provider trust report/history authority;
    send/open/ack policy authority;
    future verification UX authority.

Cypher Relay Space substrate must be consumed later as routing context, not trust truth.

## 4. What Comms must not do next

Do not immediately implement:

    broad provider live-flow;
    automatic provider event import;
    automatic candidate promotion;
    trust.json mutation from provider observation;
    Relay Space membership as trust;
    OpenMLS/provider membership as local verification;
    CLI/registry surfaces;
    local-backbone validation profile.

## 5. Later Comms implementation split

Later Comms work should split into:

    Relay Space client wrapper;
    no-trust-mutation tests;
    candidate handoff for explicit identity material;
    provider/OpenMLS join wiring;
    ack-boundary tests;
    validation profile participation.

Do not combine all of this into one rung.

## 6. Implementation continuity

Before implementation after this planning arc, use the latest LogDoc as a direct continuity anchor and scout relevant planning docs again.

## 7. Nonclaims

This document does not claim:

    Comms local-backbone implementation;
    provider live-flow implementation;
    Relay Space client support;
    verified identity import;
    trust.json mutation;
    CLI/registry exposure;
    production readiness.
