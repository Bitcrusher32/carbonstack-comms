# CarbonStackComms Post-Recovery-Orchestration Boundary v0

Status: component-local blocker reassessment
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/184-v0.5.30-local-backbone-blocker-reassessment-v0.md

## 1. Purpose

This document records the Comms-side boundary after recovery orchestration / classification composition.

This is a decision record only.

No code is added by this document.

## 2. Current Comms state

Comms now has internal helpers for:

    trust.json load/save;
    trust-events.jsonl append/load;
    identity-candidates.json load/save/add/dedupe;
    mapped identity mismatch classification;
    candidate review/update;
    candidate/mismatch history events;
    candidate observation orchestration;
    recovery classification;
    recovery-history events;
    recovery orchestration.

The recovery orchestration helper can classify local recovery state and optionally append selected recovery-history events.

It is not recovery execution.

## 3. Boundary preserved

Current Comms recovery/candidate/provider helpers do not:

    delete files;
    restore files;
    reset files;
    recover files;
    re-enroll identities;
    verify identity;
    replace key material;
    mutate trust.json from observation;
    mutate identity-candidates.json from recovery;
    emit device_verified from recovery;
    emit device_key_changed from recovery;
    emit device_revoked from recovery;
    affect send/open/ack behavior;
    expose CLI/registry;
    implement Relay Space join;
    implement local-backbone.

## 4. Local-backbone assessment

Comms is closer to local-backbone because candidate, mismatch, and recovery helper layers now exist.

Comms is still not local-backbone-ready because:

    Relay Space join/invite/member semantics are not planned deeply enough;
    provider live-flow wiring boundary is not decided;
    validation profile claims are not ready;
    CLI/registry exposure would overstate maturity;
    mature verification ceremony does not exist;
    broad provider identity import remains forbidden.

## 5. Relay Space next

The next Comms-relevant planning target should be Relay Space recon/planning.

It should define:

    server routing membership;
    provider/MLS membership;
    local verified trust;
    invite/claim/join/member terms;
    what Cypher may store;
    what Comms must decide locally;
    what must fail loudly when recovery/trust state is unsafe.

It should not implement Relay Space yet.

## 6. Provider live-flow boundary

Do not broadly wire provider live-flow yet.

Provider observations must remain unable to:

    verify identity;
    replace key material;
    mutate trust.json;
    bypass candidate review;
    weaken send/open/ack behavior.

## 7. CLI / registry

Do not expose candidate/recovery/Relay Space helpers through CLI or registry yet.

CLI/registry remains a late v0.5.x possibility only after local-backbone and Relay Space claim boundaries are honest.

## 8. Nonclaims

This document does not claim:

    local-backbone readiness;
    Relay Space implementation;
    provider live-flow wiring;
    mature user trust UX;
    verification ceremony;
    verified provider identity import;
    destructive reset support;
    backup/restore support;
    re-enrollment implementation;
    production readiness.
