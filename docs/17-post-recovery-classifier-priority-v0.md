# CarbonStackComms Post-Recovery-Classifier Priority v0

Status: component-local integration-priority decision
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/183-v0.5.27-post-recovery-classifier-priority-decision-v0.md

## 1. Purpose

This document records the Comms-side next-rung decision after the pure reset/recovery classifier.

This is a decision record only.

No recovery-history append implementation is added by this document.

## 2. Decision

Next implementation target:

    recovery-history append helpers.

Later target:

    recovery orchestration/classification composition.

Deferred:

    Relay Space join/invite/member planning;
    local-backbone;
    broad provider live-flow wiring;
    CLI/registry.

## 3. Rationale

The recovery classifier can now classify missing/corrupt/conflicting local trust/candidate states.

The next safe step is to record selected recovery classifications in trust history without mutating trust state.

Recovery-history append helpers should come before recovery orchestration because orchestration will be simpler and safer once classification-to-history conversion is explicit and tested.

## 4. Expected next implementation

Candidate files:

    internal/trust/identity_recovery_events.go
    internal/trust/identity_recovery_events_test.go

Expected behavior:

    convert IdentityRecoveryClassification into an append-only trust-history draft/event;
    append selected recovery events to trust-events.jsonl;
    preserve classification, severity, reason, review/reverify/reenrollment/block flags;
    reject device trust mutation event names;
    prove no trust.json mutation;
    prove no identity-candidates.json mutation.

Candidate recovery event names:

    recovery_clean_local_state
    recovery_missing_trust_store
    recovery_missing_trust_history
    recovery_missing_candidate_store
    recovery_corrupt_trust_store
    recovery_corrupt_trust_history
    recovery_corrupt_candidate_store
    recovery_provider_identity_mismatch
    recovery_candidate_conflict
    recovery_requires_reverify
    recovery_requires_reenrollment
    recovery_blocked_revoked
    recovery_blocked_compromised

## 5. First implementation must not

Recovery-history append helpers must not:

    delete files;
    restore files;
    reset files;
    mutate trust.json;
    mutate identity-candidates.json;
    verify identity;
    replace key material;
    emit device_verified;
    emit device_key_changed;
    emit device_revoked;
    affect send/open/ack behavior;
    expose CLI;
    update registry;
    create local-backbone.

## 6. Relay Space boundary

Relay Space planning should wait until recovery-history and recovery orchestration are clearer.

Join/invite/member lifecycle must not hide identity recovery uncertainty.

## 7. CLI and registry

Do not add CLI or registry entries yet.

Reset/recovery/re-enrollment surfaces are too dangerous and too immature for command exposure.

## 8. Nonclaims

This document does not claim:

    recovery-history append implementation;
    recovery orchestration;
    destructive reset support;
    backup/restore support;
    re-enrollment implementation;
    verified identity import;
    trust mutation;
    local-backbone readiness;
    production readiness.
