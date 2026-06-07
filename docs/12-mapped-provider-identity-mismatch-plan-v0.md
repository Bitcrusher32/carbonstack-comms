# CarbonStackComms Mapped Provider Identity Mismatch Plan v0

Status: component-local planning record
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/177-v0.5.15-mapped-provider-identity-mismatch-plan-v0.md

## 1. Purpose

This document defines how CarbonStackComms should classify provider/candidate identity material that conflicts with known local device trust state.

This is planning only.

No code is added by this plan.

## 2. Core rule

Provider identity mismatch is a security-relevant observation.

It is not automatically a verified fact.

It must not automatically:

    verify a device;
    replace a known device key;
    mutate trust.json;
    un-revoke a device;
    trust Cypher as identity authority;
    trust sidecar labels as identity authority.

## 3. Current related code

Relevant current code:

    internal/protocol/provider_trust_report.go
    internal/protocol/provider_trust_history_draft.go
    internal/protocol/provider_trust_event_draft.go
    internal/trust/provider_events.go
    internal/trust/trust.go

Current state:

    provider trust reports exist;
    provider history drafts exist;
    provider trust-event drafts exist;
    trust-side provider event append helper exists;
    candidate identity import does not exist;
    mapped mismatch mutation does not exist.

## 4. Classification

No known mapping:

    candidate-only;
    no trust.json mutation;
    no changed state.

Known unverified device, same material:

    continuity observation;
    remain unverified.

Known unverified device, different material:

    review-required conflict;
    strict send blocks.

Known verified device, same material:

    continuity observation;
    verified state remains unchanged.

Known verified device, different material:

    reverify-required;
    strict send blocks;
    later implementation may mark changed only with explicit mapped-mutation policy.

Known changed device:

    preserve changed;
    require reverify.

Known revoked device:

    block promotion;
    do not un-revoke.

Known compromised-reserved device:

    block promotion;
    keep behavior reserved.

## 5. Future event names

Candidate future event names:

    provider_identity_candidate_observed
    provider_identity_candidate_conflict
    provider_identity_continuity_observed
    provider_identity_mismatch_detected
    provider_identity_reverify_required
    provider_identity_changed_mapped
    provider_identity_promotion_blocked_revoked
    provider_identity_promotion_blocked_compromised

Keep existing trust events narrow:

    device_verified requires explicit verification ceremony;
    device_key_changed requires actual trust-state mutation;
    device_revoked requires explicit revocation flow.

## 6. Future implementation gate

A future implementation may mutate trust.json only after:

    candidate/mismatch classification is tested;
    mapping evidence exists;
    no verified identity can be created from provider observation;
    history append behavior is defined;
    strict send blocks changed/reverify states;
    user-visible warning/recovery behavior is defined.

## 7. Next

Recommended next work:

    Relay Space architecture recon / decision record.

Do not implement candidate storage or trust.json mutation yet.
