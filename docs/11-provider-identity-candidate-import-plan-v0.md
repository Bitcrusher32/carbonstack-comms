# CarbonStackComms Provider Identity Candidate / Unverified Import Plan v0

Status: component-local planning record
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/176-v0.5.14-provider-identity-candidate-import-plan-v0.md

## 1. Purpose

This document defines how CarbonStackComms should think about provider-observed identity material before any implementation of candidate or unverified import.

This is planning only.

No code is added by this plan.

## 2. Core rule

Provider-observed identity material is not trust.

It must not automatically become verified.

It must not silently replace a known device.

It must not let Cypher become an identity authority.

It must not let sidecar labels become identity authority.

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
    runtime provider events are not wired into live append flow yet;
    provider identity import does not exist.

## 4. Candidate identity

Candidate identity means observed identity material stored or represented for review.

Candidate identity does not mean:

    verified;
    safe to trust;
    safe for mature strict send;
    accepted by the user;
    proven by the server.

## 5. Unverified identity

Unverified identity may later become a local trust-state or candidate-state concept.

Unverified identity is known but not verified.

Mature strict send should block unverified identities unless a later explicit override policy exists.

## 6. Storage options

Possible future storage paths:

    trust.json with trust_state=unverified;
    identity-candidates.json;
    append-only trust-events history first;
    future vault-bound pending identity domain.

Current preference:

    plan both trust.json-unverified and separate identity-candidates.json;
    avoid choosing too quickly;
    avoid verified trust.json writes from provider observation.

## 7. Candidate fields

Future candidate records may need:

    candidate_id;
    account_id;
    claimed_device_id;
    sidecar_device_label;
    provider_identity_label;
    public_identity_material;
    fingerprint;
    observed_at;
    source;
    source_detail;
    provider_event_name;
    conversation_label;
    envelope_id;
    keypackage_ref;
    welcome_ref;
    conflict_status;
    note.

claimed_device_id and sidecar_device_label are not proof.

## 8. Conflict behavior

No known mapping:

    record candidate only;
    do not invent verified identity.

Known device, same material:

    record continuity observation if useful;
    do not mutate trust.json.

Known verified device, different material:

    record conflict;
    require reverify;
    later mapped mismatch plan may mark changed.

Known revoked device:

    block promotion and warn.

## 9. Trust-history behavior

Candidate observation may eventually append provider-originated trust history.

Possible future event names:

    provider_identity_candidate_observed
    provider_identity_candidate_conflict
    provider_identity_candidate_promoted_unverified
    provider_identity_candidate_rejected
    provider_identity_candidate_verified_by_ceremony

Do not emit device_verified unless explicit verification ceremony occurred.

## 10. Verification boundary

Candidate import and verification are separate steps.

Verification may later use:

    manual fingerprint comparison;
    QR ceremony;
    hardware-key signed enrollment;
    in-person ceremony;
    recovery/re-enrollment flow.

This plan does not choose the final ceremony.

## 11. Next

Recommended next work:

    mapped provider identity mismatch -> changed/reverify plan.

Do not implement candidate storage until mismatch/reverify policy is clear.
