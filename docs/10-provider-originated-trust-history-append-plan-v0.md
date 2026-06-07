# CarbonStackComms Provider-Originated Trust-History Append Plan v0

Status: component-local planning record
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/175-v0.5.10-provider-originated-trust-history-append-plan-v0.md

## 1. Purpose

This document defines how provider-originated observations may eventually become Comms trust-history entries.

This is planning only.

No provider event currently appends to:

    trust-events.jsonl

No provider event currently mutates:

    trust.json

## 2. Current inputs

Relevant code:

    internal/trust/trust.go
    internal/protocol/provider_events.go
    internal/protocol/provider_trust.go
    internal/protocol/provider_trust_report.go

Relevant docs:

    docs/06-trust-state-model-v0.md
    docs/07-provider-state-linkage-plan-v0.md
    docs/08-provider-trust-report-contract-v0.md
    docs/09-provider-trust-report-exposure-decision-v0.md

## 3. Append rule

Provider-originated trust history should be append-only when an event affects user-visible trust, identity continuity, provider state safety, recovery, or message security.

Do not append ordinary provider lifecycle noise.

## 4. Likely future provider-originated event names

Candidate future event names:

    provider_identity_changed
    provider_reverify_required
    provider_signature_invalid
    provider_tamper_detected
    provider_replay_detected
    provider_epoch_stale
    provider_state_missing
    provider_state_corrupt
    provider_checkpoint_failed
    provider_secret_unavailable
    provider_group_unrecoverable
    provider_invariant_violation

These are not implemented yet.

## 5. No-append cases

Do not append trust history for normal:

    fixture started/completed;
    public bundle created/exported;
    identity loaded when expected;
    storage saved/loaded;
    conversation loaded;
    message protected;
    message opened.

## 6. Append-only cases

Append history later, without trust.json mutation, for:

    signature invalid;
    tamper detected;
    replay detected;
    stale epoch;
    provider state missing/corrupt;
    checkpoint failed;
    secret unavailable;
    group unrecoverable;
    invariant violation.

## 7. Append plus reverify cases

Append and require reverify later for:

    provider identity changed;
    provider reverify required.

If a known Comms device mapping exists later, these may become changed/reverify-required trust-state transitions.

If no mapping exists, do not invent one.

## 8. trust.json boundary

Provider-originated trust-history append is not the same as trust-state mutation.

Do not mutate trust.json from provider event observation alone.

Do not mark a device verified from:

    KeyPackage receipt;
    Welcome receipt;
    Cypher envelope delivery;
    sidecar label existence;
    identity loaded;
    message opened.

## 9. Ack boundary

Trust-history append must not weaken ack policy.

Do not ack unless sidecar message-open succeeds.

Do not ack just because:

    an envelope was retrieved;
    an artifact was written;
    a provider report was generated;
    a trust-history event was appended.

## 10. First implementation spike candidate

A future append spike should be narrow.

Good first candidate:

    helper/test conversion from ProviderTrustReport to a draft trust event shape for a tiny allowlist.

Do not yet:

    import provider identity;
    mutate trust.json;
    append all provider events;
    expose CLI solely for this;
    change ack behavior;
    replace send/inbox.
