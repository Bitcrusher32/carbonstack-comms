# CarbonStackComms Candidate Review/Update Priority v0

Status: component-local implementation-priority decision
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/181-v0.5.21-candidate-review-update-priority-decision-v0.md

## 1. Purpose

This document records the Comms-side decision that candidate review/update mechanics should be implemented before candidate/mismatch trust-history append integration.

This is a decision record only.

No review/update implementation is added by this document.

## 2. Decision

Next implementation target:

    candidate review/update mechanics.

Later target:

    candidate/mismatch trust-history append integration.

## 3. Rationale

Candidate state should become locally updateable before history append integration is added.

Append integration will be safer once candidate review/reject/unverified/conflict transitions are explicit and tested.

## 4. Expected first implementation

Expected files:

    internal/trust/identity_candidate_review.go
    internal/trust/identity_candidate_review_test.go

Expected behavior:

    update candidate by candidate_id;
    optionally update candidate by deterministic dedupe key;
    mark pending_review;
    mark rejected;
    mark unverified;
    mark conflicts_known_device;
    preserve source/provenance and raw identity material;
    write only identity-candidates.json.

## 5. Transition policy

Suggested initial allowed transitions:

    observed -> pending_review
    observed -> rejected
    observed -> unverified
    observed -> conflicts_known_device

    pending_review -> rejected
    pending_review -> unverified
    pending_review -> conflicts_known_device

    conflicts_known_device -> pending_review
    conflicts_known_device -> rejected

    unverified -> rejected

Do not allow:

    any state -> verified;
    rejected -> unverified;
    rejected -> pending_review;
    unverified -> verified;
    conflicts_known_device -> verified.

## 6. First implementation must not

Candidate review/update must not:

    mutate trust.json;
    append trust-events.jsonl;
    mark verified;
    mark changed;
    replace known key material;
    affect send/open/ack behavior;
    wire live provider import;
    expose CLI;
    update registry;
    implement verification ceremony;
    create local-backbone.

## 7. CLI and registry

Do not add CLI or registry entries yet.

Candidate review/update remains internal trust mechanics until local-backbone is ready enough to expose honestly.

## 8. Next

Recommended next work:

    v0.5.22 candidate review/update mechanics spike.

After that:

    candidate/mismatch trust-history append integration.
