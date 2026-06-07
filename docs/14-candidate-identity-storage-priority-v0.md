# CarbonStackComms Candidate Identity Storage Priority v0

Status: component-local implementation-priority decision
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/180-v0.5.18-implementation-priority-decision-v0.md

## 1. Purpose

This document records the Comms-side decision that candidate identity storage should be the next narrow implementation target.

This is a decision record only.

No candidate storage is implemented by this document.

## 2. Decision

The next implementation spike should add candidate identity storage.

Preferred storage:

    identity-candidates.json

Preferred owner:

    internal/trust

internal/protocol should remain policy/draft-only.

## 3. Rationale

Candidate identity material is local trust-adjacent state.

It is not provider protocol truth.

It must not be confused with verified trust.

A separate identity-candidates.json file is safer than inserting provider-observed material directly into trust.json.

## 4. Initial states

Initial candidate states should be:

    observed
    pending_review
    unverified
    conflicts_known_device
    rejected

Do not implement verified candidate promotion yet.

## 5. Dev raw-material policy

The first implementation may store raw candidate public identity material for dev comparison.

This must be documented as dev/pre-alpha and future-vault-bound.

Store fingerprint as well.

## 6. Dedupe

First implementation should dedupe by:

    claimed_device_id + fingerprint + source

If claimed_device_id is blank:

    fingerprint + source

## 7. First implementation must not

The first candidate storage spike must not:

    mutate trust.json;
    append trust-events.jsonl;
    mark verified;
    mark changed;
    replace known key material;
    affect send/open/ack behavior;
    wire live provider import;
    expose CLI;
    update registry;
    implement verification ceremony.

## 8. Verify stub

Do not add a verify stub yet.

Verification wording is dangerous until ceremony and promotion semantics are defined.

Registry entries should wait until an actual command/profile/script/API surface exists.

## 9. Research fallback

If implementation becomes too tangled, use an unstable research folder or revisit the storage model.

Possible fallback:

    internal/trust/research/*

Research folder contents must remain non-prod and non-release-facing.

## 10. Next

Expected next work:

    identity_candidates.go
    identity_candidates_test.go

Expected behavior:

    load missing store as empty;
    save/load round trip;
    add candidate;
    deterministic dedupe;
    no trust.json mutation;
    no verified state creation.
