# Comms no-ack-on-failure coverage note

Status: targeted coverage note
Parent: carbonstack/docs/197-v0.5.56-live-negative-path-design-matrix-v0.md
Phase: v0.5.57 Comms no-ack-on-failure recon
Scope: openmls-relay-join-dev ACK_AFTER_JOIN / no-ack-on-failure ownership
Date: 2026-06-09 local session

## 1. Purpose

This note records the v0.5.57 Comms-side recon result for no-ack-on-failure behavior.

The purpose is to avoid duplicating already-covered join failure behavior and to clarify the next remaining failure-path target.

This checkpoint does not add:

    new Comms command;
    new Comms script;
    new Cypher route;
    new Cypher schema;
    new runner profile;
    relay-openmls-join-dev expansion;
    full profile inclusion;
    release-snapshot inclusion;
    trust.json mutation;
    trust-events.jsonl mutation;
    identity-candidates.json mutation;
    candidate observation;
    local-backbone claim;
    hostile-server safety claim;
    metadata-privacy claim;
    production-security claim.

## 2. Current baseline

Current mainline baseline at the start of v0.5.57 recon:

    carbonstack        39e2c23 docs: map Relay OpenMLS negative-path hardening
    carbonstack-comms  a62391b docs: define Relay OpenMLS validation state contract
    carbonstack-cypher 59b74c9 docs: define local Cypher validation state contract
    carbonstack-os     1bbbe52 docs: clarify CarbonStackOS target direction

v0.5.57 recon reran:

    go run . --profile relay-openmls-join-dev --compact-summary

and the positive-path profile remained healthy.

## 3. Ack rule being protected

The protected rule is:

    Welcome ack is optional.
    Welcome is not acked by default.
    Welcome may be acked only when ACK_AFTER_JOIN / --ack-after-join is explicitly requested.
    Welcome ack may occur only after sidecar conversation-join succeeds.
    Ack is local-processing / delivery state, not identity verification or trust.

KeyPackage is not acked by the narrow join smoke script.

Add-member does not ack the KeyPackage.

Add-member does not ack the Welcome.

## 4. Current Comms join-path test coverage

Recon found existing focused Comms tests for openmls-relay-join-dev:

    TestOpenMLSRelayJoinDevRequiresCoreArgs
    TestOpenMLSRelayJoinDevWritesWelcomeRunsSidecarWithoutAckByDefault
    TestOpenMLSRelayJoinDevAcksOnlyAfterJoinSuccessWhenRequested
    TestOpenMLSRelayJoinDevDoesNotAckWhenSidecarJoinFails
    TestOpenMLSRelayJoinDevDoesNotAckWhenWelcomeWriteFails
    TestOpenMLSRelayJoinDevRejectsNoWelcomeEnvelopes

Interpretation:

    the first intended v0.5.57 target, no ack when sidecar conversation-join fails, is already covered at the Comms command-test layer.

    no ack when Welcome write fails is also already covered.

    no Welcome envelope behavior is already covered.

    ack-after-join success behavior is already covered.

Therefore, adding another join-failure unit test now would mostly duplicate existing coverage.

## 5. Relationship to v0.5.56 matrix

v0.5.56 assigned failure-path ownership as:

    Cypher tests:
        routing and ack authorization boundaries;
        wrong Relay Space ack;
        wrong recipient ack;
        missing Relay Space scoped routes.

    Comms tests:
        sidecar/write/join/add-member behavior;
        no ack on sidecar failure;
        no ack on write failure;
        no trust/candidate mutation.

    Runner tests:
        DB assertion behavior;
        compact summary behavior;
        stale generated-state refusal;
        trust/candidate absence checks.

v0.5.57 confirms that the Comms join side of this matrix is stronger than initially assumed.

## 6. Remaining high-value gap

The next higher-value Comms gap is add-member / KeyPackage-to-Welcome failure behavior, not join failure.

Candidate v0.5.58 target:

    openmls-relay-add-member-dev sidecar conversation-add-member failure;
    prove no KeyPackage ack;
    prove no Welcome ack;
    prove no success output;
    preserve clear command failure;
    preserve no trust/candidate mutation.

Related add-member failure surfaces:

    missing KeyPackage envelope;
    KeyPackage artifact write failure;
    sidecar conversation-add-member failure;
    missing welcome_artifact_path_hint;
    Welcome submit failure after sidecar success.

## 7. Placement rule

Do not put this coverage into relay-openmls-join-dev by default.

relay-openmls-join-dev remains the positive-path local/dev profile:

    no-ack subrun;
    ACK_AFTER_JOIN subrun;
    compact summary;
    strict nonclaims;
    runner-owned temp state.

Negative/failure cases should remain targeted:

    Comms command tests for command behavior;
    Cypher API tests for routing/ack authorization;
    runner helper tests for DB/output assertions;
    separate runner negative profile only if later release-readiness needs live runner-level evidence.

## 8. Nonclaims

This note does not claim:

    local-backbone;
    production secure messaging;
    hostile-server safety;
    metadata privacy;
    verified identity;
    secure enrollment;
    candidate acceptance;
    trust mutation;
    deployability;
    release-package readiness;
    audit;
    certification.
