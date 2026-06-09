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

## 9. v0.5.57 triple-scout coverage diagnosis

After the initial v0.5.57 coverage note was committed, a deeper three-scout review was run to avoid prematurely assuming the remaining failure-path surface.

The scouts were:

    Scout 1:
        add-member / KeyPackage-to-Welcome failure coverage

    Scout 2:
        join / Welcome / ACK_AFTER_JOIN coverage completeness

    Scout 3:
        Cypher / runner / trust-candidate / hygiene gap map

This section records the diff diagnosis from that triple scout.

## 10. Scout 1 result: add-member is partially covered, but remains the next best implementation target

Scout 1 confirmed that `openmls-relay-add-member-dev` already has useful focused coverage.

Existing add-member related tests include:

    TestOpenMLSRelayAddMemberDevRequiresCoreArgs
    TestOpenMLSRelayAddMemberDevWritesKeyPackageRunsSidecarAndSubmitsWelcome
    TestOpenMLSRelayAddMemberDevAllowsWelcomeRecipientOverride
    TestOpenMLSRelayAddMemberDevRejectsNoKeyPackageEnvelopes
    TestOpenMLSRelayAddMemberDevRejectsMissingWelcomeHint

Current interpretation:

    missing KeyPackage envelope behavior is covered;
    positive KeyPackage -> sidecar add-member -> Welcome submit behavior is covered;
    Welcome recipient override behavior is covered;
    missing sidecar welcome_artifact_path_hint behavior is covered.

The remaining higher-value add-member failure gaps are narrower:

    sidecar conversation-add-member returns an error;
    KeyPackage artifact write fails before the sidecar is invoked;
    Welcome submit fails after sidecar success;
    failure output must not print a misleading success status;
    failure paths must not imply KeyPackage ack, Welcome ack, trust mutation, candidate mutation, verified identity, local-backbone, or production-security behavior.

There is still no add-member ack path.

Therefore the add-member failure question is mostly about preserving failure ordering and non-success/nonmutation boundaries, not about implementing ack behavior.

Recommended next implementation target:

    v0.5.58:
        add a targeted Comms test for sidecar conversation-add-member failure.

Preferred assertion shape:

    command returns an error;
    sidecar failure is visible in the error;
    Welcome submit helper is not called;
    success output is not printed;
    no KeyPackage ack or Welcome ack behavior is introduced;
    no trust/candidate files are touched.

## 11. Scout 2 result: join / Welcome / ACK_AFTER_JOIN is already materially covered

Scout 2 confirmed that the originally suspected v0.5.57 implementation target is already covered at the Comms command-test layer.

Existing join related tests include:

    TestOpenMLSRelayJoinDevRequiresCoreArgs
    TestOpenMLSRelayJoinDevWritesWelcomeRunsSidecarWithoutAckByDefault
    TestOpenMLSRelayJoinDevAcksOnlyAfterJoinSuccessWhenRequested
    TestOpenMLSRelayJoinDevDoesNotAckWhenSidecarJoinFails
    TestOpenMLSRelayJoinDevDoesNotAckWhenWelcomeWriteFails
    TestOpenMLSRelayJoinDevRejectsNoWelcomeEnvelopes

Current interpretation:

    no ack by default is covered;
    ACK_AFTER_JOIN success behavior is covered;
    no ack when sidecar conversation-join fails is covered;
    no ack when Welcome artifact write fails is covered;
    no Welcome envelope behavior is covered.

Therefore, another join-failure test would mostly duplicate existing coverage.

Do not expand `relay-openmls-join-dev` to include these join negative cases yet.

The long runner profile should remain positive-path unless a separate negative runner profile is intentionally designed later.

## 12. Scout 3 result: Cypher and runner negative coverage are already strong

Scout 3 confirmed that the Cypher and runner layers already cover the major negative behavior assigned to them by the v0.5.56 matrix.

Cypher focused tests include:

    TestAckIsIdempotentForRecipient
    TestAckRejectsUnknownEnvelope
    TestAckRequiresRecipientDeviceID
    TestAckRejectsWrongRecipient
    TestRelaySpaceHTTPLifecycle
    TestRelaySpaceHTTPRejectsMissingSpaceForSubresources
    TestRelaySpaceHTTPDoesNotExposeTrustOrVerifiedFields
    TestRelaySpaceScopedEnvelopeLifecycle
    TestRelaySpaceScopedEnvelopeRejectsWrongSpaceAndRecipient
    TestRelaySpaceScopedEnvelopeRejectsMissingSpace

Current interpretation:

    wrong recipient ack behavior is covered;
    wrong Relay Space scoped ack behavior is covered;
    missing Relay Space scoped route behavior is covered;
    idempotent ack behavior is covered;
    Relay Space HTTP surface does not expose trust/verified fields.

Runner focused tests include:

    TestRefuseExistingSidecarDevice
    TestAssertRelayOpenMLSDBStateNegativePaths
    TestAssertRelayOpenMLSTrustCandidateAbsentNegativePaths
    TestCollectRelayOpenMLSSubrunResultNegativePaths
    TestExpectRelayOpenMLSDBCountNegativePath

Current interpretation:

    stale sidecar refusal is covered;
    DB assertion negative paths are covered;
    trust/candidate absence negative paths are covered;
    missing KeyPackage/Welcome scalar result collection is covered;
    count mismatch behavior is covered.

Therefore, do not duplicate Cypher ack authorization or runner helper negative checks inside the long positive-path profile right now.

## 13. Hygiene remains separate

Scout 3 still reports the repo-local review artifact:

    carbonstack-cypher/cypher.db

No WAL/SHM files were present in the scout.

Current interpretation:

    this is not used by `relay-openmls-join-dev`;
    it is not a v0.5.57 blocker;
    it remains a hygiene/release-readiness item for a later explicit cleanup rung.

Do not silently delete it as part of failure-path work.

## 14. Updated v0.5.57 decision

v0.5.57 should remain docs/update only.

No implementation is needed in this rung because:

    join failure coverage already exists;
    Cypher ack negative coverage already exists;
    runner helper negative coverage already exists;
    add-member has partial coverage but should be implemented as a targeted follow-up, not rushed into the current docs checkpoint.

Recommended next rung:

    v0.5.58:
        targeted Comms add-member failure test.

Preferred first v0.5.58 target:

    sidecar conversation-add-member failure should return an error and must not submit a Welcome.

Secondary v0.5.58/v0.5.59 targets:

    KeyPackage artifact write failure should not invoke sidecar and should not submit Welcome;
    Welcome submit failure after sidecar success should return an error and not print success;
    consider an explicit no-trust/candidate-mutation check only if there is a concrete path that could create those files.

## 15. Updated nonclaims

The triple-scout diagnosis does not claim:

    local-backbone;
    production secure messaging;
    hostile-server safety;
    metadata privacy;
    verified identity;
    secure enrollment;
    candidate acceptance;
    trust mutation;
    broad trust-store safety;
    broad candidate-store safety;
    deployability;
    release-package readiness;
    audit;
    certification.
