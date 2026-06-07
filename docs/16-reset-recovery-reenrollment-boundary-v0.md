# CarbonStackComms Reset/Recovery/Re-enrollment Boundary v0

Status: component-local reset/recovery/re-enrollment decision
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/182-v0.5.25-reset-recovery-reenrollment-decision-v0.md

## 1. Purpose

This document records the Comms-side reset/recovery/re-enrollment boundary after candidate storage, mismatch classification, candidate review/update, candidate history append, and candidate observation orchestration.

This is a decision record only.

No reset/recovery/re-enrollment implementation is added by this document.

## 2. Decision

Reset/recovery/re-enrollment semantics must be defined before local-backbone.

Comms local state comes first.

Cypher reset/recovery remains downstream operational context.

## 3. Definitions

Reset:

    deliberate discard or reinitialization of local state.

Recovery:

    restore or reuse of prior local state after loss, migration, corruption, or reinstall.

Re-enrollment:

    deliberate introduction of new local identity/device material after loss, rotation, compromise, reinstall, or migration.

None of these automatically verify identity.

## 4. State domains

Comms reset/recovery must distinguish:

    local app state;
    trust.json;
    trust-events.jsonl;
    identity-candidates.json;
    OpenMLS provider state;
    relay staging artifacts;
    generated dev artifacts.

Do not collapse these into one generic reset.

## 5. trust.json boundary

trust.json is trust-bearing state.

Missing trust.json may currently load as an empty store, but mature behavior must not treat that as trust continuity.

Recovered or re-enrolled identity material must not silently replace trust.json records.

## 6. trust-events.jsonl boundary

trust-events.jsonl is trust-history state.

Missing history should not be treated as proof that nothing happened.

Candidate/recovery history append is allowed later, but history append is not trust mutation.

## 7. identity-candidates.json boundary

identity-candidates.json is trust-adjacent candidate state.

It may contain raw candidate public identity material in dev/pre-alpha.

Recovered candidates must not become verified automatically.

## 8. Provider state boundary

OpenMLS provider state is identity/group/conversation-bearing state.

Missing/corrupt provider state can affect continuity and must fail loudly.

Reset/recovery must not silently regenerate identity/group state and pretend continuity was preserved.

## 9. Re-enrollment boundary

Re-enrollment should first create or observe candidate/unverified state.

It must not:

    call VerifyDevice automatically;
    call MarkDeviceChanged automatically from provider observation alone;
    replace known key material automatically;
    mark verified automatically;
    bypass candidate review.

## 10. Reset scope model

Future reset helpers should require explicit scope.

Candidate scopes:

    generated_dev_artifacts
    relay_staging
    candidate_state
    trust_history
    trust_store
    provider_state
    local_app_state
    all_comms_local_state

Dangerous scopes:

    trust_store
    trust_history
    provider_state
    all_comms_local_state

Dangerous scopes should not hide behind generic reset wording.

## 11. First implementation recommendation

Recommended next Comms implementation:

    pure reset/recovery classification helper.

Candidate files:

    internal/trust/identity_recovery.go
    internal/trust/identity_recovery_test.go

First helper should classify, not mutate.

It should not:

    delete files;
    restore files;
    mutate trust.json;
    append trust-events.jsonl;
    mutate identity-candidates.json;
    verify identity;
    replace key material;
    affect send/open/ack behavior;
    expose CLI/registry.

## 12. CLI / registry

Do not expose reset/recovery/re-enrollment CLI or registry entries yet.

Reset/recovery commands are dangerous and should wait until classification and destructive-scope semantics are mature.

## 13. Nonclaims

This document does not claim:

    reset implementation;
    recovery implementation;
    re-enrollment implementation;
    backup/restore support;
    verified identity import;
    trust mutation;
    key replacement;
    local-backbone readiness;
    production readiness.
