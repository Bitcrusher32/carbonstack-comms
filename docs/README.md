# CarbonStackComms docs

This directory contains component-local CarbonStackComms design, planning, and result notes.

The main CarbonStack repository remains the source of truth for public release framing, roadmap state, release packages, and cross-repo validation.

## How to read these docs

These docs are historical and component-local.

Older notes may be stale.

Use them for:

    implementation context;
    trust/provider/candidate/recovery decisions;
    Relay Space and OpenMLS command boundaries;
    local component rationale;
    debugging why current tests or helper packages exist.

Do not treat older notes as current public release claims.

## Current component state

CarbonStackComms is dev/pre-alpha.

It currently includes:

    OpenMLS sidecar integration;
    Relay Space client and artifact bridge helpers;
    KeyPackage / Welcome / add-member / join dev command surfaces;
    dev runtime OpenMLS send/inbox command surfaces;
    provider/trust/candidate/recovery helper packages;
    focused command tests and smoke scripts.

It does not yet include:

    mature public send/inbox UX;
    production secure vault/key storage;
    verified provider identity import;
    mature verification ceremony;
    broad provider live-flow;
    local-backbone;
    hostile-server safety proof;
    metadata privacy proof;
    production secure messaging.

## Current important boundaries

Provider-observed identity material is not trust.

Relay Space membership is not trust.

OpenMLS group membership is not local identity verification.

Cypher delivery is not trust.

Ack is local-processing/delivery state, not identity verification.

Generated sidecar provider/signer/group state is dev-local state, not a production vault.

## Current validation shape

From this repo:

    go test ./... -count=1

Cross-repo validation lives in the main CarbonStack runner:

    carbonstack/tools/carbonstack-validate

Use release-specific runbooks for release-package validation.
- [31 Gate F F5 Basic Local Trust Posture](31-gate-f-f5-basic-local-trust-posture-v0.md)
- [32 Gate F F5 Basic Local Trust Closure](32-gate-f-f5-basic-local-trust-closure-v0.md)
