# CarbonStackComms

CarbonStackComms is the text-first communications client component of CarbonStack.

At this stage, it is not a finished messenger.

It is not production-certified.

It is not externally audited.

It is not Android-ready.

It does not provide mature public send/inbox UX yet.

## Source of truth

Use the main CarbonStack repository for public release framing, release assets, validation runbooks, roadmap state, and project-wide claim boundaries:

    https://git.bitcrusher32.win/bitcrusher32/carbonstack

Related repositories:

    https://git.bitcrusher32.win/bitcrusher32/carbonstack
    https://git.bitcrusher32.win/bitcrusher32/carbonstack-cypher
    https://git.bitcrusher32.win/bitcrusher32/carbonstack-os

Gitea remains source of truth. GitHub mirrors may exist but are not release authority unless project policy changes.

## Current role

CarbonStackComms currently contains:

    text-first client scaffolding;
    local state and trust-state packages;
    dev/pre-alpha OpenMLS sidecar integration;
    OpenMLS sidecar command tests;
    Comms/Cypher relay helpers;
    Relay Space client wrappers;
    Relay Space OpenMLS artifact bridge helpers;
    KeyPackage / Welcome / add-member / join dev commands;
    dev runtime OpenMLS send/inbox commands;
    trust/candidate/recovery helper packages;
    command tests and smoke scripts.

This is useful development evidence. It is not a finished secure messenger.

## Current OpenMLS / Relay Space dev surfaces

Current dev/pre-alpha surfaces include:

    openmls-send-dev
    openmls-inbox-dev
    openmls-relay-keypackage-submit-dev
    openmls-relay-keypackage-inbox-dev
    openmls-relay-welcome-submit-dev
    openmls-relay-welcome-inbox-dev
    openmls-relay-add-member-dev
    openmls-relay-join-dev

These commands are development surfaces.

They are not mature public CLI UX.

They do not replace the legacy/stub-era send/inbox commands yet.

They do not prove production secure messaging.

They do not prove local-backbone.

They do not prove hostile-server safety or metadata privacy.

## Current validated shape

Current validation has covered:

    OpenMLS application-message relay through Cypher;
    openmls-send-dev -> Cypher -> openmls-inbox-dev --ack smoke proof;
    wrapper-based OpenMLS runtime smoke proof;
    Relay Space KeyPackage submit/inbox/write;
    Relay Space Welcome inbox/write;
    Relay Space add-member / Welcome submit;
    Relay Space join with optional --ack-after-join;
    positive relay-openmls-join-dev validation profile from the main runner;
    no-ack and ACK_AFTER_JOIN live evidence;
    no ack when join fails;
    no ack when Welcome write fails;
    no Welcome envelope rejection;
    add-member sidecar-failure no-Welcome-submit test.

The current add-member failure coverage proves:

    if KeyPackage artifact writing fails, sidecar add-member does not run and Welcome submit does not run;
    if sidecar conversation-add-member fails, the command returns the error, does not submit a Welcome, and does not print success-only fields;
    if Welcome submit fails after sidecar success, the command returns the error and does not print success-only fields.

## Stub-era send/inbox warning

The older send/inbox path remains stub-era.

Do not confuse legacy send/inbox with the OpenMLS dev paths.

The mature public send/inbox UX is not complete.

## OpenMLS sidecar

The promoted OpenMLS sidecar lives at:

    internal/protocol/mls/openmls-sidecar

It is used by protocol tests, relay smoke proofs, and dev command surfaces.

It is still dev-local and experimental.

It does not implement production secure vault storage.

Generated signer/provider/group state must not be committed.

## Trust and candidate state

CarbonStackComms includes internal trust/candidate/recovery helpers, including:

    provider trust report helpers;
    provider trust-history draft/event/append helpers;
    identity-candidates.json storage;
    mapped mismatch classifier;
    candidate review/update;
    candidate/mismatch history helpers;
    candidate observation orchestration;
    recovery classifier/history/orchestration helpers.

Current boundary:

    provider-observed identity material is not trust;
    Relay Space membership is not trust;
    OpenMLS/provider membership is not local verification;
    Cypher delivery is not trust;
    trust.json mutation from provider observation is not implemented;
    verified provider identity import is not implemented.

## Key storage / vault warning

Key storage is not complete.

Current sidecar/provider state is dev-local generated state.

CarbonStackComms does not currently implement a production encrypted vault, hardware-backed key storage, mature backup/restore, mature re-enrollment, or production secure local key lifecycle.

## Docs

Component docs live under:

    docs/

Start with:

    docs/README.md

The main CarbonStack repo remains the public release and roadmap authority.

## Development validation

From this repository:

    go test ./... -count=1

For cross-repo validation, use the main CarbonStack runner:

    cd ~/repos/carbonstack_umbrella/carbonstack/tools/carbonstack-validate
    go test ./... -count=1
    go run . --profile doctor

Use release-specific runbooks for release-package validation.

## Boundaries

CarbonStackComms does not currently prove:

    production readiness;
    production E2EE product readiness;
    hostile-server safety;
    metadata privacy;
    secure local vault/key storage;
    mature Comms runtime send/inbox UX;
    verified identity;
    secure enrollment;
    rollback/replay safety against a malicious server;
    Android readiness;
    public ingress safety;
    external audit or certification.

License: MIT.
See the repository's LICENSE file for more information.
