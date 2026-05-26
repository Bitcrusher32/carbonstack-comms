# CarbonStack OpenMLS Sidecar

Classification: Phase 2D / Phase 2E-prep promoted development sidecar.

This crate is the maintained OpenMLS sidecar scaffold for CarbonStackComms development.

It was promoted from the Phase 2D research sidecar after the mainline OpenMLS lifecycle proof closed. The research reference remains intact at:

    ../research/openmls-sidecar

Use this promoted sidecar for active development and contract tests.

## Status

This sidecar is dev-local and experimental.

It is not production E2EE.

It is not wired into the CarbonStackComms runtime send/inbox path.

It is not wired into CarbonStackCypher.

It does not mutate `trust.json` or `trust-events.jsonl`.

It uses dev-local signer/provider storage and does not implement production secure vault storage.

Generated sidecar state must not be committed.

## Supported commands

The current promoted sidecar supports:

    provider-info
    identity-create
    identity-status
    public-bundle-export
    conversation-create
    conversation-load-check
    conversation-add-member
    conversation-join
    message-protect
    message-open

Still unsupported:

    state-checkpoint
    state-load-check

## Current validated lifecycle

The Go contract tests validate a dev-local Alice/Bob lifecycle:

    identity-create
    identity-status
    public-bundle-export
    public-bundle-export --write-artifact
    conversation-create
    conversation-load-check
    conversation-add-member
    conversation-join
    message-protect
    message-open
    two sequential message labels
    out-of-order same-sender open
    duplicate/replay rejection
    corrupt/truncated artifact rejection
    wrong-device rejection
    wrong-conversation rejection
    bidirectional Alice/Bob message flow

## Dev-state layout

Generated local state lives under:

    .carbonstack-openmls-sidecar-state/dev/

Current conversation state is device-scoped:

    .carbonstack-openmls-sidecar-state/dev/devices/<device-label>/conversations/<conversation-label>/

Important local-only sensitive files:

    signer.json
    provider-storage.json

Important opaque protocol artifacts:

    public-bundle.keypackage.bin
    welcome.bin
    application-message.bin

Do not print, paste, inspect casually, expose, or commit secret-bearing generated state.

## Test ownership

The Go contract tests are split by ownership:

    internal/protocol/openmls_sidecar_helpers_test.go
    internal/protocol/openmls_sidecar_provider_info_test.go
    internal/protocol/openmls_sidecar_identity_test.go
    internal/protocol/openmls_sidecar_public_bundle_test.go
    internal/protocol/openmls_sidecar_conversation_test.go
    internal/protocol/openmls_sidecar_message_test.go
    internal/protocol/openmls_sidecar_message_negative_test.go

These tests target this promoted sidecar path.

## Validation

From the sidecar crate:

    cargo check
    cargo test
    cargo run -- provider-info

From the `carbonstack-comms` repo root:

    go test -p 1 ./internal/protocol
    go test -p 1 ./...
    powershell -ExecutionPolicy Bypass -File .\scripts\check-no-rust-artifacts.ps1

## Current non-goals

Do not claim:

    production E2EE
    Signal-equivalent security
    hostile-server proof
    metadata privacy
    production vault storage
    Android / Pixel 4a validation
    Comms runtime OpenMLS integration
    Cypher MLS artifact routing
    trust-state mutation from sidecar events

Next planned rung after README/current-state cleanup:

    v0.2.47 — Cypher minimal opaque MLS artifact relay recon.
