# CarbonStack OpenMLS Sidecar

Classification: promoted development sidecar
Component: CarbonStackComms
Maturity: experimental / pre-release

This crate is the maintained OpenMLS sidecar scaffold used by CarbonStackComms development, contract tests, and current relay lifecycle proofs.

It was promoted from the Phase 2D research sidecar after the mainline OpenMLS lifecycle proof closed.

The research reference remains intact at:

    ../research/openmls-sidecar

Use this promoted sidecar for active development and tests.

## Current status

This sidecar is dev-local and experimental.

It is not production E2EE.

It is not production-certified.

It is not externally audited.

It is not wired into polished CarbonStackComms runtime `send` / `inbox` UX.

It does not mutate `trust.json` or `trust-events.jsonl`.

It uses dev-local signer/provider storage and does not implement production secure vault storage.

Generated sidecar state must not be committed.

## Current validated use

The sidecar is used in the current CarbonStack experimental backbone proof.

Validated path:

1. `public-bundle-export --write-artifact` writes a KeyPackage artifact.
2. Comms relays the KeyPackage through Cypher.
3. `conversation-add-member` consumes the downloaded KeyPackage and writes a Welcome artifact.
4. Comms relays the Welcome through Cypher.
5. `conversation-join` consumes the downloaded Welcome.
6. `message-protect` writes an application-message artifact.
7. Comms relays the application-message through Cypher.
8. `message-open` consumes the downloaded application-message.
9. The plaintext matches.
10. Envelopes are acked only after successful sidecar consume.

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

## Generated state warning

Do not commit generated sidecar state.

Sensitive or generated paths include:

    .carbonstack-openmls-sidecar-state/
    signer.json
    provider-storage.json
    welcome.bin
    application-message.bin
    public-bundle.keypackage.bin
    target/

The generated provider and signer files are development state. They are not production secure vault storage.

## Validation

From this crate:

    cargo fmt
    cargo check
    cargo test
    cargo run -- provider-info

From the `carbonstack-comms` repo root:

    go test -p 1 ./internal/protocol -count=1
    powershell -ExecutionPolicy Bypass -File .\scripts\smoke-openmls-real-cypher-relay.ps1
    powershell -ExecutionPolicy Bypass -File .\scripts\check-no-rust-artifacts.ps1

## Boundary

This crate is a development sidecar.

It proves current OpenMLS artifact lifecycle behavior for the CarbonStack experimental backbone.

It does not prove production readiness, Android readiness, hostile-server completeness, metadata privacy, or external certification.
