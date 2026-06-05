# CarbonStackComms

CarbonStackComms is the text-first communications client component of CarbonStack.

At this stage, it is not a finished messenger.

It is not production-certified.

It is not externally audited.

It is not Android-ready.

The current validated artifact is a development proof that CarbonStackComms can use an OpenMLS sidecar and CarbonStackCypher relay storage to complete a local OpenMLS relay lifecycle.


_Related repositories: [carbonstack](https://git.bitcrusher32.win/bitcrusher32/carbonstack) / [carbonstack-cypher](https://git.bitcrusher32.win/bitcrusher32/carbonstack-cypher) / [carbonstack-os](https://git.bitcrusher32.win/bitcrusher32/carbonstack-os)_

## Current implemented role

CarbonStackComms currently contains:

- a text-first client scaffold;
- a promoted OpenMLS development sidecar;
- protocol tests for the OpenMLS sidecar lifecycle;
- an internal relay helper for Cypher/OpenMLS artifact transport;
- a real-Cypher smoke harness;
- metadata validation before writing downloaded sidecar artifacts;
- consume-then-ack proof boundaries.

## Current validated relay path

The current proof validates:

1. Bob exports an OpenMLS KeyPackage artifact.
2. Comms submits it to Cypher as an opaque envelope.
3. Alice retrieves and writes the artifact.
4. Alice consumes it through the OpenMLS sidecar and creates a Welcome.
5. Comms submits the Welcome to Cypher.
6. Bob retrieves and writes the Welcome.
7. Bob consumes it through the sidecar.
8. Alice creates an application-message artifact.
9. Comms submits it to Cypher.
10. Bob retrieves, validates metadata, writes, and consumes the application-message.
11. The plaintext matches.
12. Envelopes are acked only after sidecar consume succeeds.

This is a development proof. It is not a polished runtime UX.

## Core communication constraints

CarbonStackComms is intended to preserve these constraints:

- text-first messaging;
- no rich previews;
- no hidden linkification;
- no inline attachments by default;
- loud trust changes;
- hostile-server assumptions;
- strict parser minimization;
- no server-trusted identity changes.

## Dev-only OpenMLS runtime command

The first explicit runtime OpenMLS command is:

    go run ./cmd/comms openmls-send-dev

This command is dev-only and pre-alpha. It does not replace the existing stub-era `send` command yet.

Current purpose:

    call the OpenMLS sidecar `message-protect` command
    submit the resulting application-message artifact through the Cypher relay helper
    preserve dev-mode trust behavior by default, with optional `--strict`

Minimal shape:

    go run ./cmd/comms openmls-send-dev \
      --to-device <recipient-cypher-device-id> \
      --sidecar-device-label <sender-sidecar-device-label> \
      --conversation <sidecar-conversation-label> \
      --message <plaintext> \
      [--message-label <label>] \
      [--strict]

This is not mature messaging UX, not local-backbone, and not a production security claim.

## OpenMLS sidecar

The promoted OpenMLS sidecar lives at:

    internal/protocol/mls/openmls-sidecar

It is used by protocol tests and relay smoke proofs.

It is still dev-local and experimental.

It does not implement production secure vault storage.

Generated signer/provider state must not be committed.

## Smoke harness

Run the current OpenMLS backbone self-test:

    powershell -ExecutionPolicy Bypass -File .\scripts\self-test-openmls-backbone.ps1

Run broader validation:

    powershell -ExecutionPolicy Bypass -File .\scripts\self-test-openmls-backbone.ps1 -Full
    powershell -ExecutionPolicy Bypass -File .\scripts\check-no-rust-artifacts.ps1

## Main runbook

Use the main `carbonstack` repo for the current public runbook:

    docs/113-experimental-backbone-deployability-runbook-v0.md

## What is not implemented

CarbonStackComms does not currently provide:

- production runtime send/inbox OpenMLS UX;
- Android app readiness;
- production local vault storage;
- external audit or certification;
- production E2EE security claims;
- hostile-server-complete rollback/replay defense.

This repo is an implementation and development surface. The public release framing belongs in the main `carbonstack` repo.
## Lower-level smoke harness

The public self-test entrypoint is:

    powershell -ExecutionPolicy Bypass -File .\scripts\self-test-openmls-backbone.ps1

The lower-level implementation harness remains available for debugging:

    powershell -ExecutionPolicy Bypass -File .\scripts\smoke-openmls-real-cypher-relay.ps1


---

License: MIT.
See the repository's LICENSE file for more information.

