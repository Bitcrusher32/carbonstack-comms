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

## Dev-only OpenMLS runtime commands

The explicit runtime OpenMLS dev commands are:

    go run ./cmd/comms openmls-send-dev
    go run ./cmd/comms openmls-inbox-dev

These commands are dev-only and pre-alpha. They do not replace the existing stub-era `send` / `inbox` commands yet.

`openmls-send-dev` current purpose:

    call the OpenMLS sidecar `message-protect` command
    submit the resulting application-message artifact through the Cypher relay helper
    preserve dev-mode trust behavior by default, with optional `--strict`

Minimal send shape:

    go run ./cmd/comms openmls-send-dev \
      --to-device <recipient-cypher-device-id> \
      --sidecar-device-label <sender-sidecar-device-label> \
      --conversation <sidecar-conversation-label> \
      --message <plaintext> \
      [--message-label <label>] \
      [--strict]

`openmls-inbox-dev` current purpose:

    fetch the current device inbox from Cypher
    skip unsupported non-OpenMLS application-message envelopes
    write an OpenMLS application-message artifact through the relay helper
    call the OpenMLS sidecar `message-open` command
    print plaintext only after sidecar success
    ack only after sidecar success when `--ack` is explicitly set

Minimal inbox shape:

    go run ./cmd/comms openmls-inbox-dev \
      --sidecar-device-label <recipient-sidecar-device-label> \
      --conversation <sidecar-conversation-label> \
      [--message-label <label>] \
      [--limit 1] \
      [--ack]

This is not mature messaging UX, not local-backbone, and not a production security claim.

## OpenMLS sidecar

The promoted OpenMLS sidecar lives at:

    internal/protocol/mls/openmls-sidecar

It is used by protocol tests and relay smoke proofs.

It is still dev-local and experimental.

It does not implement production secure vault storage.

Generated signer/provider state must not be committed.

## Dev runtime OpenMLS smoke proof

The dev runtime smoke proof is:

    scripts/dev-openmls-runtime-smoke.sh

It creates a temporary local Cypher server, temporary Comms state files, dev-local OpenMLS sidecar identities, and a dev-local sidecar conversation. It then proves the current CLI runtime message path:

    openmls-send-dev -> Cypher -> openmls-inbox-dev --ack

Boundary:

    this is dev/pre-alpha only
    this is not local-backbone
    this is not production messaging UX
    this does not replace the old stub-era send/inbox commands
    sidecar KeyPackage/Welcome/bootstrap setup is still direct dev setup
    the application-message path is the runtime CLI proof target

The script removes prior sidecar dev state before running and uses a temporary Cypher database.\n\n## Smoke harness

Run the current OpenMLS backbone self-test:

    powershell -ExecutionPolicy Bypass -File .\scripts\self-test-openmls-backbone.ps1

Run broader validation:

    powershell -ExecutionPolicy Bypass -File .\scripts\self-test-openmls-backbone.ps1 -Full
    powershell -ExecutionPolicy Bypass -File .\scripts\check-no-rust-artifacts.ps1

## Main runbook

Use the main `carbonstack` repo for the current public runbook:

    docs/113-experimental-backbone-deployability-runbook-v0.md

## Trust-state model

CarbonStackComms has a development trust-state model covering:

- unknown;
- unverified;
- verified;
- changed;
- revoked;
- reserved compromised.

Component-local notes live in:

    docs/06-trust-state-model-v0.md

This model describes current dev trust behavior and future trust requirements. It is not production identity safety, not secure vault storage, and not provider-state linkage implementation.

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

## Dev-only OpenMLS bootstrap commands

These commands are development helpers for explicit OpenMLS sidecar bootstrap state.

They are not production identity UX, not Relay Space join UX, not local-backbone, and not secure vault/state management.

    openmls-identity-create-dev
    openmls-identity-status-dev
    openmls-bundle-export-dev
    openmls-conversation-create-dev
    openmls-conversation-load-check-dev
    openmls-conversation-add-member-dev
    openmls-conversation-join-dev

Current identity bootstrap examples:

    go run ./cmd/comms openmls-identity-create-dev --sidecar-device-label carbonstack-dev-alice
    go run ./cmd/comms openmls-identity-status-dev --sidecar-device-label carbonstack-dev-alice
    go run ./cmd/comms openmls-bundle-export-dev --sidecar-device-label carbonstack-dev-alice --write-artifact
    go run ./cmd/comms openmls-conversation-create-dev --sidecar-device-label carbonstack-dev-alice --conversation carbonstack-dev-conversation
    go run ./cmd/comms openmls-conversation-load-check-dev --sidecar-device-label carbonstack-dev-alice --conversation carbonstack-dev-conversation
    go run ./cmd/comms openmls-conversation-add-member-dev --sidecar-device-label carbonstack-dev-alice --conversation carbonstack-dev-conversation --member-keypackage <path-to-member-keypackage>
    go run ./cmd/comms openmls-conversation-join-dev --sidecar-device-label carbonstack-dev-bob --conversation carbonstack-dev-conversation --welcome <path-to-welcome>

Boundary:

    sidecar labels are explicit for now
    Comms state/trust files are not mutated by these wrappers
    existing send/inbox remain stub-era
    dev-runtime-openmls remains the current manual smoke-profile proof
## Wrapper-based dev runtime OpenMLS smoke proof

This optional smoke script validates the current dev-only bootstrap wrapper surface before the existing runtime send/open path:

    scripts/dev-openmls-runtime-smoke-wrappers.sh

Proof shape:

    openmls-*-dev bootstrap wrappers -> openmls-send-dev -> Cypher -> openmls-inbox-dev --ack

Boundary:

    This is a dev/pre-alpha wrapper smoke proof.
    It is not local-backbone.
    It is not mature messaging UX.
    It is not production E2EE.
    It does not replace the direct-sidecar smoke script yet.
    The manual dev-runtime-openmls runner profile still wraps scripts/dev-openmls-runtime-smoke.sh.
