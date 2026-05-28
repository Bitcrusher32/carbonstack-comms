# CarbonStackComms

CarbonStackComms is the text-first communications client component of CarbonStack.

At this stage, it is not a finished messenger.

It is not production-certified.

It is not externally audited.

It is not Android-ready.

The current validated artifact is a development proof that CarbonStackComms can use an OpenMLS sidecar and CarbonStackCypher relay storage to complete a local OpenMLS relay lifecycle.

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

## OpenMLS sidecar

The promoted OpenMLS sidecar lives at:

    internal/protocol/mls/openmls-sidecar

It is used by protocol tests and relay smoke proofs.

It is still dev-local and experimental.

It does not implement production secure vault storage.

Generated signer/provider state must not be committed.

## Smoke harness

Run the current real-server OpenMLS relay smoke harness:

    powershell -ExecutionPolicy Bypass -File .\scripts\smoke-openmls-real-cypher-relay.ps1

Run broader validation:

    powershell -ExecutionPolicy Bypass -File .\scripts\smoke-openmls-real-cypher-relay.ps1 -Full
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
