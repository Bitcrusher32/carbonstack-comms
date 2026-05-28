# CarbonStackComms Client Lifecycle

Status: historical Phase 1 plan with current-state notice
Component: CarbonStackComms
Maturity: experimental / pre-release

This document originally described a Phase 1 CLI client lifecycle.

It is no longer the current release surface.

The current validated proof is the OpenMLS sidecar + Cypher relay smoke path, not a polished runtime CLI messenger.

Use the main `carbonstack` runbook for current validation:

    docs/113-experimental-backbone-deployability-runbook-v0.md

## Historical Phase 1 goal

The original CLI goal was to validate a minimal local client that could:

1. Claim an invite.
2. Register a device.
3. Store local account/device state.
4. Look up another device.
5. Build a stub encrypted envelope.
6. Send it to CarbonStackCypher.
7. Retrieve envelopes.
8. Decode/decrypt through a mock provider.
9. Acknowledge delivery.

This was useful scaffolding.

It is not the current OpenMLS relay proof.

## Current validated lifecycle

The current validated lifecycle is:

1. Bob exports an OpenMLS KeyPackage artifact.
2. Comms submits it to Cypher.
3. Alice retrieves and writes it.
4. Alice consumes it through the OpenMLS sidecar and creates a Welcome.
5. Comms submits the Welcome to Cypher.
6. Bob retrieves and writes it.
7. Bob consumes it through the sidecar.
8. Alice creates an application-message artifact.
9. Comms submits it to Cypher.
10. Bob retrieves, validates metadata, writes, and consumes it.
11. The plaintext matches.
12. Envelopes are acked only after sidecar consume succeeds.

## Why CLI/dev harness remains useful

Android-first implementation would still introduce unnecessary complexity:

- Android lifecycle;
- UI complexity;
- keystore integration;
- permission model concerns;
- emulator/device debugging;
- hardware-key integration complexity.

The CLI/dev harness path remains useful, but it must be updated around the OpenMLS sidecar relay model rather than the old stub-only lifecycle.

## Nonclaims

This document does not describe a production messenger.

It does not describe production local vault security.

It does not describe a finished runtime send/inbox UX.

It preserves historical Phase 1 planning and points to the current experimental backbone proof.
