# CarbonStackComms Client Protocol Foundation

Status: current doctrine with implementation update
Component: CarbonStackComms
Maturity: experimental / pre-release

CarbonStackComms must not invent cryptography casually.

The client protocol must be built around mature, reviewed foundations while preserving CarbonStack-specific constraints:

- strict text policy;
- hostile-server assumptions;
- loud trust changes;
- local-state isolation;
- minimal parser exposure;
- visible membership/device changes.

## Current implementation direction

Earlier Phase 1 planning investigated Signal-style one-to-one messaging.

The current mainline experimental proof uses an OpenMLS sidecar.

The current validated artifact is not a production protocol. It is a local development proof that OpenMLS artifacts can be generated, relayed through Cypher, consumed, and acknowledged after sidecar success.

Current validated artifact flow:

- KeyPackage artifact;
- Welcome artifact;
- application-message artifact;
- Cypher opaque envelope relay;
- payload metadata validation;
- consume-then-ack semantics.

## Protocol boundary

CarbonStackComms should not treat the server as trusted.

The server must not be able to silently:

- add members;
- replace keys;
- forge sender identity;
- rewrite group history;
- roll back group state without client-visible detection.

The current implementation does not fully prove all of these hostile-server goals. They remain design requirements.

## Current OpenMLS relay content types

The current Cypher relay path uses:

    carbonstack.mls.keypackage.v0
    carbonstack.mls.welcome.v0
    carbonstack.mls.application-message.v0

Protocol version:

    carbonstack-openmls-sidecar-v0

## Nonclaims

This document does not claim:

- production E2EE readiness;
- hostile-server completeness;
- metadata privacy;
- external audit or certification;
- Android readiness;
- stable public protocol status.

Use the main `carbonstack` runbook for current known-good validation.
