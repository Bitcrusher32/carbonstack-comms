# CarbonStackComms MLS Area

This directory contains CarbonStackComms MLS-related development work.

It is no longer only a future placeholder.

The active promoted OpenMLS sidecar lives at:

    internal/protocol/mls/openmls-sidecar

The historical research reference remains under:

    internal/protocol/mls/research

## Current status

Classification: experimental / development

The promoted OpenMLS sidecar is used by CarbonStackComms protocol tests and real-Cypher relay smoke proofs.

It is not production-certified.

It is not externally audited.

It is not wired into polished runtime `send` / `inbox` UX.

It does not implement production secure vault storage.

## Directory roles

### `openmls-sidecar`

Maintained development sidecar.

Used for active contract tests and relay lifecycle proofs.

### `research`

Historical research area.

Preserves earlier OpenMLS feasibility work and known-good reference context.

Do not treat research READMEs as current release surfaces unless a newer doc explicitly points to them.

## Current architectural position

CarbonStackComms currently uses OpenMLS sidecar artifacts for the experimental relay proof:

- KeyPackage artifact;
- Welcome artifact;
- application-message artifact.

CarbonStackCypher relays these as opaque envelopes.

Comms validates payload metadata before writing downloaded artifacts locally.

The sidecar consume step remains the cryptographic validity gate.

## Nonclaims

This directory does not prove:

- production E2EE;
- hostile-server-complete safety;
- metadata privacy;
- production local storage security;
- Android readiness;
- external audit or certification.

Use the main `carbonstack` runbook for the current system-level validation path.
