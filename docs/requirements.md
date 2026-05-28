# CarbonStackComms Requirements

Status: current requirements direction
Component: CarbonStackComms
Maturity: experimental / pre-release

These requirements describe intended direction.

They do not imply current production implementation.

## Current validated base

The current validated base is:

- OpenMLS sidecar artifact lifecycle;
- Cypher opaque envelope relay;
- payload metadata validation;
- consume-then-ack semantics;
- real local Cypher smoke harness.

This is not a finished runtime messenger.

## Product requirements

CarbonStackComms should preserve:

- text-first messaging;
- strict UTF-8 validation;
- no rich previews;
- no hidden linkification;
- no inline attachments by default;
- no plaintext notification content;
- loud key-change or trust-state warnings;
- hostile-server assumptions;
- minimal parser exposure.

## Security requirements

The server must not be able to silently:

- add members;
- replace keys;
- forge sender identity;
- rewrite group history;
- roll back group state without client-visible detection.

The current implementation does not fully prove every hostile-server requirement.

## Local storage requirement

A production-ready CarbonStackComms requires an encrypted local vault.

The current development sidecar state is not that vault.

Do not claim production local secrecy from current development storage.

## Deferred

Deferred work includes:

- polished runtime send/inbox UX;
- Android app readiness;
- production local vault;
- multi-device support;
- media support;
- rich text;
- Markdown rendering in chat;
- browser-based rendering;
- external audit and certification.
