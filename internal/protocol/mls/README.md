# CarbonStackComms Experimental MLS Provider Slot

## Status

Classification: EXPERIMENTAL / PHASE 2C RESEARCH SLOT

This directory is reserved for future MLS feasibility work.

It does not currently contain a real MLS provider.

It does not currently import OpenMLS, mls-rs, libsignal, or any other cryptographic protocol dependency.

## Purpose

CarbonStack is moving toward an MLS-shaped, provider-neutral architecture.

The current provider boundary lives in:

- `internal/protocol`

This directory is the planned in-project location for future MLS feasibility work:

- `internal/protocol/mls`

The purpose of this marker is to keep future protocol work close to the provider boundary while making the experimental status explicit.

## Current Consensus

CarbonStack currently assumes:

- every conversation is conceptually group-shaped
- 1:1 conversations are two-member conversations
- MLS is the preferred long-term architecture shape
- Signal/libsignal remains a reference and fallback, not a mainline dependency
- AGPL dependencies should be avoided in mainline unless explicitly accepted later
- Rust is acceptable inside provider modules if it serves the project
- no custom cryptography should be implemented

## What Belongs Here Later

Future contents may include:

- MLS feasibility notes specific to CarbonStackComms
- local-only MLS spike code
- experimental provider adapters
- test fixtures for two-member conversations
- serialization experiments
- membership/epoch inspection experiments
- provider-event mapping experiments

## What Does Not Belong Here Yet

Do not add yet:

- OpenMLS dependency
- mls-rs dependency
- libsignal dependency
- production provider code
- Android code
- CarbonStackOS code
- hardware-key logic
- production vault logic
- custom cryptographic primitives
- production security claims

## First MLS Feasibility Target

The first MLS spike should prove only a local test flow:

1. Alice provider identity exists.
2. Bob provider identity exists.
3. Alice and Bob have public setup material.
4. Alice creates a two-member conversation.
5. Bob joins or receives equivalent welcome/setup state.
6. Alice protects a text message.
7. Bob opens the text message.
8. Membership can be inspected.
9. Epoch or state version can be inspected.
10. Provider state can be serialized/restored, if practical.

## Provider Boundary Rules

MLS provider code may report provider facts, such as:

- message opened
- message protected
- member added
- member removed
- stale epoch
- malformed message
- decrypt failed
- state updated

CarbonStack application logic decides policy:

- whether to warn
- whether to block
- whether to mark a device changed
- whether to require re-verification
- whether to append trust history
- whether to reject revoked devices

## First Implementation Constraint

The first implementation should be local-only and test-only.

It should not wire into normal `comms send` or `comms inbox` behavior until the provider boundary is proven.

## Allowed Claims

Allowed:

- CarbonStackComms has a reserved experimental MLS provider slot.
- CarbonStack is preparing for an MLS feasibility spike.
- No MLS implementation has been integrated yet.

Not allowed:

- CarbonStackComms uses MLS.
- CarbonStack has real encryption.
- CarbonStack has production E2EE.
- CarbonStack has selected a final MLS implementation.
- CarbonStack has hostile-server proof.
