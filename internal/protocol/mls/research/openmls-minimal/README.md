# OpenMLS Minimal Scratch Experiment

## Status

Classification: EXPERIMENTAL / RUST-ONLY / NOT INTEGRATED

This directory is reserved for the first local-only OpenMLS scratch experiment.

It intentionally does not yet contain:

- Cargo.toml
- Rust source
- OpenMLS dependency
- mls-rs dependency
- Go integration
- CarbonStackComms CLI integration

## Purpose

The purpose of this experiment is to learn whether OpenMLS can fit CarbonStack's provider boundary and trust model.

The first experiment should be Rust-only.

Do not solve Go/Rust integration here yet.

## Intended Minimal Flow

The first eventual code should prove:

1. Alice credential/identity exists.
2. Bob credential/identity exists.
3. Bob public setup material / KeyPackage exists.
4. Alice creates an MLS group.
5. Alice adds Bob.
6. Bob joins from Welcome / staged Welcome.
7. Alice protects application text.
8. Bob opens application text.
9. Plaintext matches.
10. Epoch or group state version can be inspected.
11. Membership can be inspected or inferred.
12. Persistence requirements are understood.

## Integration Guardrail

This experiment must not be wired into:

- comms send
- comms inbox
- CarbonStackCypher
- production state
- trust.json
- trust-events.jsonl
- Android
- CarbonStackOS

## Mapping Target

If the experiment works, map its concepts back to:

- ProviderIdentity
- PublicBundle
- PublicVerification
- ConversationState
- ConversationEpoch
- ProtectedMessage
- OpenedMessage
- ProviderEvent

## Allowed Claims

Allowed:

- CarbonStackComms has a reserved Rust-only OpenMLS scratch experiment path.

Not allowed:

- CarbonStackComms uses OpenMLS.
- CarbonStackComms has MLS encryption.
- CarbonStackComms has real E2EE.
- CarbonStackComms has a production MLS provider.
