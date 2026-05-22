# OpenMLS Minimal Scratch Experiment

## Status

Classification: EXPERIMENTAL / RUST-ONLY / NOT INTEGRATED

This directory contains the first local Rust scratch crate for CarbonStack's OpenMLS feasibility work.

This is not a production provider.

This is not wired into CarbonStackComms.

This is not real CarbonStack messaging.

## Current Stage

Current stage:

- dependency/build probe

This stage proves only:

- Rust is installed
- Cargo works
- OpenMLS-related crates can be added
- dependencies can compile on the local Windows/MSVC setup
- the scratch crate can run

## Current Dependencies

Intended probe dependencies:

- openmls
- openmls_rust_crypto
- openmls_basic_credential

## Not Yet Implemented

Not yet implemented:

- Alice identity creation
- Bob identity creation
- KeyPackage creation
- MLS group creation
- Bob join from Welcome
- application message protection
- application message opening
- epoch inspection
- membership inspection
- state export/import
- provider boundary mapping
- Go integration
- CarbonStackComms CLI integration

## Guardrails

Do not wire this crate into:

- comms send
- comms inbox
- CarbonStackCypher
- trust.json
- trust-events.jsonl
- Android
- CarbonStackOS

## Allowed Claims

Allowed:

- CarbonStackComms has a Rust-only OpenMLS scratch crate.
- The scratch crate can test whether OpenMLS dependencies resolve and compile.

Not allowed:

- CarbonStackComms uses OpenMLS for messaging.
- CarbonStack has MLS encryption.
- CarbonStack has real E2EE.
- CarbonStack has selected a final MLS implementation.
- CarbonStack has production secure messaging.
