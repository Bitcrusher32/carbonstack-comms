# OpenMLS Minimal Scratch Experiment

## Status

Classification: EXPERIMENTAL / RUST-ONLY / NOT INTEGRATED

This directory contains the first local Rust scratch crate for CarbonStack's OpenMLS feasibility work.

This is not a production provider.

This is not wired into CarbonStackComms.

This is not real CarbonStack messaging.

## Current Stage

Current stage:

- OpenMLS local same-process provider-storage reload probe

This stage proves only:

- Rust is installed
- Cargo works
- OpenMLS-related crates resolve
- OpenMLS dependencies compile on the local Windows/MSVC setup
- basic OpenMLS credentials can be created
- signature key pairs can be created
- KeyPackages can be built
- Alice can create a local MLS group
- Alice can add Bob from Bob's KeyPackage
- Welcome can be extracted from `MlsMessageOut` body
- Alice and Bob use separate provider/storage instances
- Bob can stage Welcome and join into his own `MlsGroup`
- Alice can create MLS application messages
- Bob can process/open Alice's application messages
- Bob-opened plaintext matches Alice plaintext across the current two-message probe

## Current Dependencies

Current probe dependencies:

- openmls
- openmls_rust_crypto
- openmls_basic_credential
- tls_codec

## Current Probe Scope

Current executable:

- src/main.rs

Current behavior:

- creates Alice setup material
- creates Bob setup material
- creates Alice MLS group
- adds Bob to Alice group
- extracts Welcome for Bob
- merges Alice pending commit
- stages Bob Welcome
- creates Bob MLS group
- sends local Alice application message
- processes/opens local message as Bob
- confirms plaintext match

## Not Yet Implemented

Not yet implemented:

- state export/import
- provider boundary mapping
- Go integration
- CarbonStackComms CLI integration
- CarbonStackCypher envelope routing
- trust-state integration
- hostile-server tamper tests
- persistence design
- production security review

## Guardrails

Do not wire this crate into:

- comms send
- comms inbox
- CarbonStackCypher
- trust.json
- trust-events.jsonl
- Android
- CarbonStackOS

## Important Lessons

- `KeyPackage::builder().build(...)` returns `KeyPackageBundle`; extract the public `KeyPackage` with `key_package_bundle.key_package().clone()`.
- `MlsMessageOut::to_bytes()` serializes the whole MLS message wrapper, not the raw `Welcome`; extract Welcome from `MlsMessageOut::body()`.
- Alice and Bob must use separate provider/storage instances. Reusing one provider caused `GroupAlreadyExists`.
- For application messages, serialize `MlsMessageOut`, deserialize into `MlsMessageIn`, convert into `ProtocolMessage`, then call `process_message`.
- `ProcessedMessageContent::ApplicationMessage(...).into_bytes()` gives the opened plaintext bytes.

## Allowed Claims

Allowed:

- CarbonStackComms has a Rust-only OpenMLS scratch crate.
- The scratch crate can create a local two-member OpenMLS group.
- The scratch crate can locally protect/open one application message between Alice and Bob.

Not allowed:

- CarbonStackComms uses OpenMLS for real messaging.
- CarbonStack has production MLS encryption.
- CarbonStack has production E2EE.
- CarbonStack has a production MLS provider.
- CarbonStack has selected a final MLS implementation.
- CarbonStack has hostile-server proof.

## Git Hygiene

Commit only source/control files from this scratch crate:

- `Cargo.toml`
- `Cargo.lock`
- `README.md`
- `src/main.rs`

Do not commit generated Cargo artifacts:

- `target/`
- `.fingerprint/`
- `debug/`
- `release/`
- `.exe`
- `.pdb`
- `.o`
- generated rustdoc output

Before committing Rust scratch work, run from `carbonstack-comms`:

- `git diff --cached --name-only`
- `git show --stat --oneline HEAD`

Neither output should contain `target/`, `.exe`, `.pdb`, `.fingerprint`, or `.o`.


## State Continuity Probe

The scratch crate now sends two sequential Alice-to-Bob application messages inside one process.

This validates:

- Alice/Bob group state remains usable after one application message.
- Bob's mutable group state can process a second message.
- Message processing is stateful and must be treated as a persistence-relevant operation.

This does not validate:

- disk persistence
- process restart recovery
- provider-state export/import
- secure vault storage
- CarbonStackComms integration

Next persistence work should identify the real OpenMLS provider storage/export strategy.



## Same-Process Provider Storage Reload Probe

The scratch crate now reloads Alice and Bob `MlsGroup` state from each device's provider storage inside the same process.

This validates:

- `MlsGroup::load(provider.storage(), group_id)` works with the current OpenMLS provider storage.
- Alice group state can be loaded from Alice provider storage.
- Bob group state can be loaded from Bob provider storage.
- Loaded groups preserve epoch and member count.
- Loaded groups can protect/open a second application message after reload.
- Provider storage contains usable group state at least within the same process.

This does not validate:

- disk persistence
- process restart recovery
- portable provider-state export/import
- secure vault storage
- custom storage backend design
- CarbonStackComms integration

Next persistence work should identify whether OpenMLS 0.8.1 supports practical disk-backed provider storage or whether CarbonStack needs a provider-owned storage adapter/sidecar.

