# CarbonStackComms Local State Model v0

Status: historical development-state plan with current-state notice
Component: CarbonStackComms
Maturity: experimental / pre-release

This document describes early development local-state ideas.

It is not the current secure vault design.

It is not a production storage model.

The current OpenMLS sidecar proof uses dev-local sidecar state and generated provider/signer files. Those files are sensitive development artifacts and must not be committed.

## Current warning

Do not treat current local state as production-secure.

Do not commit:

- `.carbonstack-openmls-sidecar-state/`
- `signer.json`
- `provider-storage.json`
- raw OpenMLS group/provider state
- private keys
- generated artifacts
- local SQLite DB files

## Original development directory

The early development directory was:

    .carbonstack-comms/

Early planned files included:

- `state.json`
- `trust.json`
- `messages.jsonl`

These were inspectable development files, not a secure vault.

## Future vault requirement

A future production local vault must provide:

- encrypted local message storage;
- identity key protection;
- group state protection;
- trust record protection;
- revocation state protection;
- safe lock/duress behavior;
- memory and key lifecycle design.

That design is not implemented yet.

## Current implementation boundary

The current validated relay proof focuses on:

- OpenMLS sidecar artifacts;
- Cypher envelope relay;
- payload metadata validation;
- consume-then-ack behavior;
- local development smoke tests.

It does not solve production local storage.
