# Local Vault Model

Status: future design requirement
Component: CarbonStackComms
Maturity: not implemented as production storage

The local vault is a future production requirement.

It is not implemented by the current OpenMLS sidecar development state.

## Required vault contents

A future vault must protect:

- message database;
- identity keys;
- OpenMLS group state;
- contact trust records;
- revocation state;
- local metadata needed for safe recovery and trust decisions.

## Required vault behavior

The vault must be cryptographically locked.

It must not be merely hidden.

In CarbonStackOS lockdown or duress states, vault keys should be evicted from memory and vault access should stop.

## Current boundary

Current development state may include generated signer/provider files and sidecar artifacts.

Those files are sensitive development artifacts.

They must not be committed.

They do not provide production local secrecy.
