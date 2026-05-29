# CarbonStackComms Scripts

This folder contains local development validation scripts.

These scripts are not production deployment tooling.

They exist to prove the current CarbonStack experimental backbone path from the Comms side.

## Current known-good entrypoint

Run:

    powershell -ExecutionPolicy Bypass -File .\scripts\self-test-openmls-backbone.ps1

This is the current OpenMLS backbone self-test path.

The wrapper delegates to the lower-level real-Cypher smoke harness:

    powershell -ExecutionPolicy Bypass -File .\scripts\smoke-openmls-real-cypher-relay.ps1

It proves the local OpenMLS sidecar + real Cypher server relay lifecycle:

1. start a real local Cypher server;
2. use a temp SQLite database;
3. export an OpenMLS KeyPackage;
4. relay the KeyPackage through Cypher;
5. consume the KeyPackage and produce a Welcome;
6. relay the Welcome through Cypher;
7. consume the Welcome;
8. protect an application-message;
9. relay the application-message through Cypher;
10. validate payload metadata before artifact write;
11. consume the application-message through the sidecar;
12. ack envelopes only after sidecar consume succeeds.

This proves an experimental local backbone lifecycle.

It does not prove production readiness.

It does not prove hostile-server safety.

It does not prove metadata privacy.

It does not prove Android readiness.

It does not prove external audit or certification.

## Broader validation

Run:

    powershell -ExecutionPolicy Bypass -File .\scripts\self-test-openmls-backbone.ps1 -Full

The `-Full` path delegates to the lower-level smoke harness and runs the targeted real-server proof, relay tests, protocol tests, broader Go tests, and generated Rust/OpenMLS artifact guard.

The lower-level command remains available:

    powershell -ExecutionPolicy Bypass -File .\scripts\smoke-openmls-real-cypher-relay.ps1 -Full

Use `-Full` before pushing changes that affect relay, protocol, sidecar, client, or script behavior.

## Generated artifact guard

Run:

    powershell -ExecutionPolicy Bypass -File .\scripts\check-no-rust-artifacts.ps1

This checks that generated Rust/build artifacts are not tracked by Git.

It does not check every sensitive generated sidecar file. It is a build-artifact guard, not a complete secret scanner.

## Stale Cypher process warning

The smoke harness refuses to run if a `cypher` process is already active.

Inspect stale processes:

    Get-Process cypher -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path

Stop stale test processes when no intentional Cypher server is running:

    Get-Process cypher -ErrorAction SilentlyContinue | Stop-Process -Force

This matters on Windows because stale `cypher.exe` processes can hold temp SQLite files open.

## Older scripts

`test-local-lifecycle.ps1` and `test-trust-lifecycle.ps1` belong to earlier local client/trust scaffolding.

They are not the current OpenMLS + Cypher backbone proof.

Use the OpenMLS backbone self-test path for the current known-good backbone validation.
## Self-test wrapper

The public-facing self-test name is:

    OpenMLS backbone self-test harness

The wrapper is:

    scripts/self-test-openmls-backbone.ps1

It calls the existing real-Cypher smoke harness instead of duplicating the proof logic.

