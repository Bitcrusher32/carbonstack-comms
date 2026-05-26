# Frozen Research Reference Notice

This crate is preserved as the known-good Phase 2D research sidecar reference.

Active maintained sidecar work has moved to:

    ../../openmls-sidecar

Do not use this README as the current command/status map. It intentionally preserves older research-stage context.

---
# CarbonStack OpenMLS Sidecar

Classification: Phase 2D experimental provider sidecar prototype.

This crate is the first runtime-boundary sidecar experiment after Phase 2C closure.

It is intentionally separate from the older OpenMLS minimal scratch crate:

- `../openmls-minimal`

The scratch crate preserved OpenMLS feasibility research.

This sidecar crate is for command-surface and runtime-boundary shaping.

## Current supported command

```powershell
cargo run -- provider-info
```

The command prints JSON describing the experimental provider.

## Current unsupported commands

These are intentionally not implemented yet:

- `identity-create`
- `public-bundle-export`
- `conversation-create`
- `conversation-add-member`
- `conversation-join`
- `message-protect`
- `message-open`
- `state-checkpoint`
- `state-load-check`

## Security status

This sidecar is not production E2EE.

This sidecar does not generate or handle real user secrets.

This sidecar is not wired into CarbonStackComms.

This sidecar is not wired into CarbonStackCypher.

This sidecar does not mutate `trust.json`.

This sidecar does not write provider storage.

## Phase 2D goal

The immediate Phase 2D goal is to prove that CarbonStack can maintain a small, explicit, JSON-speaking provider-sidecar boundary without coupling OpenMLS directly into the Go CLI.

The first milestone is deliberately boring:

- build the sidecar
- run `provider-info`
- validate JSON output shape
- keep all secret-bearing commands unsupported

