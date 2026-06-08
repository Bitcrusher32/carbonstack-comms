# CarbonStackComms

CarbonStackComms is the text-first communications client component of CarbonStack.

At this stage, it is not a finished messenger.

It is not production-certified.

It is not externally audited.

It is not Android-ready.

The current validated artifact is a development proof that CarbonStackComms can use an OpenMLS sidecar and CarbonStackCypher relay storage to complete a local OpenMLS relay lifecycle.


_Related repositories: [carbonstack](https://git.bitcrusher32.win/bitcrusher32/carbonstack) / [carbonstack-cypher](https://git.bitcrusher32.win/bitcrusher32/carbonstack-cypher) / [carbonstack-os](https://git.bitcrusher32.win/bitcrusher32/carbonstack-os)_

## Current implemented role

CarbonStackComms currently contains:

- a text-first client scaffold;
- a promoted OpenMLS development sidecar;
- protocol tests for the OpenMLS sidecar lifecycle;
- an internal relay helper for Cypher/OpenMLS artifact transport;
- a real-Cypher smoke harness;
- metadata validation before writing downloaded sidecar artifacts;
- consume-then-ack proof boundaries.

## Current validated relay path

The current proof validates:

1. Bob exports an OpenMLS KeyPackage artifact.
2. Comms submits it to Cypher as an opaque envelope.
3. Alice retrieves and writes the artifact.
4. Alice consumes it through the OpenMLS sidecar and creates a Welcome.
5. Comms submits the Welcome to Cypher.
6. Bob retrieves and writes the Welcome.
7. Bob consumes it through the sidecar.
8. Alice creates an application-message artifact.
9. Comms submits it to Cypher.
10. Bob retrieves, validates metadata, writes, and consumes the application-message.
11. The plaintext matches.
12. Envelopes are acked only after sidecar consume succeeds.

This is a development proof. It is not a polished runtime UX.

## Core communication constraints

CarbonStackComms is intended to preserve these constraints:

- text-first messaging;
- no rich previews;
- no hidden linkification;
- no inline attachments by default;
- loud trust changes;
- hostile-server assumptions;
- strict parser minimization;
- no server-trusted identity changes.

## Dev-only OpenMLS runtime commands

The explicit runtime OpenMLS dev commands are:

    go run ./cmd/comms openmls-send-dev
    go run ./cmd/comms openmls-inbox-dev

These commands are dev-only and pre-alpha. They do not replace the existing stub-era `send` / `inbox` commands yet.

`openmls-send-dev` current purpose:

    call the OpenMLS sidecar `message-protect` command
    submit the resulting application-message artifact through the Cypher relay helper
    preserve dev-mode trust behavior by default, with optional `--strict`

Minimal send shape:

    go run ./cmd/comms openmls-send-dev \
      --to-device <recipient-cypher-device-id> \
      --sidecar-device-label <sender-sidecar-device-label> \
      --conversation <sidecar-conversation-label> \
      --message <plaintext> \
      [--message-label <label>] \
      [--strict]

`openmls-inbox-dev` current purpose:

    fetch the current device inbox from Cypher
    skip unsupported non-OpenMLS application-message envelopes
    write an OpenMLS application-message artifact through the relay helper
    call the OpenMLS sidecar `message-open` command
    print plaintext only after sidecar success
    ack only after sidecar success when `--ack` is explicitly set

Minimal inbox shape:

    go run ./cmd/comms openmls-inbox-dev \
      --sidecar-device-label <recipient-sidecar-device-label> \
      --conversation <sidecar-conversation-label> \
      [--message-label <label>] \
      [--limit 1] \
      [--ack]

This is not mature messaging UX, not local-backbone, and not a production security claim.

## OpenMLS sidecar

The promoted OpenMLS sidecar lives at:

    internal/protocol/mls/openmls-sidecar

It is used by protocol tests and relay smoke proofs.

It is still dev-local and experimental.

It does not implement production secure vault storage.

Generated signer/provider state must not be committed.

## Dev runtime OpenMLS smoke proof

The dev runtime smoke proof is:

    scripts/dev-openmls-runtime-smoke.sh

It creates a temporary local Cypher server, temporary Comms state files, dev-local OpenMLS sidecar identities, and a dev-local sidecar conversation. It then proves the current CLI runtime message path:

    openmls-send-dev -> Cypher -> openmls-inbox-dev --ack

Boundary:

    this is dev/pre-alpha only
    this is not local-backbone
    this is not production messaging UX
    this does not replace the old stub-era send/inbox commands
    sidecar KeyPackage/Welcome/bootstrap setup is still direct dev setup
    the application-message path is the runtime CLI proof target

The script removes prior sidecar dev state before running and uses a temporary Cypher database.\n\n## Smoke harness

Run the current OpenMLS backbone self-test:

    powershell -ExecutionPolicy Bypass -File .\scripts\self-test-openmls-backbone.ps1

Run broader validation:

    powershell -ExecutionPolicy Bypass -File .\scripts\self-test-openmls-backbone.ps1 -Full
    powershell -ExecutionPolicy Bypass -File .\scripts\check-no-rust-artifacts.ps1

## Main runbook

Use the main `carbonstack` repo for the current public runbook:

    docs/113-experimental-backbone-deployability-runbook-v0.md

## Trust-state model

CarbonStackComms has a development trust-state model covering:

- unknown;
- unverified;
- verified;
- changed;
- revoked;
- reserved compromised.

Component-local notes live in:

    docs/06-trust-state-model-v0.md

This model describes current dev trust behavior and future trust requirements. It is not production identity safety, not secure vault storage, and not provider-state linkage implementation.

## Provider-state linkage plan

CarbonStackComms has a provider-state linkage plan for how OpenMLS sidecar/provider events should eventually map into Comms trust behavior.

Component-local notes live in:

    docs/07-provider-state-linkage-plan-v0.md

Current provider-trust decisions are pure pre-integration policy helpers. They do not mutate `trust.json`, do not append `trust-events.jsonl`, and do not implement production provider-state linkage.

## Provider-trust report contract

CarbonStackComms has an internal provider-trust report helper for inspecting pure `protocol.DecideProviderTrust` output.

Component-local notes live in:

    docs/08-provider-trust-report-contract-v0.md

The structured JSON report fields are the diagnostic source of truth. Human summaries are interpretive helper text, not final UX copy and not the policy source of truth. The helper is non-mutating: it does not write `trust.json`, does not append `trust-events.jsonl`, and does not import provider identity.

## Provider-trust report exposure decision

The provider-trust report helper remains internal-only for now.

Component-local notes live in:

    docs/09-provider-trust-report-exposure-decision-v0.md

No `provider-trust-report-dev` command exists yet. A future dev command should be JSON-first, non-mutating, and registry-tracked when it becomes useful.

## Provider-originated trust-history append plan

CarbonStackComms has a plan for how provider-originated security/trust observations may eventually append trust history.

Component-local notes live in:

    docs/10-provider-originated-trust-history-append-plan-v0.md

No provider event currently appends `trust-events.jsonl` or mutates `trust.json`. Future append behavior must preserve the rule that provider observation alone does not verify identity.

## Provider identity candidate / unverified import plan

CarbonStackComms has a planning record for how provider-observed identity material may later become a candidate or unverified identity record.

Component-local notes live in:

    docs/11-provider-identity-candidate-import-plan-v0.md

Provider-observed identity material is not trust. It must not automatically become verified, must not silently replace a known device, and must not let Cypher delivery or sidecar labels become trust roots.

## Mapped provider identity mismatch plan

CarbonStackComms has a planning record for how provider/candidate identity conflicts with known local device state should later become history-only, review-required, changed/reverify-required, or blocked.

Component-local notes live in:

    docs/12-mapped-provider-identity-mismatch-plan-v0.md

Provider mismatch handling is not implemented yet. The current plan preserves that provider observation alone must not verify a device, replace a known key, mutate `trust.json`, or trust Cypher/sidecar labels as identity authority.

## Relay Space boundary

CarbonStackComms has a planning note for the future Relay Space boundary:

    docs/13-relay-space-boundary-v0.md

Relay Space is routing/conversation infrastructure, not identity authority. Server membership claims, invite claims, Cypher delivery, and sidecar labels must not become verified local trust.

## Candidate identity storage priority

CarbonStackComms has a decision record for the next narrow implementation target:

    docs/14-candidate-identity-storage-priority-v0.md

The preferred next implementation is separate `identity-candidates.json` storage owned by `internal/trust`. Candidate identity material must not automatically become verified trust, must not mutate `trust.json`, and must not affect send/open/ack behavior in the first spike.

## Candidate review/update priority

CarbonStackComms has a decision record for the next internal trust implementation target:

    docs/15-candidate-review-update-priority-v0.md

Candidate review/update mechanics should come before candidate/mismatch trust-history append integration. This remains internal trust-package work: no `trust.json` mutation, no `trust-events.jsonl` append, no verified identity import, no send/open/ack changes, no CLI, and no registry exposure yet.

## Reset/recovery/re-enrollment boundary

CarbonStackComms has a decision record for reset/recovery/re-enrollment boundaries:

    docs/16-reset-recovery-reenrollment-boundary-v0.md

Reset, recovery, and re-enrollment are not implemented yet. The current boundary is Comms-first: define how local app state, `trust.json`, `trust-events.jsonl`, `identity-candidates.json`, OpenMLS provider state, relay staging artifacts, and generated dev artifacts should be classified before any destructive reset or recovery helper exists.

## Post-recovery-classifier priority

CarbonStackComms has a decision record for the next internal trust implementation target after the pure reset/recovery classifier:

    docs/17-post-recovery-classifier-priority-v0.md

The next target is recovery-history append helpers. These should record selected recovery classifications in `trust-events.jsonl` without mutating `trust.json`, without mutating `identity-candidates.json`, without verifying identity, without replacing key material, without send/open/ack changes, and without CLI/registry exposure.

## Post-recovery-orchestration boundary

CarbonStackComms has a component-local reassessment after the recovery orchestration helper:

    docs/18-post-recovery-orchestration-boundary-v0.md

The current recovery orchestration path is internal and non-destructive. It can classify local recovery state and optionally append recovery-history events, but it is not recovery execution, not a verification ceremony, not Relay Space, not local-backbone, and not a CLI/registry surface.

## Relay Space join/invite/member boundary

CarbonStackComms has a component-local planning record for future Relay Space join/invite/member mechanics:

    docs/19-relay-space-join-invite-member-boundary-v0.md

Relay Space is a vector to OpenMLS join and a routing/conversation container. It is not local trust. OpenMLS/provider join is cryptographic group participation. Local verification remains the actual trust/auth/presence decision.

## Provider live-flow boundary

CarbonStackComms has a component-local planning record for future provider/OpenMLS live-flow wiring:

    docs/20-provider-live-flow-boundary-v0.md

Broad provider live-flow remains deferred. Future wiring must preserve candidate/review/recovery/trust boundaries, must not verify identity from provider observation alone, must not mutate `trust.json` from provider observation alone, and must keep ack gated on successful sidecar message-open/consume.

## What is not implemented

CarbonStackComms does not currently provide:

- production runtime send/inbox OpenMLS UX;
- Android app readiness;
- production local vault storage;
- external audit or certification;
- production E2EE security claims;
- hostile-server-complete rollback/replay defense.

This repo is an implementation and development surface. The public release framing belongs in the main `carbonstack` repo.
## Lower-level smoke harness

The public self-test entrypoint is:

    powershell -ExecutionPolicy Bypass -File .\scripts\self-test-openmls-backbone.ps1

The lower-level implementation harness remains available for debugging:

    powershell -ExecutionPolicy Bypass -File .\scripts\smoke-openmls-real-cypher-relay.ps1


---

License: MIT.
See the repository's LICENSE file for more information.

## Dev-only OpenMLS bootstrap commands

These commands are development helpers for explicit OpenMLS sidecar bootstrap state.

They are not production identity UX, not Relay Space join UX, not local-backbone, and not secure vault/state management.

    openmls-identity-create-dev
    openmls-identity-status-dev
    openmls-bundle-export-dev
    openmls-conversation-create-dev
    openmls-conversation-load-check-dev
    openmls-conversation-add-member-dev
    openmls-conversation-join-dev

Current identity bootstrap examples:

    go run ./cmd/comms openmls-identity-create-dev --sidecar-device-label carbonstack-dev-alice
    go run ./cmd/comms openmls-identity-status-dev --sidecar-device-label carbonstack-dev-alice
    go run ./cmd/comms openmls-bundle-export-dev --sidecar-device-label carbonstack-dev-alice --write-artifact
    go run ./cmd/comms openmls-conversation-create-dev --sidecar-device-label carbonstack-dev-alice --conversation carbonstack-dev-conversation
    go run ./cmd/comms openmls-conversation-load-check-dev --sidecar-device-label carbonstack-dev-alice --conversation carbonstack-dev-conversation
    go run ./cmd/comms openmls-conversation-add-member-dev --sidecar-device-label carbonstack-dev-alice --conversation carbonstack-dev-conversation --member-keypackage <path-to-member-keypackage>
    go run ./cmd/comms openmls-conversation-join-dev --sidecar-device-label carbonstack-dev-bob --conversation carbonstack-dev-conversation --welcome <path-to-welcome>

Boundary:

    sidecar labels are explicit for now
    Comms state/trust files are not mutated by these wrappers
    existing send/inbox remain stub-era
    dev-runtime-openmls remains the current manual smoke-profile proof
## Wrapper-based dev runtime OpenMLS smoke proof

This optional smoke script validates the current dev-only bootstrap wrapper surface before the existing runtime send/open path:

    scripts/dev-openmls-runtime-smoke-wrappers.sh

Proof shape:

    openmls-*-dev bootstrap wrappers -> openmls-send-dev -> Cypher -> openmls-inbox-dev --ack

Boundary:

    This is a dev/pre-alpha wrapper smoke proof.
    It is not local-backbone.
    It is not mature messaging UX.
    It is not production E2EE.
    It does not replace the direct-sidecar smoke script yet.
    The manual dev-runtime-openmls runner profile still wraps scripts/dev-openmls-runtime-smoke.sh.
