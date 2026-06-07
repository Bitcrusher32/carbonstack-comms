# CarbonStackComms Trust State Model v0

Status: component-local model / planning record
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/171-v0.5.5-trust-state-model-v0.md

## 1. Purpose

This document records the CarbonStackComms-local trust-state model.

It mirrors the main CarbonStack v0.5.5 trust-state model, but keeps the component-local implementation boundary visible.

CarbonStackComms currently has:

    trust.json
    trust-events.jsonl
    internal/trust/trust.go
    fingerprint
    verify-device
    trust-history
    trust-list
    simulate-key-change
    revoke-device
    dev and strict send trust policy

It does not currently have:

    production secure trust storage;
    real safety-number UX;
    OpenMLS provider identity import into trust.json;
    provider-state linkage;
    mature send/inbox UX;
    local-backbone;
    production vault protection.

## 2. Current trust files

Trust files are derived from the Comms state path:

    .carbonstack-comms/trust.json
    .carbonstack-comms/trust-events.jsonl

Current storage properties:

    parent directories are created with restrictive permissions where current helpers write state;
    trust store files are development JSON / JSONL;
    they are not production secure vault storage;
    they must not be committed.

## 3. Trust states

### unknown

No local trust record exists for the device.

Current behavior:

    dev mode may warn and allow;
    strict mode blocks.

Mature target:

    block by default unless an explicit unsafe override exists.

### unverified

A device identity has been observed or recorded but not verified by the user.

Current behavior:

    state constant exists;
    current flows mostly use unknown or verified.

Mature target:

    display as not verified;
    block by default for high-trust sends;
    require verification.

### verified

The user has explicitly accepted the device identity.

Current behavior:

    verify-device records verified state;
    strict send allows verified devices;
    trust-events.jsonl records device_verified.

Mature target:

    verified means locally accepted, not server-approved.

### changed

A known device identity appears different from the local record.

Current behavior:

    simulate-key-change marks changed;
    strict send blocks;
    dev mode warns and can allow;
    verify-device can reverify changed material.

Mature target:

    block until reverified;
    preserve warning and history.

### revoked

The device was explicitly revoked.

Current behavior:

    revoke-device marks revoked;
    revoked blocks even in dev mode;
    trust-events.jsonl records device_revoked.

Mature target:

    require explicit re-enrollment or recovery policy, not silent re-enable.

### compromised

Reserved state for future compromise/recovery behavior.

Current behavior:

    state constant exists;
    not meaningfully exercised by current flows.

Mature target:

    block and require recovery/re-enrollment.

## 4. Current send policy

| Trust state | Dev mode | Strict mode |
|---|---|---|
| unknown | warn + allow | block |
| unverified | warn + allow | block |
| verified | allow | allow |
| changed | warn + allow | block |
| revoked | block | block |
| compromised | block | block |

This is development behavior.

Mature UX should be stricter by default.

## 5. Trust events

Current event types:

    device_verified
    device_key_changed
    device_revoked

Current event record fields:

    event_id
    event_type
    account_id
    device_id
    previous_trust_state
    new_trust_state
    fingerprint
    event_time
    source
    note

Required future behavior:

    verification events should remain visible;
    key-change events should be loud;
    revocation events should remain blocking;
    event history loss should become loud;
    provider-originated events must be distinguishable from manual user actions.

## 6. OpenMLS sidecar boundary

Current OpenMLS bootstrap wrappers do not mutate:

    trust.json
    trust-events.jsonl

Current runtime OpenMLS dev commands may consult trust state for send behavior, but provider identity is not yet imported into the Comms trust store.

Future provider linkage must be explicit:

    observed provider identity should not silently become verified;
    provider identity mismatch should become changed / reverify-required behavior;
    provider trust-security events should produce loud warnings or blocks;
    Cypher must not decide trust truth.

## 7. Local vault boundary

Trust state is future vault-relevant.

Current trust files are not a vault.

Future vault or authenticated storage should protect:

    trust.json;
    trust-events.jsonl;
    future real identity bindings;
    revocation and recovery records.

## 8. Nonclaims

This document does not claim:

    production identity safety;
    production E2EE;
    production trust-store security;
    provider-state linkage implementation;
    mature UX;
    local-backbone;
    hostile-server safety;
    metadata privacy;
    vault protection;
    audit or certification.
