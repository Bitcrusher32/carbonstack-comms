# Comms validation-profile generated-state contract

Status: component validation-profile design contract
Parent: carbonstack/docs/196-v0.5.51-validation-profile-design-contract-v0.md
Scope: Comms smoke script, sidecar state, generated labels, trust/candidate nonmutation
Date: 2026-06-09 local session

## 1. Purpose

This document defines the Comms-side contract for a future narrow local-dev validation profile.

It is docs-only.

It does not add a runner profile, script change, command change, registry entry, trust mutation, candidate mutation, or local-backbone claim.

## 2. Evidence baseline

Comms has live evidence for:

    no-ack KeyPackage -> add-member -> Welcome -> join;
    ACK_AFTER_JOIN=1 KeyPackage -> add-member -> Welcome -> join -> scoped Welcome ack.

These paths used:

    openmls-relay-keypackage-submit-dev;
    openmls-relay-add-member-dev;
    openmls-relay-join-dev;
    scripts/openmls-relay-narrow-join-smoke-dev.sh.

## 3. Future profile requirements

Future profile implementation must create fresh generated Comms state:

    Alice Comms state file;
    Bob Comms state file;
    Alice sidecar device label;
    Bob sidecar device label;
    Alice conversation label;
    Bob conversation label;
    no-ack smoke log;
    ACK_AFTER_JOIN smoke log.

The profile must not reuse older labels such as:

    carbonstack-alice-device;
    carbonstack-bob-device;
    carbonstack-test-conversation.

Reusing old labels caused a provider-storage collision during v0.5.49 live smoke attempts.

## 4. Sidecar state rule

Current sidecar generated state lives under:

    internal/protocol/mls/openmls-sidecar/.carbonstack-openmls-sidecar-state

Until a sidecar state-root override exists, the validation profile must use unique labels and refuse to continue if a matching device/conversation path already exists.

It must not delete unknown sidecar state.

## 5. Comms state rule

Comms state files used by the profile must live under runner-owned temp roots.

The profile must not use or mutate user-provided Comms state files.

The profile must not infer trust from:

    Relay Space membership;
    KeyPackage presence;
    Welcome presence;
    sidecar add-member success;
    sidecar join success;
    provider member count;
    epoch movement;
    group_reloadable;
    scoped ack.

## 6. Ack behavior required

No-ack run must show:

    ack_requested: false;
    welcome_acked: false.

ACK_AFTER_JOIN run must show:

    ack_requested: true;
    welcome_acked: true;
    ack_delivery_state: acknowledged;
    acknowledged_at populated.

KeyPackage must not be acked by the smoke script.

Welcome must be acked only after sidecar conversation-join succeeds and only when requested.

## 7. Trust/candidate boundary

Future validation must not mutate:

    trust.json;
    trust-events.jsonl;
    identity-candidates.json;
    verified device state;
    candidate acceptance state;
    key replacement state;
    recovery state.

Initial validation may check absence/unchanged state only under profile-owned state roots and known Comms state directories.

It must state that this is not a general trust-safety proof.

## 8. Nonclaims

Passing the future profile must not claim:

    local-backbone;
    verified identity;
    candidate acceptance;
    trust mutation;
    production messaging;
    hostile-server safety;
    metadata privacy;
    release-ready CLI.
