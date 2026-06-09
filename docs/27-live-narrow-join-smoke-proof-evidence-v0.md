# Comms live narrow join smoke-proof evidence

Status: component live dev/pre-alpha smoke evidence
Parent: carbonstack/docs/194-v0.5.49-live-narrow-join-smoke-proof-evidence-v0.md
Scope: Comms-side no-ack Relay Space OpenMLS join smoke evidence
Date: 2026-06-09 local session

## 1. Purpose

This document records the Comms-side result of the first successful live no-ack narrow join smoke proof.

It is evidence only.

It is not a validation profile.

It is not local-backbone.

## 2. Fresh sidecar requirement

The smoke run succeeded after switching to fresh sidecar labels:

    carbonstack-v0549-alice-device;
    carbonstack-v0549-bob-device;
    carbonstack-v0549-conversation.

An earlier attempt using older sidecar labels failed because provider storage already existed.

Future smoke runs should use fresh sidecar labels/state unless cleanup ownership is explicit.

## 3. Successful command sequence

The successful no-ack command sequence was:

    openmls-relay-keypackage-submit-dev;
    openmls-relay-add-member-dev;
    openmls-relay-join-dev.

ACK_AFTER_JOIN was unset.

## 4. KeyPackage evidence

Observed:

    command: openmls-relay-keypackage-submit-dev
    status: sent
    sidecar_command: public-bundle-export
    content_type: carbonstack.mls.keypackage.v0
    protocol_version: carbonstack-openmls-sidecar-v0
    delivery_state: queued

## 5. Add-member evidence

Observed:

    command: openmls-relay-add-member-dev
    status: welcome_created_and_sent
    sidecar_command: conversation-add-member
    keypackage_acked: false
    welcome_acked: false
    member_added: true
    welcome_artifact_written: true
    group_reloadable: true
    member_count_before: 1
    member_count_after: 2
    epoch_before: GroupEpoch(0)
    epoch_after: GroupEpoch(1)

## 6. Join evidence

Observed:

    command: openmls-relay-join-dev
    status: joined
    sidecar_command: conversation-join
    ack_requested: false
    welcome_acked: false
    joined: true
    group_reloadable: true
    member_count: 2
    epoch: GroupEpoch(1)

## 7. Ack boundary

The successful run was no-ack:

    KeyPackage was not acked.
    Welcome was not acked.
    ACK_AFTER_JOIN was unset.
    openmls-relay-join-dev reported ack_requested: false and welcome_acked: false.

This preserves the scoped ack boundary for a dedicated ACK_AFTER_JOIN=1 run or validation-profile preflight.

## 8. Trust/candidate boundary

The run did not create or mutate the checked trust/candidate stores:

    trust.json;
    trust-events.jsonl;
    identity-candidates.json.

Comms still must not convert Relay Space membership, KeyPackage presence, Welcome presence, sidecar add-member success, sidecar join success, provider member count, epoch advancement, or scoped ack into local verification.

## 9. Nonclaims

This evidence does not claim:

    local-backbone;
    verified identity;
    candidate acceptance;
    trust mutation;
    production messaging;
    hostile-server safety;
    metadata privacy;
    release-ready CLI.
