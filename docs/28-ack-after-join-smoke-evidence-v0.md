# Comms ACK_AFTER_JOIN smoke evidence

Status: component live dev/pre-alpha ACK_AFTER_JOIN smoke evidence
Parent: carbonstack/docs/195-v0.5.50-ack-after-join-smoke-evidence-and-validation-profile-preflight-v0.md
Scope: Comms-side ACK_AFTER_JOIN evidence for Relay Space OpenMLS narrow join smoke proof
Date: 2026-06-09 local session

## 1. Purpose

This document records the Comms-side ACK_AFTER_JOIN=1 smoke proof.

It is evidence only.

It is not a validation profile.

It is not local-backbone.

## 2. Fresh generated state

The successful ACK_AFTER_JOIN run used fresh labels/state:

    carbonstack-v0550-alice-device;
    carbonstack-v0550-bob-device;
    carbonstack-v0550-conversation;
    v0550-ack-smoke-relay-space.

Future validation work should own fresh generated state explicitly.

## 3. Successful command sequence

The successful command sequence was:

    openmls-relay-keypackage-submit-dev;
    openmls-relay-add-member-dev;
    openmls-relay-join-dev.

ACK_AFTER_JOIN was set to 1.

## 4. KeyPackage evidence

Observed:

    command: openmls-relay-keypackage-submit-dev
    status: sent
    sidecar_command: public-bundle-export
    content_type: carbonstack.mls.keypackage.v0
    protocol_version: carbonstack-openmls-sidecar-v0
    delivery_state: queued

The KeyPackage envelope remained queued.

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

## 6. Join and ack evidence

Observed:

    command: openmls-relay-join-dev
    status: joined
    sidecar_command: conversation-join
    ack_requested: true
    welcome_acked: true
    ack_delivery_state: acknowledged
    joined: true
    group_reloadable: true
    member_count: 2
    epoch: GroupEpoch(1)

Observed ack fields:

    ack_envelope_id: 4da140d8-19a7-442e-9c30-31129ba15331
    acknowledged_at: 2026-06-09T13:44:45Z

## 7. DB evidence

The fresh v0.5.50 Cypher DB reported:

    envelopes: 2
    envelope_acks: 1

Envelope states:

    KeyPackage:
        content_type: carbonstack.mls.keypackage.v0
        delivery_state: queued

    Welcome:
        content_type: carbonstack.mls.welcome.v0
        delivery_state: acknowledged

The single ack row referenced the Welcome envelope.

## 8. Ack boundary

This run confirms the intended explicit ACK_AFTER_JOIN behavior:

    no KeyPackage ack;
    no Welcome ack during add-member;
    Welcome ack only after Bob's conversation-join succeeds;
    ack remains delivery/local-processing state, not trust or identity verification.

## 9. Trust/candidate boundary

The run did not create or mutate the checked trust/candidate stores:

    trust.json;
    trust-events.jsonl;
    identity-candidates.json.

Comms still must not convert Relay Space membership, KeyPackage presence, Welcome presence, sidecar add-member success, sidecar join success, provider member count, epoch advancement, or scoped ack into local verification.

## 10. Nonclaims

This evidence does not claim:

    local-backbone;
    verified identity;
    candidate acceptance;
    trust mutation;
    production messaging;
    hostile-server safety;
    metadata privacy;
    release-ready CLI.
