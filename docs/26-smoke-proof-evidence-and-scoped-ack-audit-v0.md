# Comms smoke-proof evidence and scoped ack audit

Status: component evidence checklist / scoped ack audit
Parent: carbonstack/docs/193-v0.5.49-smoke-proof-evidence-and-scoped-ack-audit-v0.md
Scope: Comms-side evidence expectations for Relay Space OpenMLS narrow join smoke proof
Date: 2026-06-09 local session

## 1. Purpose

This document defines the Comms-side evidence checklist for the v0.5.48 narrow join smoke script.

It is docs-only.

It does not add a command, script, registry entry, validation profile, trust mutation, candidate mutation, or local-backbone claim.

## 2. Script under audit

The script under audit is:

    scripts/openmls-relay-narrow-join-smoke-dev.sh

It sequences:

    openmls-relay-keypackage-submit-dev;
    openmls-relay-add-member-dev;
    openmls-relay-join-dev.

Supporting commands remain separate:

    openmls-relay-keypackage-inbox-dev;
    openmls-relay-welcome-submit-dev;
    openmls-relay-welcome-inbox-dev.

## 3. Required environment capture

Before running, capture:

    ALICE_STATE;
    BOB_STATE;
    RELAY_SPACE_ID;
    ALICE_DEVICE_ID;
    BOB_DEVICE_ID;
    ALICE_SIDECAR_LABEL;
    BOB_SIDECAR_LABEL;
    ALICE_CONVERSATION_LABEL;
    BOB_CONVERSATION_LABEL;
    COMMS_DIR if set;
    ACK_AFTER_JOIN setting.

Redact any sensitive values before public sharing.

## 4. Expected command evidence

Step 1 should show KeyPackage submitted:

    command: openmls-relay-keypackage-submit-dev
    status: sent
    content_type: application/vnd.carbonstack.openmls.keypackage
    envelope_id:

Step 2 should show add-member and Welcome submit:

    command: openmls-relay-add-member-dev
    status: welcome_created_and_sent
    sidecar_command: conversation-add-member
    welcome_envelope_id:
    keypackage_acked: false
    welcome_acked: false

Step 3 should show join:

    command: openmls-relay-join-dev
    status: joined
    sidecar_command: conversation-join
    ack_requested:
    welcome_acked:

If ACK_AFTER_JOIN is not 1:

    ack_requested: false
    welcome_acked: false

If ACK_AFTER_JOIN is 1:

    ack_requested: true
    welcome_acked: true
    ack_envelope_id:
    ack_delivery_state:
    acknowledged_at:

## 5. Ack audit rule

Comms must preserve:

    no KeyPackage ack in this script;
    no Welcome ack before join;
    no Welcome ack by default;
    optional Welcome ack only after sidecar join success;
    ack is local-processing/delivery state, not identity verification.

## 6. Failure cases to preserve before validation profile

Before turning this into a validation profile, evidence or tests must cover:

    no KeyPackage envelope;
    no Welcome envelope;
    KeyPackage write failure;
    Welcome write failure;
    sidecar conversation-add-member failure;
    sidecar conversation-join failure;
    ack client failure after join;
    no ack when write fails;
    no ack when join fails;
    no trust/candidate mutation.

## 7. Trust and candidate boundary

The smoke proof must not mutate:

    trust.json;
    trust-events.jsonl;
    identity-candidates.json;
    verified device state;
    candidate acceptance state;
    key replacement state;
    recovery state.

Comms must not convert:

    Relay Space membership;
    KeyPackage presence;
    Welcome presence;
    sidecar add-member success;
    sidecar join success;
    provider member count;
    epoch advancement;
    scoped ack;

into local verification.

## 8. Nonclaims

The script and its output do not claim:

    local-backbone;
    verified identity;
    candidate acceptance;
    trust mutation;
    production messaging;
    hostile-server safety;
    metadata privacy;
    release-ready CLI.
