# Comms narrow join smoke-proof runbook

Status: component runbook / dev smoke-proof
Parent: carbonstack/docs/192-v0.5.48-narrow-join-smoke-proof-runbook-v0.md
Scope: Comms-side command sequence for Relay Space KeyPackage -> add-member -> Welcome -> join
Date: 2026-06-08 local session

## 1. Purpose

This document records the Comms-side narrow join smoke-proof sequence.

It is not a validation profile.

It is not local-backbone.

## 2. Commands involved

    openmls-relay-keypackage-submit-dev
    openmls-relay-add-member-dev
    openmls-relay-join-dev

Supporting commands remain available:

    openmls-relay-keypackage-inbox-dev
    openmls-relay-welcome-submit-dev
    openmls-relay-welcome-inbox-dev

## 3. Narrow sequence

    Bob submits a KeyPackage to Alice through Relay Space.
    Alice consumes the KeyPackage and runs sidecar conversation-add-member.
    Alice submits the produced Welcome back to Bob through Relay Space.
    Bob consumes the Welcome and runs sidecar conversation-join.
    Bob may optionally scoped-ack the Welcome only after join success.

## 4. Helper script

The helper script lives at:

    scripts/openmls-relay-narrow-join-smoke-dev.sh

The script is a thin command sequencer.

It does not create state.

It does not start Cypher.

It does not create Relay Spaces.

It does not mutate trust or candidates directly.

It does not claim local-backbone.

## 5. Required environment

    ALICE_STATE
    BOB_STATE
    RELAY_SPACE_ID
    ALICE_DEVICE_ID
    BOB_DEVICE_ID
    ALICE_SIDECAR_LABEL
    BOB_SIDECAR_LABEL
    ALICE_CONVERSATION_LABEL
    BOB_CONVERSATION_LABEL

Optional:

    COMMS_DIR
    ACK_AFTER_JOIN=1

## 6. Nonclaims

The smoke proof does not claim:

    local-backbone;
    verified identity;
    candidate acceptance;
    trust mutation;
    production messaging;
    hostile-server safety;
    metadata privacy;
    release-ready CLI.
