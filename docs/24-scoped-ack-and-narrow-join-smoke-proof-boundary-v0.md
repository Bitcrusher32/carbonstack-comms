# Comms scoped ack and narrow join smoke-proof boundary

Status: component boundary / planning-only
Parent: carbonstack/docs/191-v0.5.47-scoped-ack-and-narrow-join-smoke-proof-plan-v0.md
Scope: Comms-side Relay Space OpenMLS dev join scaffold boundary
Date: 2026-06-08 local session

## 1. Purpose

This document records the Comms boundary after the Relay Space OpenMLS dev command scaffold reached:

    KeyPackage submit/inbox/write;
    add-member + Welcome submit;
    Welcome inbox/write;
    join;
    optional Welcome scoped ack after join success.

It is docs-only.

## 2. Current command scaffold

The current Comms command scaffold includes:

    openmls-relay-keypackage-submit-dev;
    openmls-relay-keypackage-inbox-dev;
    openmls-relay-welcome-submit-dev;
    openmls-relay-welcome-inbox-dev;
    openmls-relay-add-member-dev;
    openmls-relay-join-dev.

These are dev/pre-alpha commands.

They are not production UX.

## 3. Ack boundary

Comms owns the client-side decision of when scoped ack is safe.

Current rule:

    Welcome scoped ack is absent by default.
    Welcome scoped ack is opt-in through --ack-after-join.
    Welcome scoped ack may occur only after sidecar conversation-join succeeds.

Failure paths must not ack:

    missing Welcome;
    Welcome write failure;
    sidecar conversation-join failure;
    ack client failure before a successful ack response.

## 4. Trust and candidate boundary

Comms must not convert Relay Space or OpenMLS provider observations into local trust.

Do not mutate:

    trust.json;
    identity-candidates.json;
    verified device state;
    key replacement state;
    recovery state.

The current commands may move artifacts and run sidecar commands.

They do not verify identity.

## 5. Next safe work

Next safe work is a narrow smoke-proof plan or harness, not a validation profile.

The smoke proof should demonstrate one local/dev KeyPackage -> add-member -> Welcome -> join sequence with explicit nonclaims.

Validation profile work should wait until the smoke proof is repeatable and failure behavior is documented.
