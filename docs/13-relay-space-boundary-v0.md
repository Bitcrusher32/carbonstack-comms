# CarbonStackComms Relay Space Boundary v0

Status: component-local architecture note
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/178-v0.5.16-relay-space-architecture-decision-v0.md

## 1. Purpose

This document records what Relay Space means for CarbonStackComms.

This is planning only.

No Comms runtime flow is changed by this document.

## 2. Core rule

Relay Space is routing/conversation infrastructure.

Relay Space is not identity authority.

Server membership claims are not local trust.

Invite claim is not verification.

Cypher delivery is not trust.

## 3. Comms responsibilities

Comms owns:

    local identity state;
    local trust state;
    local trust history;
    provider event classification;
    candidate identity policy later;
    mapped mismatch/reverify policy later;
    send/open/ack behavior;
    user-visible trust warnings later;
    verification ceremonies later.

## 4. Membership boundary

Comms must distinguish:

    server-visible routing membership;
    provider/MLS group membership;
    local known devices;
    local verified devices;
    local changed/revoked devices;
    unresolved candidate identities.

A server saying a device is present does not make it verified.

## 5. Candidate/mismatch interaction

Relay Space join or invite flows may later produce candidate identity material.

Candidate identity material must follow the v0.5.14/v0.5.15 rules:

    provider-observed identity material is not trust;
    candidate import and verification are separate;
    mapped mismatch requires explicit policy;
    known verified identity must not be silently replaced.

## 6. Ack boundary

Relay Space work must preserve ack policy:

    retrieval is not enough;
    artifact write is not enough;
    trust-history append is not enough;
    successful sidecar message-open/consume is required before ack unless a later negative-ack/quarantine design is explicitly created.

## 7. Future warning

Do not create local-backbone or mature Relay Space join UX until Relay Space architecture, candidate identity, mapped mismatch, reset/recovery, and validation-profile boundaries are stable enough.
