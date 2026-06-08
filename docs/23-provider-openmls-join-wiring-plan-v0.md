# Comms provider/OpenMLS join wiring plan

Status: component boundary / planning-only
Parent: carbonstack/docs/190-v0.5.42-provider-openmls-join-wiring-plan-v0.md
Scope: Comms-side provider/OpenMLS join wiring boundaries after Relay Space client/bridge work
Date: 2026-06-08 local session

## 1. Purpose

This Comms component doc records how Comms should approach future Relay Space-backed OpenMLS join wiring.

It does not implement code.

It does not add app/runtime wiring, provider live-flow, OpenMLS join automation, validation profile, CLI/registry, or full local-backbone.

## 2. Current Comms state

Comms currently has:

    unscoped Cypher client methods;
    Relay Space Cypher client methods;
    unscoped OpenMLS artifact bridge helpers;
    Relay Space-aware OpenMLS artifact bridge helpers;
    OpenMLS sidecar dev commands for identity, KeyPackage export, conversation create, add-member, join, message protect, and message open;
    existing unscoped openmls-send-dev and openmls-inbox-dev behavior;
    ack-after-message-open behavior in the existing inbox path.

These surfaces are enough to plan join wiring.

They are not yet enough to claim mature provider live-flow or local-backbone.

## 3. Future Comms join path

A future Comms join path should be explicit and staged:

    invitee exports KeyPackage;
    invitee submits KeyPackage through Relay Space-scoped envelope;
    inviter receives KeyPackage through Relay Space-scoped inbox;
    inviter runs conversation-add-member;
    inviter submits Welcome through Relay Space-scoped envelope;
    invitee receives Welcome through Relay Space-scoped inbox;
    invitee runs conversation-join;
    invitee acks Welcome only after join succeeds.

Application-message flow comes later.

## 4. Ack rule

Comms must preserve ack-after-successful-sidecar-processing.

Do not ack:

    KeyPackage before successful add-member or explicit safe terminal handling;
    Welcome before successful conversation-join;
    application message before successful message-open.

## 5. Candidate/trust rule

Comms may eventually observe identity material from provider/OpenMLS artifacts.

That material may only enter candidate observation/review paths.

It must not:

    verify identity;
    mutate trust.json directly;
    replace keys;
    bypass candidate review;
    bypass recovery classification.

## 6. First safe Comms implementation after this plan

The first safe implementation should be narrow.

Preferred target:

    preflight first;
    add helper/command scaffolding for Relay Space KeyPackage and Welcome artifact transport only if route, sidecar, and ack boundaries remain clear;
    avoid broad runtime flow;
    avoid registry exposure;
    avoid validation profile claims.

## 7. Nonclaims

This doc does not claim:

    provider live-flow implementation;
    OpenMLS join automation;
    local-backbone;
    validation profile;
    verified identity import;
    trust mutation;
    metadata privacy;
    hostile-server safety;
    production secure messaging.
