# CarbonStackComms Relay Space Join/Invite/Member Boundary v0

Status: component-local Relay Space planning boundary
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/185-v0.5.31-relay-space-join-invite-member-planning-v0.md

## 1. Purpose

This document records what Relay Space join/invite/member mechanics mean for CarbonStackComms.

This is planning only.

No Comms runtime flow is changed by this document.

## 2. Core rule

Relay Space is a vector to OpenMLS join and a routing/conversation container.

Relay Space is not local trust.

OpenMLS/provider join is cryptographic group participation.

Local verification is the actual trust/auth/presence decision.

## 3. Comms authority

Comms owns:

    local identity state;
    local trust state;
    local trust history;
    identity-candidates.json;
    candidate review/update;
    mapped mismatch classification;
    recovery classification/orchestration;
    provider trust reports/history;
    send/open/ack policy;
    future verification ceremony.

Cypher and Relay Space must not mutate these by themselves.

## 4. Membership terms

Comms should distinguish:

    routing_member;
    provider_member;
    local_known_device;
    local_verified_device;
    candidate_identity;
    blocked_or_revoked_device.

A routing_member is server-side routing state.

A provider_member is OpenMLS/provider group state.

A local_verified_device is Comms-local trust state.

Do not treat routing membership as verified trust.

## 5. Join stages from Comms perspective

Suggested staged model:

    invite_claimed;
    routing_member_registered;
    provider_keypackage_observed;
    provider_welcome_consumed;
    provider_joined;
    candidate_identity_observed;
    candidate_review_required;
    locally_verified.

Only locally_verified means trusted.

## 6. Candidate / mismatch / recovery interaction

Relay Space join may surface provider identity material.

That material should enter candidate/review flows, not verified trust.

Rules:

    provider-observed identity is not trust;
    server-routed identity is not trust;
    sidecar labels are not trust;
    known verified identity must not be silently replaced;
    conflicts require review/reverify;
    unsafe recovery state must block or warn before trust-sensitive actions.

## 7. Ack boundary

Comms must preserve ack-after-open:

    routing membership is not enough;
    invite claim is not enough;
    envelope retrieval is not enough;
    artifact write is not enough;
    trust-history append is not enough;
    only successful sidecar message-open/consume may permit ack unless a later negative-ack/quarantine design exists.

## 8. Future implementation guidance

Future Comms work should be split into narrow rungs:

    client wrapper for Relay Space APIs;
    candidate handoff for observed identity material;
    provider/OpenMLS join wiring;
    tests proving no trust.json mutation from server membership;
    tests proving no identity-candidates mutation unless candidate observation is explicit;
    tests preserving ack boundary.

Do not combine Relay Space, provider live-flow, validation profile, CLI, and local-backbone into one rung.

## 9. Nonclaims

This document does not claim:

    Relay Space implementation;
    OpenMLS join automation;
    provider live-flow wiring;
    mature verification UX;
    verified identity import;
    trust.json mutation;
    local-backbone readiness;
    CLI/registry exposure;
    production readiness.
