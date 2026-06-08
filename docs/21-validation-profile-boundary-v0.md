# CarbonStackComms Validation Profile Boundary v0

Status: component-local validation-profile boundary
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/187-v0.5.33-validation-profile-boundary-v0.md

## 1. Purpose

This document records Comms-side validation profile boundaries before Relay Space, provider live-flow, local-backbone, CLI, or registry implementation.

This is planning only.

No Comms runtime flow or validation profile is changed by this document.

## 2. Comms state classes

Comms may create or use several classes of state:

    trust.json;
    trust-events.jsonl;
    identity-candidates.json;
    OpenMLS sidecar state;
    provider storage/checkpoint state;
    signer state;
    test fixtures;
    generated build artifacts.

These must not be treated as one cleanup class.

## 3. Cleanup boundary

Validation cleanup may remove only known generated/build/test roots created for validation.

Validation cleanup must not delete or rewrite:

    user trust.json;
    user trust-events.jsonl;
    user identity-candidates.json;
    user provider identity state;
    user provider storage/checkpoint state;
    unknown local state;
    non-temp generated roots.

Cleanup is not recovery.

## 4. Trust boundary

Validation must not silently:

    verify devices;
    promote candidates;
    replace keys;
    revoke devices;
    mark devices changed;
    suppress reverify/recovery warnings;
    mutate trust.json from provider observation;
    mutate identity-candidates.json from Relay Space routing membership.

Test-only state mutation is allowed only in isolated temp/generated roots and must remain explicitly named.

## 5. Provider / Relay Space boundary

Future validation may test provider/OpenMLS operations only under explicit dev boundaries.

It must preserve:

    Relay Space is not local trust;
    OpenMLS/provider membership is not local verification;
    candidate observation is not verification;
    recovery classification is not recovery execution;
    ack remains sidecar-open/consume gated.

## 6. Future profile participation

Comms may later participate in:

    Relay Space client-wrapper validation;
    provider join validation;
    candidate handoff validation;
    no-trust-mutation validation;
    ack-boundary validation;
    local-backbone dev validation.

Do not expose those as CLI/registry/profile surfaces until implementation and claim boundaries exist.

## 7. Nonclaims

This document does not claim:

    new validation profile;
    local-backbone;
    Relay Space implementation;
    provider live-flow implementation;
    CLI/registry exposure;
    production secure messaging;
    mature verification UX;
    security certification.
