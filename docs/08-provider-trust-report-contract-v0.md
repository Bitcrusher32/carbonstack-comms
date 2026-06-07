# CarbonStackComms Provider-Trust Report Contract v0

Status: component-local implementation contract
Component: CarbonStackComms
Maturity: experimental / pre-release
Related code:

    internal/protocol/provider_trust.go
    internal/protocol/provider_trust_report.go
    internal/protocol/provider_trust_report_test.go

Related planning:

    docs/07-provider-state-linkage-plan-v0.md
    carbonstack/docs/172-v0.5.6-provider-state-linkage-plan-v0.md

## 1. Purpose

This document records the internal provider-trust report contract added after the provider-state linkage plan.

The current provider-trust report helper is an internal, non-mutating diagnostic surface around:

    protocol.DecideProviderTrust

It exists to make provider-trust decisions inspectable before CarbonStackComms implements provider-originated trust mutation.

It does not add a CLI command yet.

## 2. Current implementation

Current report helper:

    BuildProviderTrustReport(decision ProviderTrustDecision) ProviderTrustReport
    BuildProviderTrustReportForEvent(name ProviderEventName) ProviderTrustReport
    ProviderTrustReportJSON(report ProviderTrustReport) (string, error)
    ProviderTrustSummary(report ProviderTrustReport) string

Current report shape:

    event
    class
    severity
    trust_relevant
    actions
    blocks_send
    blocks_receive
    blocks_open
    requires_reverify
    user_visible
    history_relevant
    summary

## 3. Source-of-truth rule

The structured JSON fields are the diagnostic source of truth.

The human summary is interpretive helper text.

Meaning:

    tests and future automation should rely on structured fields;
    summary output may help humans read decisions;
    summary output is not final UX copy;
    summary output is not the policy source of truth;
    summary wording may evolve more freely than structured fields.

## 4. Non-mutating boundary

The report helper does not:

    mutate trust.json;
    append trust-events.jsonl;
    import provider identity;
    verify provider identity;
    revoke devices;
    mark devices changed in trust storage;
    ack messages;
    open messages;
    replace send/inbox;
    create local-backbone.

This boundary is intentional.

Provider-trust report output may describe actions such as:

    block_send;
    block_open;
    require_reverify;
    mark_identity_changed;
    quarantine_message;
    fatal_local_state.

But describing an action is not the same as executing it.

## 5. Current testing intent

Current tests cover representative events including:

    provider.identity.changed;
    provider.message.tamper.detected;
    message.opened;
    provider.signature.invalid;
    provider.secret.material.unavailable.

The tests prove report shape and mapping behavior.

They do not prove mature UX, provider identity import, trust-store mutation, or hostile-server safety.

## 6. Future exposure policy

A dev-only CLI command may be added later when useful.

Suggested future command shape, not implemented now:

    provider-trust-report-dev --event <provider-event-name> --json
    provider-trust-report-dev --event <provider-event-name> --summary

If such a command is added:

    JSON should be the stable output mode;
    human summary should be labelled interpretive;
    registry/commands.v0.yaml should be updated in the same or next checkpoint;
    README/docs should describe nonclaims;
    the command must remain non-mutating unless a later checkpoint deliberately changes that.

## 7. Nonclaims

This helper does not claim:

    provider-state linkage implementation;
    production identity safety;
    secure vault storage;
    mature UX;
    local-backbone;
    hostile-server safety;
    PQ/hybrid security;
    audit or certification.
