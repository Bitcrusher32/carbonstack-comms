# CarbonStackComms Provider-Trust Report Exposure Decision v0

Status: component-local decision record
Component: CarbonStackComms
Maturity: experimental / pre-release
Related main doctrine: carbonstack/docs/174-v0.5.9-provider-trust-report-exposure-decision-v0.md

## 1. Decision

Keep the provider-trust report helper internal-only for now.

Do not add:

    provider-trust-report-dev

yet.

## 2. Reason

The helper is already test-backed and useful internally.

A CLI command would create a new command/registry/help surface before the workflow actually needs it.

The next better target is provider-originated trust-history append planning.

## 3. Current helper

Current helper code:

    internal/protocol/provider_trust_report.go

Current tests:

    internal/protocol/provider_trust_report_test.go

Current docs:

    docs/08-provider-trust-report-contract-v0.md

## 4. Output policy

Structured JSON fields are the diagnostic source of truth.

Human summaries are interpretive helper text.

If a future CLI command is added:

    JSON should be the stable output;
    summary output should be labelled interpretive;
    summary output should not be parsed as policy;
    the command must stay non-mutating unless a later checkpoint deliberately changes that.

## 5. Non-mutating boundary

The helper does not:

    write trust.json;
    append trust-events.jsonl;
    import provider identity;
    verify provider identity;
    revoke devices;
    mark devices changed in persistent trust storage;
    ack messages;
    open messages;
    replace send/inbox;
    create local-backbone.

## 6. CLI gate

A CLI command becomes useful when:

    terminal diagnostics need arbitrary provider event inspection;
    runner validation needs command-level coverage;
    docs need a user-visible diagnostic workflow;
    provider-originated trust-history append work needs a before/after report;
    registry/help generation work needs this as a real surface.

Until then, keep it internal.

## 7. Next

Next recommended work:

    provider-originated trust-history append plan.

Do not jump directly into provider identity import.
