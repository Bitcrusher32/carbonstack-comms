package protocol

import (
	"encoding/json"
	"strings"
)

// ProviderTrustReport is a stable, non-mutating report shape for provider
// trust decisions. It is intended for dev diagnostics and future CLI display.
//
// The structured JSON fields are the diagnostic source of truth. Summary is
// interpretive helper text for humans and must not be treated as the policy
// source of truth.
//
// It does not mutate trust.json.
// It does not append trust-events.jsonl.
// It does not import provider identity.
// It does not decide final user-facing UX.
type ProviderTrustReport struct {
	Event            string   `json:"event"`
	Class            string   `json:"class"`
	Severity         string   `json:"severity"`
	TrustRelevant    bool     `json:"trust_relevant"`
	Actions          []string `json:"actions"`
	BlocksSend       bool     `json:"blocks_send"`
	BlocksReceive    bool     `json:"blocks_receive"`
	BlocksOpen       bool     `json:"blocks_open"`
	RequiresReverify bool     `json:"requires_reverify"`
	UserVisible      bool     `json:"user_visible"`
	HistoryRelevant  bool     `json:"history_relevant"`
	Summary          string   `json:"summary"`
}

// BuildProviderTrustReport converts a pure ProviderTrustDecision into a stable
// report shape for diagnostics. This function is intentionally side-effect free.
func BuildProviderTrustReport(decision ProviderTrustDecision) ProviderTrustReport {
	actions := make([]string, 0, len(decision.Actions))
	for _, action := range decision.Actions {
		actions = append(actions, string(action))
	}

	report := ProviderTrustReport{
		Event:            string(decision.Event),
		Class:            string(decision.Descriptor.Class),
		Severity:         string(decision.Descriptor.Severity),
		TrustRelevant:    decision.Descriptor.TrustRelevant,
		Actions:          actions,
		BlocksSend:       decision.BlocksSend,
		BlocksReceive:    decision.BlocksReceive,
		BlocksOpen:       decision.BlocksOpen,
		RequiresReverify: decision.RequiresReverify,
		UserVisible:      decision.UserVisible,
		HistoryRelevant:  decision.HistoryRelevant,
	}
	report.Summary = ProviderTrustSummary(report)

	return report
}

// BuildProviderTrustReportForEvent runs the existing pure provider-trust
// decision function and returns a non-mutating report.
func BuildProviderTrustReportForEvent(name ProviderEventName) ProviderTrustReport {
	return BuildProviderTrustReport(DecideProviderTrust(name))
}

// ProviderTrustReportJSON returns stable pretty JSON for a report.
func ProviderTrustReportJSON(report ProviderTrustReport) (string, error) {
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ProviderTrustSummary returns concise human-readable helper text.
//
// The summary is interpretive diagnostic documentation, not the source of truth.
// Callers that need stable behavior should inspect ProviderTrustReport fields or
// ProviderTrustReportJSON output.
func ProviderTrustSummary(report ProviderTrustReport) string {
	parts := []string{
		"event=" + report.Event,
		"class=" + report.Class,
		"severity=" + report.Severity,
	}

	if report.TrustRelevant {
		parts = append(parts, "trust-relevant")
	} else {
		parts = append(parts, "not-trust-relevant")
	}

	if report.BlocksSend {
		parts = append(parts, "blocks-send")
	}
	if report.BlocksReceive {
		parts = append(parts, "blocks-receive")
	}
	if report.BlocksOpen {
		parts = append(parts, "blocks-open")
	}
	if report.RequiresReverify {
		parts = append(parts, "requires-reverify")
	}
	if report.UserVisible {
		parts = append(parts, "user-visible")
	}
	if report.HistoryRelevant {
		parts = append(parts, "history-relevant")
	}
	if len(report.Actions) > 0 {
		parts = append(parts, "actions="+strings.Join(report.Actions, ","))
	}

	return strings.Join(parts, " ")
}
