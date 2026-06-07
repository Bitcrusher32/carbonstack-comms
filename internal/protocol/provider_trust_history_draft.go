package protocol

import (
	"errors"
	"strings"
)

// ProviderTrustHistoryDraft is a non-persistent draft shape for a future
// provider-originated trust-history event.
//
// It is intentionally kept in internal/protocol for now because it translates
// provider policy/report output into a future history candidate. It does not
// write trust-events.jsonl and does not mutate trust.json.
type ProviderTrustHistoryDraft struct {
	EventType        string   `json:"event_type"`
	ProviderEvent    string   `json:"provider_event"`
	ProviderClass    string   `json:"provider_class"`
	ProviderSeverity string   `json:"provider_severity"`
	Actions          []string `json:"actions"`

	BlocksSend       bool `json:"blocks_send"`
	BlocksReceive    bool `json:"blocks_receive"`
	BlocksOpen       bool `json:"blocks_open"`
	RequiresReverify bool `json:"requires_reverify"`
	UserVisible      bool `json:"user_visible"`
	HistoryRelevant  bool `json:"history_relevant"`

	Source string `json:"source"`
	Note   string `json:"note"`
}

// ProviderTrustHistoryDraftResult describes whether a provider report is
// eligible to become a future trust-history event.
//
// Eligible=false is not an error. It usually means the provider event is normal
// lifecycle/setup/message noise that should not enter trust history.
type ProviderTrustHistoryDraftResult struct {
	Eligible bool                       `json:"eligible"`
	Reason   string                     `json:"reason,omitempty"`
	Draft    *ProviderTrustHistoryDraft `json:"draft,omitempty"`
}

// ErrProviderTrustHistoryDraftUnsupported is returned when a caller asks for a
// strict draft conversion for an unsupported provider event.
var ErrProviderTrustHistoryDraftUnsupported = errors.New("provider trust history draft unsupported for event")

// BuildProviderTrustHistoryDraft converts a ProviderTrustReport into a
// non-mutating draft trust-history event.
//
// This function does not append trust-events.jsonl.
// This function does not mutate trust.json.
// This function does not import provider identity.
// This function does not ack, open, or quarantine messages.
func BuildProviderTrustHistoryDraft(report ProviderTrustReport) ProviderTrustHistoryDraftResult {
	eventType, ok := providerTrustHistoryEventType(report.Event)
	if !ok {
		return ProviderTrustHistoryDraftResult{
			Eligible: false,
			Reason:   "provider event is not eligible for trust-history append",
		}
	}

	draft := &ProviderTrustHistoryDraft{
		EventType:        eventType,
		ProviderEvent:    report.Event,
		ProviderClass:    report.Class,
		ProviderSeverity: report.Severity,
		Actions:          append([]string(nil), report.Actions...),
		BlocksSend:       report.BlocksSend,
		BlocksReceive:    report.BlocksReceive,
		BlocksOpen:       report.BlocksOpen,
		RequiresReverify: report.RequiresReverify,
		UserVisible:      report.UserVisible,
		HistoryRelevant:  report.HistoryRelevant,
		Source:           "provider_trust_report",
		Note:             providerTrustHistoryNote(report),
	}

	return ProviderTrustHistoryDraftResult{
		Eligible: true,
		Draft:    draft,
	}
}

// MustBuildProviderTrustHistoryDraft is useful for tests and future narrow
// callsites that intentionally operate only on eligible events.
func MustBuildProviderTrustHistoryDraft(report ProviderTrustReport) (ProviderTrustHistoryDraft, error) {
	result := BuildProviderTrustHistoryDraft(report)
	if !result.Eligible || result.Draft == nil {
		return ProviderTrustHistoryDraft{}, ErrProviderTrustHistoryDraftUnsupported
	}
	return *result.Draft, nil
}

// BuildProviderTrustHistoryDraftForEvent runs the existing report helper and
// then returns a non-mutating draft history conversion.
func BuildProviderTrustHistoryDraftForEvent(name ProviderEventName) ProviderTrustHistoryDraftResult {
	return BuildProviderTrustHistoryDraft(BuildProviderTrustReportForEvent(name))
}

func providerTrustHistoryEventType(event string) (string, bool) {
	switch event {
	case string(ProviderEventIdentityChanged):
		return "provider_identity_changed", true
	case string(ProviderEventSignatureInvalid):
		return "provider_signature_invalid", true
	case string(ProviderEventTamperDetected):
		return "provider_tamper_detected", true
	case string(ProviderEventReplayDetected):
		return "provider_replay_detected", true
	case string(ProviderEventSecretUnavailable):
		return "provider_secret_unavailable", true
	default:
		return "", false
	}
}

func providerTrustHistoryNote(report ProviderTrustReport) string {
	parts := []string{
		"provider_event=" + report.Event,
		"class=" + report.Class,
		"severity=" + report.Severity,
	}

	if report.RequiresReverify {
		parts = append(parts, "requires_reverify=true")
	}
	if report.BlocksSend {
		parts = append(parts, "blocks_send=true")
	}
	if report.BlocksReceive {
		parts = append(parts, "blocks_receive=true")
	}
	if report.BlocksOpen {
		parts = append(parts, "blocks_open=true")
	}
	if report.UserVisible {
		parts = append(parts, "user_visible=true")
	}
	if len(report.Actions) > 0 {
		parts = append(parts, "actions="+strings.Join(report.Actions, ","))
	}

	return strings.Join(parts, " ")
}
