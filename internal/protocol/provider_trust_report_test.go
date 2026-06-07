package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildProviderTrustReportForIdentityChanged(t *testing.T) {
	report := BuildProviderTrustReportForEvent(ProviderEventIdentityChanged)

	if report.Event != string(ProviderEventIdentityChanged) {
		t.Fatalf("event = %q, want %q", report.Event, ProviderEventIdentityChanged)
	}
	if report.Class != string(ProviderEventClassTrustSecurity) {
		t.Fatalf("class = %q, want %q", report.Class, ProviderEventClassTrustSecurity)
	}
	if report.Severity != string(ProviderEventSeveritySecurity) {
		t.Fatalf("severity = %q, want %q", report.Severity, ProviderEventSeveritySecurity)
	}
	if !report.TrustRelevant {
		t.Fatal("identity changed should be trust relevant")
	}
	if !report.BlocksSend {
		t.Fatal("identity changed should block send")
	}
	if !report.BlocksReceive {
		t.Fatal("identity changed should block receive")
	}
	if !report.RequiresReverify {
		t.Fatal("identity changed should require reverify")
	}
	if !report.UserVisible {
		t.Fatal("identity changed should be user visible")
	}
	if !report.HistoryRelevant {
		t.Fatal("identity changed should be history relevant")
	}
	if !containsAction(report.Actions, string(ProviderTrustActionMarkIdentityChanged)) {
		t.Fatalf("expected mark_identity_changed action, got %#v", report.Actions)
	}
}

func TestBuildProviderTrustReportForMessageTamper(t *testing.T) {
	report := BuildProviderTrustReportForEvent(ProviderEventTamperDetected)

	if !report.BlocksOpen {
		t.Fatal("tamper detected should block open")
	}
	if !containsAction(report.Actions, string(ProviderTrustActionQuarantineMessage)) {
		t.Fatalf("expected quarantine_message action, got %#v", report.Actions)
	}
	if !report.UserVisible {
		t.Fatal("tamper detected should be user visible")
	}
	if !report.HistoryRelevant {
		t.Fatal("tamper detected should be history relevant")
	}
}

func TestBuildProviderTrustReportForNormalMessageOpened(t *testing.T) {
	report := BuildProviderTrustReportForEvent(ProviderEventMessageOpened)

	if report.TrustRelevant {
		t.Fatal("normal message opened should not be trust relevant")
	}
	if report.BlocksSend || report.BlocksReceive || report.BlocksOpen {
		t.Fatalf("normal message opened should not block, got report %#v", report)
	}
	if !report.HistoryRelevant {
		t.Fatal("normal message opened should remain history relevant")
	}
	if !containsAction(report.Actions, string(ProviderTrustActionAppendHistory)) {
		t.Fatalf("expected append_history action, got %#v", report.Actions)
	}
}

func TestProviderTrustReportJSONIsStableShape(t *testing.T) {
	report := BuildProviderTrustReportForEvent(ProviderEventSignatureInvalid)

	body, err := ProviderTrustReportJSON(report)
	if err != nil {
		t.Fatalf("json report: %v", err)
	}

	var decoded ProviderTrustReport
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode json report: %v", err)
	}

	if decoded.Event != string(ProviderEventSignatureInvalid) {
		t.Fatalf("decoded event = %q, want %q", decoded.Event, ProviderEventSignatureInvalid)
	}
	if !decoded.BlocksOpen {
		t.Fatal("signature invalid should block open")
	}
	if !decoded.RequiresReverify {
		t.Fatal("signature invalid should require reverify")
	}
	if decoded.Summary == "" {
		t.Fatal("expected summary")
	}
}

func TestProviderTrustSummaryContainsImportantFlags(t *testing.T) {
	report := BuildProviderTrustReportForEvent(ProviderEventSecretUnavailable)
	summary := report.Summary

	for _, want := range []string{
		"event=provider.secret.material.unavailable",
		"class=terminal_fatal",
		"severity=fatal",
		"trust-relevant",
		"blocks-send",
		"user-visible",
		"history-relevant",
		"fatal_local_state",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary %q missing %q", summary, want)
		}
	}
}

func containsAction(actions []string, want string) bool {
	for _, action := range actions {
		if action == want {
			return true
		}
	}
	return false
}
