package protocol

import (
	"errors"
	"testing"
)

func TestBuildProviderTrustHistoryDraftForIdentityChanged(t *testing.T) {
	result := BuildProviderTrustHistoryDraftForEvent(ProviderEventIdentityChanged)

	if !result.Eligible {
		t.Fatalf("identity changed should be eligible: %s", result.Reason)
	}
	if result.Draft == nil {
		t.Fatal("expected draft")
	}

	draft := result.Draft
	if draft.EventType != "provider_identity_changed" {
		t.Fatalf("event type = %q", draft.EventType)
	}
	if draft.ProviderEvent != string(ProviderEventIdentityChanged) {
		t.Fatalf("provider event = %q", draft.ProviderEvent)
	}
	if !draft.BlocksSend {
		t.Fatal("identity changed draft should preserve blocks_send")
	}
	if !draft.BlocksReceive {
		t.Fatal("identity changed draft should preserve blocks_receive")
	}
	if !draft.RequiresReverify {
		t.Fatal("identity changed draft should preserve requires_reverify")
	}
	if !draft.UserVisible {
		t.Fatal("identity changed draft should preserve user_visible")
	}
	if !draft.HistoryRelevant {
		t.Fatal("identity changed draft should preserve history_relevant")
	}
	if draft.Source != "provider_trust_report" {
		t.Fatalf("source = %q", draft.Source)
	}
}

func TestBuildProviderTrustHistoryDraftAllowlist(t *testing.T) {
	tests := []struct {
		name      ProviderEventName
		eventType string
	}{
		{ProviderEventIdentityChanged, "provider_identity_changed"},
		{ProviderEventSignatureInvalid, "provider_signature_invalid"},
		{ProviderEventTamperDetected, "provider_tamper_detected"},
		{ProviderEventReplayDetected, "provider_replay_detected"},
		{ProviderEventSecretUnavailable, "provider_secret_unavailable"},
	}

	for _, tt := range tests {
		t.Run(string(tt.name), func(t *testing.T) {
			result := BuildProviderTrustHistoryDraftForEvent(tt.name)
			if !result.Eligible {
				t.Fatalf("expected eligible, reason=%q", result.Reason)
			}
			if result.Draft == nil {
				t.Fatal("expected draft")
			}
			if result.Draft.EventType != tt.eventType {
				t.Fatalf("event type = %q, want %q", result.Draft.EventType, tt.eventType)
			}
			if result.Draft.ProviderEvent != string(tt.name) {
				t.Fatalf("provider event = %q, want %q", result.Draft.ProviderEvent, tt.name)
			}
		})
	}
}

func TestBuildProviderTrustHistoryDraftRejectsNormalEvents(t *testing.T) {
	tests := []ProviderEventName{
		ProviderEventMessageOpened,
		ProviderEventMessageProtected,
		ProviderEventIdentityLoaded,
		ProviderEventPublicBundleExported,
		ProviderEventConversationLoaded,
	}

	for _, event := range tests {
		t.Run(string(event), func(t *testing.T) {
			result := BuildProviderTrustHistoryDraftForEvent(event)
			if result.Eligible {
				t.Fatalf("expected event %q to be ineligible", event)
			}
			if result.Draft != nil {
				t.Fatalf("expected nil draft for %q", event)
			}
			if result.Reason == "" {
				t.Fatalf("expected reason for %q", event)
			}
		})
	}
}

func TestMustBuildProviderTrustHistoryDraft(t *testing.T) {
	report := BuildProviderTrustReportForEvent(ProviderEventSignatureInvalid)

	draft, err := MustBuildProviderTrustHistoryDraft(report)
	if err != nil {
		t.Fatalf("strict draft conversion: %v", err)
	}
	if draft.EventType != "provider_signature_invalid" {
		t.Fatalf("event type = %q", draft.EventType)
	}
	if !draft.BlocksOpen {
		t.Fatal("signature invalid should preserve blocks_open")
	}
	if !draft.RequiresReverify {
		t.Fatal("signature invalid should preserve requires_reverify")
	}
}

func TestMustBuildProviderTrustHistoryDraftRejectsUnsupported(t *testing.T) {
	report := BuildProviderTrustReportForEvent(ProviderEventMessageOpened)

	_, err := MustBuildProviderTrustHistoryDraft(report)
	if !errors.Is(err, ErrProviderTrustHistoryDraftUnsupported) {
		t.Fatalf("err = %v, want ErrProviderTrustHistoryDraftUnsupported", err)
	}
}

func TestProviderTrustHistoryDraftCopiesActions(t *testing.T) {
	report := BuildProviderTrustReportForEvent(ProviderEventSecretUnavailable)

	result := BuildProviderTrustHistoryDraft(report)
	if !result.Eligible || result.Draft == nil {
		t.Fatalf("expected eligible draft, result=%#v", result)
	}

	if len(result.Draft.Actions) == 0 {
		t.Fatal("expected copied actions")
	}

	originalFirst := result.Draft.Actions[0]
	report.Actions[0] = "mutated_by_test"

	if result.Draft.Actions[0] != originalFirst {
		t.Fatal("draft actions should not alias report actions")
	}
}

func TestProviderTrustHistoryDraftNoteContainsImportantFlags(t *testing.T) {
	result := BuildProviderTrustHistoryDraftForEvent(ProviderEventTamperDetected)
	if !result.Eligible || result.Draft == nil {
		t.Fatalf("expected eligible draft, result=%#v", result)
	}

	for _, want := range []string{
		"provider_event=provider.message.tamper.detected",
		"class=trust_security",
		"severity=security",
		"blocks_open=true",
		"user_visible=true",
		"actions=",
		"block_open",
		"quarantine_message",
		"append_history",
		"warn_user",
	} {
		if !stringsContains(result.Draft.Note, want) {
			t.Fatalf("note %q missing %q", result.Draft.Note, want)
		}
	}
}

func stringsContains(s string, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && containsSubstring(s, sub))
}

func containsSubstring(s string, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
