package protocol

import (
	"errors"
	"strings"
	"testing"
)

func TestBuildProviderTrustEventDraftForIdentityChangedWithContext(t *testing.T) {
	ctx := ProviderTrustEventDraftContext{
		AccountID:          "account-1",
		DeviceID:           "device-1",
		PreviousTrustState: "verified",
		NewTrustState:      "changed",
		Fingerprint:        "CSFP-TEST",
		Source:             "test-provider",
		NowUTC:             "2026-06-07T00:00:00Z",
	}

	event, err := BuildProviderTrustEventDraftForEvent(ProviderEventIdentityChanged, ctx)
	if err != nil {
		t.Fatalf("build event draft: %v", err)
	}

	if event.EventType != "provider_identity_changed" {
		t.Fatalf("event type = %q", event.EventType)
	}
	if event.AccountID != "account-1" {
		t.Fatalf("account id = %q", event.AccountID)
	}
	if event.DeviceID != "device-1" {
		t.Fatalf("device id = %q", event.DeviceID)
	}
	if event.PreviousTrustState != "verified" {
		t.Fatalf("previous trust state = %q", event.PreviousTrustState)
	}
	if event.NewTrustState != "changed" {
		t.Fatalf("new trust state = %q", event.NewTrustState)
	}
	if event.Fingerprint != "CSFP-TEST" {
		t.Fatalf("fingerprint = %q", event.Fingerprint)
	}
	if event.Source != "test-provider" {
		t.Fatalf("source = %q", event.Source)
	}
	if event.EventTime != "2026-06-07T00:00:00Z" {
		t.Fatalf("event time = %q", event.EventTime)
	}
	if !strings.HasPrefix(event.EventID, "provider-event-") {
		t.Fatalf("event id = %q", event.EventID)
	}
}

func TestBuildProviderTrustEventDraftAllowsMissingMapping(t *testing.T) {
	event, err := BuildProviderTrustEventDraftForEvent(ProviderEventSignatureInvalid, ProviderTrustEventDraftContext{
		NowUTC: "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("build event draft: %v", err)
	}

	if event.EventType != "provider_signature_invalid" {
		t.Fatalf("event type = %q", event.EventType)
	}
	if event.AccountID != "" || event.DeviceID != "" || event.Fingerprint != "" {
		t.Fatalf("missing mapping should stay empty, got event=%#v", event)
	}
	if event.Source != "provider_trust_history_draft" {
		t.Fatalf("default source = %q", event.Source)
	}
}

func TestBuildProviderTrustEventDraftRejectsNormalProviderEvents(t *testing.T) {
	_, err := BuildProviderTrustEventDraftForEvent(ProviderEventMessageOpened, ProviderTrustEventDraftContext{
		NowUTC: "2026-06-07T00:00:00Z",
	})
	if !errors.Is(err, ErrProviderTrustEventDraftUnsupported) {
		t.Fatalf("err = %v, want ErrProviderTrustEventDraftUnsupported", err)
	}
}

func TestBuildProviderTrustEventDraftNotePreservesProviderFlags(t *testing.T) {
	event, err := BuildProviderTrustEventDraftForEvent(ProviderEventTamperDetected, ProviderTrustEventDraftContext{
		NowUTC: "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("build event draft: %v", err)
	}

	for _, want := range []string{
		"provider_event=provider.message.tamper.detected",
		"provider_class=trust_security",
		"provider_severity=security",
		"blocks_open=true",
		"user_visible=true",
		"history_relevant=true",
		"actions=",
		"block_open",
		"quarantine_message",
		"append_history",
		"warn_user",
	} {
		if !strings.Contains(event.Note, want) {
			t.Fatalf("note %q missing %q", event.Note, want)
		}
	}
}

func TestProviderTrustEventDraftIDIsDeterministicForFixedInputs(t *testing.T) {
	ctx := ProviderTrustEventDraftContext{
		AccountID: "account-1",
		DeviceID:  "device-1",
		NowUTC:    "2026-06-07T00:00:00Z",
	}

	first, err := BuildProviderTrustEventDraftForEvent(ProviderEventReplayDetected, ctx)
	if err != nil {
		t.Fatalf("first draft: %v", err)
	}
	second, err := BuildProviderTrustEventDraftForEvent(ProviderEventReplayDetected, ctx)
	if err != nil {
		t.Fatalf("second draft: %v", err)
	}

	if first.EventID != second.EventID {
		t.Fatalf("expected deterministic event id for fixed inputs, got %q and %q", first.EventID, second.EventID)
	}
}

func TestProviderTrustEventDraftDefaultTime(t *testing.T) {
	event, err := BuildProviderTrustEventDraftForEvent(ProviderEventSecretUnavailable, ProviderTrustEventDraftContext{})
	if err != nil {
		t.Fatalf("build event draft: %v", err)
	}

	if event.EventTime == "" {
		t.Fatal("expected default event time")
	}
	if event.EventID == "" {
		t.Fatal("expected event id")
	}
}
