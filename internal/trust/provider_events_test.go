package trust

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestBuildProviderEventRequiresEventType(t *testing.T) {
	_, err := BuildProviderEvent(ProviderEventAppendDraft{})
	if !errors.Is(err, ErrProviderEventAppendDraftInvalid) {
		t.Fatalf("err = %v, want ErrProviderEventAppendDraftInvalid", err)
	}
}

func TestBuildProviderEventDefaultsSourceAndTime(t *testing.T) {
	event, err := BuildProviderEvent(ProviderEventAppendDraft{
		EventType: "provider_signature_invalid",
		Note:      "provider_event=provider.signature.invalid",
	})
	if err != nil {
		t.Fatalf("build provider event: %v", err)
	}

	if event.EventType != "provider_signature_invalid" {
		t.Fatalf("event type = %q", event.EventType)
	}
	if event.Source != "provider_event_append" {
		t.Fatalf("source = %q", event.Source)
	}
	if event.EventTime == "" {
		t.Fatal("expected event time")
	}
	if event.EventID == "" {
		t.Fatal("expected event id")
	}
}

func TestBuildProviderEventPreservesContext(t *testing.T) {
	event, err := BuildProviderEvent(ProviderEventAppendDraft{
		EventType:          "provider_identity_changed",
		AccountID:          "account-1",
		DeviceID:           "device-1",
		PreviousTrustState: StateVerified,
		NewTrustState:      StateChanged,
		Fingerprint:        "CSFP-TEST",
		Source:             "provider_trust_event_draft",
		Note:               "provider_event=provider.identity.changed requires_reverify=true",
		NowUTC:             "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("build provider event: %v", err)
	}

	if event.AccountID != "account-1" {
		t.Fatalf("account id = %q", event.AccountID)
	}
	if event.DeviceID != "device-1" {
		t.Fatalf("device id = %q", event.DeviceID)
	}
	if event.PreviousTrustState != StateVerified {
		t.Fatalf("previous trust state = %q", event.PreviousTrustState)
	}
	if event.NewTrustState != StateChanged {
		t.Fatalf("new trust state = %q", event.NewTrustState)
	}
	if event.Fingerprint != "CSFP-TEST" {
		t.Fatalf("fingerprint = %q", event.Fingerprint)
	}
	if event.Source != "provider_trust_event_draft" {
		t.Fatalf("source = %q", event.Source)
	}
	if event.EventTime != "2026-06-07T00:00:00Z" {
		t.Fatalf("event time = %q", event.EventTime)
	}
}

func TestAppendProviderEventWritesOnlyEventLog(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}

	event, err := AppendProviderEvent(paths, ProviderEventAppendDraft{
		EventType: "provider_tamper_detected",
		Source:    "test-provider",
		Note:      "provider_event=provider.message.tamper.detected blocks_open=true",
		NowUTC:    "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("append provider event: %v", err)
	}

	if event.EventType != "provider_tamper_detected" {
		t.Fatalf("event type = %q", event.EventType)
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventType != "provider_tamper_detected" {
		t.Fatalf("loaded event type = %q", events[0].EventType)
	}
	if events[0].Source != "test-provider" {
		t.Fatalf("loaded source = %q", events[0].Source)
	}

	store, err := LoadStore(paths.TrustPath)
	if err != nil {
		t.Fatalf("load store: %v", err)
	}
	if len(store.TrustedDevices) != 0 {
		t.Fatalf("provider append must not mutate trust store, got %#v", store.TrustedDevices)
	}
}

func TestAppendProviderEventAllowsMissingDeviceMapping(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}

	_, err := AppendProviderEvent(paths, ProviderEventAppendDraft{
		EventType: "provider_signature_invalid",
		Note:      "provider_event=provider.signature.invalid",
		NowUTC:    "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("append provider event without mapping: %v", err)
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].AccountID != "" || events[0].DeviceID != "" || events[0].Fingerprint != "" {
		t.Fatalf("missing mapping should stay empty, got %#v", events[0])
	}
}
