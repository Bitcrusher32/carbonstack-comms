package trust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestObserveIdentityCandidateAddsCandidateAndObservedHistory(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	result, err := ObserveIdentityCandidate(paths, candidatesPath, IdentityCandidate{
		AccountID:              "account-1",
		ClaimedDeviceID:        "device-1",
		PublicIdentityMaterial: "raw-material",
		Fingerprint:            "CSFP-TEST",
		Source:                 "provider_keypackage",
		SourceDetail:           "test-source",
		ObservedAt:             "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("observe candidate: %v", err)
	}

	if !result.CandidateAdded {
		t.Fatal("expected candidate to be added")
	}
	if result.KnownDeviceFound {
		t.Fatal("did not expect known device")
	}
	if result.Decision.Classification != IdentityMismatchClassificationCandidateOnly {
		t.Fatalf("classification = %q", result.Decision.Classification)
	}
	if !result.HistoryAppended || result.HistoryEvent == nil {
		t.Fatal("expected history event append")
	}
	if result.HistoryEvent.EventType != IdentityCandidateEventObserved {
		t.Fatalf("event type = %q", result.HistoryEvent.EventType)
	}

	store, err := LoadIdentityCandidateStore(candidatesPath)
	if err != nil {
		t.Fatalf("load candidate store: %v", err)
	}
	if len(store.IdentityCandidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(store.IdentityCandidates))
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	if _, err := os.Stat(paths.TrustPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("trust.json should not be created by observation, err=%v", err)
	}
}

func TestObserveIdentityCandidateDedupesWithoutAppendingDuplicateHistory(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	input := IdentityCandidate{
		ClaimedDeviceID: "device-1",
		Fingerprint:     "CSFP-TEST",
		Source:          "provider_keypackage",
		ObservedAt:      "2026-06-07T00:00:00Z",
	}

	first, err := ObserveIdentityCandidate(paths, candidatesPath, input)
	if err != nil {
		t.Fatalf("first observe: %v", err)
	}
	if !first.CandidateAdded || !first.HistoryAppended {
		t.Fatal("expected first observation to add candidate and append history")
	}

	second, err := ObserveIdentityCandidate(paths, candidatesPath, input)
	if err != nil {
		t.Fatalf("second observe: %v", err)
	}
	if second.CandidateAdded {
		t.Fatal("expected duplicate candidate not to be added")
	}
	if second.HistoryAppended || second.HistoryEvent != nil {
		t.Fatal("expected duplicate observation not to append history")
	}

	store, err := LoadIdentityCandidateStore(candidatesPath)
	if err != nil {
		t.Fatalf("load candidates: %v", err)
	}
	if len(store.IdentityCandidates) != 1 {
		t.Fatalf("expected 1 deduped candidate, got %d", len(store.IdentityCandidates))
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 non-duplicated history event, got %d", len(events))
	}
}

func TestObserveIdentityCandidateKnownVerifiedMatchAppendsContinuity(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := SaveStore(paths.TrustPath, Store{
		TrustedDevices: []DeviceRecord{
			{
				AccountID:         "account-1",
				DeviceID:          "device-1",
				PublicIdentityKey: "raw-material",
				Fingerprint:       "CSFP-MATCH",
				TrustState:        StateVerified,
			},
		},
	}); err != nil {
		t.Fatalf("save trust setup: %v", err)
	}

	result, err := ObserveIdentityCandidate(paths, candidatesPath, IdentityCandidate{
		AccountID:              "account-1",
		ClaimedDeviceID:        "device-1",
		PublicIdentityMaterial: "raw-material",
		Fingerprint:            "CSFP-MATCH",
		Source:                 "provider_keypackage",
		ObservedAt:             "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("observe candidate: %v", err)
	}

	if !result.KnownDeviceFound {
		t.Fatal("expected known device")
	}
	if result.Decision.Classification != IdentityMismatchClassificationContinuity {
		t.Fatalf("classification = %q", result.Decision.Classification)
	}
	if result.HistoryEvent == nil || result.HistoryEvent.EventType != IdentityCandidateEventContinuityObserved {
		t.Fatalf("history event = %#v", result.HistoryEvent)
	}

	store, err := LoadStore(paths.TrustPath)
	if err != nil {
		t.Fatalf("load trust store: %v", err)
	}
	if len(store.TrustedDevices) != 1 {
		t.Fatalf("expected 1 trusted device, got %d", len(store.TrustedDevices))
	}
	if store.TrustedDevices[0].TrustState != StateVerified {
		t.Fatalf("trust state mutated to %q", store.TrustedDevices[0].TrustState)
	}
	if store.TrustedDevices[0].Fingerprint != "CSFP-MATCH" {
		t.Fatalf("fingerprint mutated to %q", store.TrustedDevices[0].Fingerprint)
	}
}

func TestObserveIdentityCandidateKnownVerifiedMismatchAppendsReverify(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := SaveStore(paths.TrustPath, Store{
		TrustedDevices: []DeviceRecord{
			{
				AccountID:         "account-1",
				DeviceID:          "device-1",
				PublicIdentityKey: "old-material",
				Fingerprint:       "CSFP-OLD",
				TrustState:        StateVerified,
			},
		},
	}); err != nil {
		t.Fatalf("save trust setup: %v", err)
	}

	result, err := ObserveIdentityCandidate(paths, candidatesPath, IdentityCandidate{
		AccountID:              "account-1",
		ClaimedDeviceID:        "device-1",
		PublicIdentityMaterial: "new-material",
		Fingerprint:            "CSFP-NEW",
		Source:                 "provider_keypackage",
		ObservedAt:             "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("observe candidate: %v", err)
	}

	if result.Decision.Classification != IdentityMismatchClassificationReverifyRequired {
		t.Fatalf("classification = %q", result.Decision.Classification)
	}
	if !result.Decision.RequiresReverify {
		t.Fatal("expected reverify requirement")
	}
	if result.HistoryEvent == nil || result.HistoryEvent.EventType != IdentityCandidateEventReverifyRequired {
		t.Fatalf("history event = %#v", result.HistoryEvent)
	}

	store, err := LoadStore(paths.TrustPath)
	if err != nil {
		t.Fatalf("load trust store: %v", err)
	}
	if store.TrustedDevices[0].TrustState != StateVerified {
		t.Fatalf("trust state should remain verified, got %q", store.TrustedDevices[0].TrustState)
	}
	if store.TrustedDevices[0].Fingerprint != "CSFP-OLD" {
		t.Fatalf("known key material should not be replaced, got %q", store.TrustedDevices[0].Fingerprint)
	}
}

func TestObserveIdentityCandidateKnownRevokedAppendsBlockedRevoked(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := SaveStore(paths.TrustPath, Store{
		TrustedDevices: []DeviceRecord{
			{
				AccountID:   "account-1",
				DeviceID:    "device-1",
				Fingerprint: "CSFP-OLD",
				TrustState:  StateRevoked,
			},
		},
	}); err != nil {
		t.Fatalf("save trust setup: %v", err)
	}

	result, err := ObserveIdentityCandidate(paths, candidatesPath, IdentityCandidate{
		AccountID:       "account-1",
		ClaimedDeviceID: "device-1",
		Fingerprint:     "CSFP-OLD",
		Source:          "provider_keypackage",
		ObservedAt:      "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("observe candidate: %v", err)
	}

	if result.Decision.Classification != IdentityMismatchClassificationBlockedRevoked {
		t.Fatalf("classification = %q", result.Decision.Classification)
	}
	if !result.Decision.BlocksPromotion {
		t.Fatal("expected promotion block")
	}
	if result.HistoryEvent == nil || result.HistoryEvent.EventType != IdentityCandidateEventBlockedRevoked {
		t.Fatalf("history event = %#v", result.HistoryEvent)
	}

	store, err := LoadStore(paths.TrustPath)
	if err != nil {
		t.Fatalf("load trust store: %v", err)
	}
	if store.TrustedDevices[0].TrustState != StateRevoked {
		t.Fatalf("revoked trust state should remain revoked, got %q", store.TrustedDevices[0].TrustState)
	}
}

func TestObserveIdentityCandidateRejectsInvalidInputs(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}

	_, err := ObserveIdentityCandidate(paths, "", IdentityCandidate{
		Fingerprint: "CSFP-TEST",
		Source:      "provider_keypackage",
	})
	if !errors.Is(err, ErrIdentityCandidateObservationInvalid) {
		t.Fatalf("empty candidate path err = %v", err)
	}

	_, err = ObserveIdentityCandidate(Paths{
		TrustPath:  "",
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}, filepath.Join(dir, "identity-candidates.json"), IdentityCandidate{
		Fingerprint: "CSFP-TEST",
		Source:      "provider_keypackage",
	})
	if !errors.Is(err, ErrIdentityCandidateObservationInvalid) {
		t.Fatalf("empty trust path err = %v", err)
	}

	_, err = ObserveIdentityCandidate(paths, filepath.Join(dir, "identity-candidates.json"), IdentityCandidate{
		Fingerprint: "",
		Source:      "provider_keypackage",
	})
	if !errors.Is(err, ErrIdentityCandidateInvalid) {
		t.Fatalf("invalid candidate err = %v", err)
	}
}

func TestObserveIdentityCandidateDoesNotEmitDeviceMutationEvents(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	_, err := ObserveIdentityCandidate(paths, candidatesPath, IdentityCandidate{
		ClaimedDeviceID: "device-1",
		Fingerprint:     "CSFP-TEST",
		Source:          "provider_keypackage",
		ObservedAt:      "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("observe candidate: %v", err)
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}

	for _, event := range events {
		switch event.EventType {
		case "device_verified", "device_key_changed", "device_revoked":
			t.Fatalf("observation must not emit device mutation event: %#v", event)
		}
	}
}
