package trust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadIdentityCandidateStoreMissingReturnsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	store, err := LoadIdentityCandidateStore(path)
	if err != nil {
		t.Fatalf("load missing candidate store: %v", err)
	}
	if len(store.IdentityCandidates) != 0 {
		t.Fatalf("expected empty candidate store, got %#v", store.IdentityCandidates)
	}
}

func TestSaveLoadIdentityCandidateStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	input := IdentityCandidateStore{
		IdentityCandidates: []IdentityCandidate{
			{
				CandidateID:            "candidate-1",
				AccountID:              "account-1",
				ClaimedDeviceID:        "device-1",
				PublicIdentityMaterial: "raw-public-identity-material",
				Fingerprint:            "CSFP-TEST",
				CandidateState:         CandidateStateObserved,
				Source:                 "provider_keypackage",
				ObservedAt:             "2026-06-07T00:00:00Z",
			},
		},
	}

	if err := SaveIdentityCandidateStore(path, input); err != nil {
		t.Fatalf("save candidate store: %v", err)
	}

	loaded, err := LoadIdentityCandidateStore(path)
	if err != nil {
		t.Fatalf("load candidate store: %v", err)
	}
	if len(loaded.IdentityCandidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(loaded.IdentityCandidates))
	}

	got := loaded.IdentityCandidates[0]
	if got.PublicIdentityMaterial != "raw-public-identity-material" {
		t.Fatalf("raw public identity material = %q", got.PublicIdentityMaterial)
	}
	if got.Fingerprint != "CSFP-TEST" {
		t.Fatalf("fingerprint = %q", got.Fingerprint)
	}
}

func TestAddIdentityCandidateWritesCandidateStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	candidate, added, err := AddIdentityCandidate(path, IdentityCandidate{
		ClaimedDeviceID:        "device-1",
		PublicIdentityMaterial: "raw-material",
		Fingerprint:            "CSFP-TEST",
		Source:                 "provider_keypackage",
		ObservedAt:             "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("add candidate: %v", err)
	}
	if !added {
		t.Fatal("expected candidate to be added")
	}
	if candidate.CandidateState != CandidateStateObserved {
		t.Fatalf("candidate state = %q", candidate.CandidateState)
	}
	if candidate.CandidateID == "" {
		t.Fatal("expected candidate id")
	}

	loaded, err := LoadIdentityCandidateStore(path)
	if err != nil {
		t.Fatalf("load candidates: %v", err)
	}
	if len(loaded.IdentityCandidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(loaded.IdentityCandidates))
	}
}

func TestAddIdentityCandidateDedupesClaimedDeviceFingerprintSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	first, added, err := AddIdentityCandidate(path, IdentityCandidate{
		ClaimedDeviceID:        "device-1",
		PublicIdentityMaterial: "raw-material-a",
		Fingerprint:            "CSFP-TEST",
		Source:                 "provider_keypackage",
		ObservedAt:             "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("add first candidate: %v", err)
	}
	if !added {
		t.Fatal("expected first candidate to be added")
	}

	second, added, err := AddIdentityCandidate(path, IdentityCandidate{
		ClaimedDeviceID:        "device-1",
		PublicIdentityMaterial: "raw-material-b",
		Fingerprint:            "CSFP-TEST",
		Source:                 "provider_keypackage",
		ObservedAt:             "2026-06-08T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("add duplicate candidate: %v", err)
	}
	if added {
		t.Fatal("expected duplicate candidate not to be added")
	}
	if second.CandidateID != first.CandidateID {
		t.Fatalf("duplicate returned candidate id = %q, want %q", second.CandidateID, first.CandidateID)
	}

	loaded, err := LoadIdentityCandidateStore(path)
	if err != nil {
		t.Fatalf("load candidates: %v", err)
	}
	if len(loaded.IdentityCandidates) != 1 {
		t.Fatalf("expected deduped store length 1, got %d", len(loaded.IdentityCandidates))
	}
}

func TestAddIdentityCandidateDedupesBlankClaimedDeviceByFingerprintSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	_, added, err := AddIdentityCandidate(path, IdentityCandidate{
		Fingerprint: "CSFP-TEST",
		Source:      "provider_welcome",
		ObservedAt:  "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("add first candidate: %v", err)
	}
	if !added {
		t.Fatal("expected first candidate to be added")
	}

	_, added, err = AddIdentityCandidate(path, IdentityCandidate{
		Fingerprint: "CSFP-TEST",
		Source:      "provider_welcome",
		ObservedAt:  "2026-06-08T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("add duplicate candidate: %v", err)
	}
	if added {
		t.Fatal("expected duplicate candidate not to be added")
	}

	loaded, err := LoadIdentityCandidateStore(path)
	if err != nil {
		t.Fatalf("load candidates: %v", err)
	}
	if len(loaded.IdentityCandidates) != 1 {
		t.Fatalf("expected deduped store length 1, got %d", len(loaded.IdentityCandidates))
	}
}

func TestAddIdentityCandidateRejectsVerifiedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	_, _, err := AddIdentityCandidate(path, IdentityCandidate{
		Fingerprint:     "CSFP-TEST",
		Source:          "provider_keypackage",
		CandidateState:  StateVerified,
		ClaimedDeviceID: "device-1",
	})
	if !errors.Is(err, ErrIdentityCandidateInvalid) {
		t.Fatalf("err = %v, want ErrIdentityCandidateInvalid", err)
	}
}

func TestAddIdentityCandidateRequiresFingerprintAndSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	_, _, err := AddIdentityCandidate(path, IdentityCandidate{
		Source: "provider_keypackage",
	})
	if !errors.Is(err, ErrIdentityCandidateInvalid) {
		t.Fatalf("missing fingerprint err = %v, want ErrIdentityCandidateInvalid", err)
	}

	_, _, err = AddIdentityCandidate(path, IdentityCandidate{
		Fingerprint: "CSFP-TEST",
	})
	if !errors.Is(err, ErrIdentityCandidateInvalid) {
		t.Fatalf("missing source err = %v, want ErrIdentityCandidateInvalid", err)
	}
}

func TestAddIdentityCandidateDoesNotMutateTrustStoreOrEvents(t *testing.T) {
	dir := t.TempDir()
	candidatesPath := filepath.Join(dir, "identity-candidates.json")
	trustPath := filepath.Join(dir, "trust.json")
	eventsPath := filepath.Join(dir, "trust-events.jsonl")

	_, added, err := AddIdentityCandidate(candidatesPath, IdentityCandidate{
		ClaimedDeviceID:        "device-1",
		PublicIdentityMaterial: "raw-material",
		Fingerprint:            "CSFP-TEST",
		Source:                 "provider_keypackage",
		ObservedAt:             "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("add candidate: %v", err)
	}
	if !added {
		t.Fatal("expected candidate to be added")
	}

	if _, err := os.Stat(trustPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("trust.json should not exist after candidate add, err=%v", err)
	}
	if _, err := os.Stat(eventsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("trust-events.jsonl should not exist after candidate add, err=%v", err)
	}
}

func TestIdentityCandidatesPathForStatePath(t *testing.T) {
	got := IdentityCandidatesPathForStatePath(filepath.Join("state-dir", "state.json"))
	want := filepath.Join("state-dir", "identity-candidates.json")

	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}
