package trust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUpdateIdentityCandidateStateByID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	candidate, _, err := AddIdentityCandidate(path, IdentityCandidate{
		ClaimedDeviceID:        "device-1",
		PublicIdentityMaterial: "raw-material",
		Fingerprint:            "CSFP-TEST",
		Source:                 "provider_keypackage",
		ObservedAt:             "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("add candidate: %v", err)
	}

	result, err := UpdateIdentityCandidateState(path, IdentityCandidateReviewUpdate{
		CandidateID: candidate.CandidateID,
		NewState:    CandidateStatePendingReview,
		Reviewer:    "test-reviewer",
		ReviewNote:  "manual review started",
		UpdatedAt:   "2026-06-08T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("update candidate: %v", err)
	}
	if !result.Updated {
		t.Fatal("expected update")
	}
	if result.Candidate.CandidateState != CandidateStatePendingReview {
		t.Fatalf("state = %q", result.Candidate.CandidateState)
	}
	if result.Candidate.PublicIdentityMaterial != "raw-material" {
		t.Fatalf("raw material changed: %q", result.Candidate.PublicIdentityMaterial)
	}
	if result.Candidate.Fingerprint != "CSFP-TEST" {
		t.Fatalf("fingerprint changed: %q", result.Candidate.Fingerprint)
	}
}

func TestUpdateIdentityCandidateStateByDedupeKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	_, _, err := AddIdentityCandidate(path, IdentityCandidate{
		ClaimedDeviceID: "device-1",
		Fingerprint:     "CSFP-TEST",
		Source:          "provider_keypackage",
	})
	if err != nil {
		t.Fatalf("add candidate: %v", err)
	}

	result, err := UpdateIdentityCandidateState(path, IdentityCandidateReviewUpdate{
		DedupeCandidate: IdentityCandidate{
			ClaimedDeviceID: "device-1",
			Fingerprint:     "CSFP-TEST",
			Source:          "provider_keypackage",
		},
		NewState: CandidateStatePendingReview,
	})
	if err != nil {
		t.Fatalf("update by dedupe key: %v", err)
	}
	if result.Candidate.CandidateState != CandidateStatePendingReview {
		t.Fatalf("state = %q", result.Candidate.CandidateState)
	}
}

func TestRejectIdentityCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	candidate, _, err := AddIdentityCandidate(path, IdentityCandidate{
		Fingerprint: "CSFP-TEST",
		Source:      "provider_keypackage",
	})
	if err != nil {
		t.Fatalf("add candidate: %v", err)
	}

	result, err := RejectIdentityCandidate(path, candidate.CandidateID, "not expected")
	if err != nil {
		t.Fatalf("reject candidate: %v", err)
	}
	if result.Candidate.CandidateState != CandidateStateRejected {
		t.Fatalf("state = %q", result.Candidate.CandidateState)
	}
}

func TestMarkIdentityCandidateUnverified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	candidate, _, err := AddIdentityCandidate(path, IdentityCandidate{
		Fingerprint: "CSFP-TEST",
		Source:      "provider_keypackage",
	})
	if err != nil {
		t.Fatalf("add candidate: %v", err)
	}

	result, err := MarkIdentityCandidateUnverified(path, candidate.CandidateID, "manual unverified mark")
	if err != nil {
		t.Fatalf("mark unverified: %v", err)
	}
	if result.Candidate.CandidateState != CandidateStateUnverified {
		t.Fatalf("state = %q", result.Candidate.CandidateState)
	}
}

func TestMarkIdentityCandidateConflictsKnownDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	candidate, _, err := AddIdentityCandidate(path, IdentityCandidate{
		Fingerprint: "CSFP-TEST",
		Source:      "provider_keypackage",
	})
	if err != nil {
		t.Fatalf("add candidate: %v", err)
	}

	result, err := MarkIdentityCandidateConflictsKnownDevice(path, candidate.CandidateID, "classifier conflict")
	if err != nil {
		t.Fatalf("mark conflict: %v", err)
	}
	if result.Candidate.CandidateState != CandidateStateConflictsKnownDevice {
		t.Fatalf("state = %q", result.Candidate.CandidateState)
	}
}

func TestRejectedCandidateCannotBecomeUnverified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	candidate, _, err := AddIdentityCandidate(path, IdentityCandidate{
		Fingerprint: "CSFP-TEST",
		Source:      "provider_keypackage",
	})
	if err != nil {
		t.Fatalf("add candidate: %v", err)
	}

	_, err = RejectIdentityCandidate(path, candidate.CandidateID, "reject")
	if err != nil {
		t.Fatalf("reject candidate: %v", err)
	}

	_, err = MarkIdentityCandidateUnverified(path, candidate.CandidateID, "should fail")
	if !errors.Is(err, ErrIdentityCandidateTransitionInvalid) {
		t.Fatalf("err = %v, want ErrIdentityCandidateTransitionInvalid", err)
	}
}

func TestIdentityCandidateReviewRejectsVerifiedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	candidate, _, err := AddIdentityCandidate(path, IdentityCandidate{
		Fingerprint: "CSFP-TEST",
		Source:      "provider_keypackage",
	})
	if err != nil {
		t.Fatalf("add candidate: %v", err)
	}

	_, err = UpdateIdentityCandidateState(path, IdentityCandidateReviewUpdate{
		CandidateID: candidate.CandidateID,
		NewState:    StateVerified,
	})
	if !errors.Is(err, ErrIdentityCandidateInvalid) {
		t.Fatalf("err = %v, want ErrIdentityCandidateInvalid", err)
	}
}

func TestUpdateIdentityCandidateStateMissingCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-candidates.json")

	_, err := UpdateIdentityCandidateState(path, IdentityCandidateReviewUpdate{
		CandidateID: "candidate-missing",
		NewState:    CandidateStatePendingReview,
	})
	if !errors.Is(err, ErrIdentityCandidateNotFound) {
		t.Fatalf("err = %v, want ErrIdentityCandidateNotFound", err)
	}
}

func TestUpdateIdentityCandidateStateDoesNotMutateTrustStoreOrEvents(t *testing.T) {
	dir := t.TempDir()
	candidatesPath := filepath.Join(dir, "identity-candidates.json")
	trustPath := filepath.Join(dir, "trust.json")
	eventsPath := filepath.Join(dir, "trust-events.jsonl")

	candidate, _, err := AddIdentityCandidate(candidatesPath, IdentityCandidate{
		Fingerprint: "CSFP-TEST",
		Source:      "provider_keypackage",
	})
	if err != nil {
		t.Fatalf("add candidate: %v", err)
	}

	_, err = UpdateIdentityCandidateState(candidatesPath, IdentityCandidateReviewUpdate{
		CandidateID: candidate.CandidateID,
		NewState:    CandidateStatePendingReview,
	})
	if err != nil {
		t.Fatalf("update candidate: %v", err)
	}

	if _, err := os.Stat(trustPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("trust.json should not exist after candidate update, err=%v", err)
	}
	if _, err := os.Stat(eventsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("trust-events.jsonl should not exist after candidate update, err=%v", err)
	}
}

func TestAllowedIdentityCandidateTransitions(t *testing.T) {
	allowed := []struct {
		from string
		to   string
	}{
		{CandidateStateObserved, CandidateStatePendingReview},
		{CandidateStateObserved, CandidateStateRejected},
		{CandidateStateObserved, CandidateStateUnverified},
		{CandidateStateObserved, CandidateStateConflictsKnownDevice},
		{CandidateStatePendingReview, CandidateStateRejected},
		{CandidateStatePendingReview, CandidateStateUnverified},
		{CandidateStatePendingReview, CandidateStateConflictsKnownDevice},
		{CandidateStateConflictsKnownDevice, CandidateStatePendingReview},
		{CandidateStateConflictsKnownDevice, CandidateStateRejected},
		{CandidateStateUnverified, CandidateStateRejected},
	}

	for _, tt := range allowed {
		t.Run(tt.from+"_to_"+tt.to, func(t *testing.T) {
			if !IsAllowedIdentityCandidateTransition(tt.from, tt.to) {
				t.Fatalf("expected transition %s -> %s to be allowed", tt.from, tt.to)
			}
		})
	}
}

func TestRejectedIdentityCandidateTransitionsAreSticky(t *testing.T) {
	for _, to := range []string{
		CandidateStateObserved,
		CandidateStatePendingReview,
		CandidateStateUnverified,
		CandidateStateConflictsKnownDevice,
		StateVerified,
	} {
		t.Run(to, func(t *testing.T) {
			if IsAllowedIdentityCandidateTransition(CandidateStateRejected, to) {
				t.Fatalf("expected rejected -> %s to be disallowed", to)
			}
		})
	}
}
