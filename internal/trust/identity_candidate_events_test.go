package trust

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestBuildIdentityCandidateObservedHistoryDraft(t *testing.T) {
	draft, err := BuildIdentityCandidateObservedHistoryDraft(IdentityCandidate{
		CandidateID:       "candidate-1",
		AccountID:         "account-1",
		ClaimedDeviceID:   "device-1",
		Fingerprint:       "CSFP-TEST",
		CandidateState:    CandidateStateObserved,
		Source:            "provider_keypackage",
		SourceDetail:      "test-detail",
		ProviderEventName: "provider.public_bundle.exported",
		ObservedAt:        "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("build observed draft: %v", err)
	}

	if draft.EventType != IdentityCandidateEventObserved {
		t.Fatalf("event type = %q", draft.EventType)
	}
	if draft.AccountID != "account-1" {
		t.Fatalf("account id = %q", draft.AccountID)
	}
	if draft.DeviceID != "device-1" {
		t.Fatalf("device id = %q", draft.DeviceID)
	}
	if draft.Fingerprint != "CSFP-TEST" {
		t.Fatalf("fingerprint = %q", draft.Fingerprint)
	}
	if draft.Source != "identity_candidate" {
		t.Fatalf("source = %q", draft.Source)
	}
	if draft.NowUTC != "2026-06-07T00:00:00Z" {
		t.Fatalf("time = %q", draft.NowUTC)
	}
	for _, want := range []string{
		"context=candidate_observed",
		"candidate_id=candidate-1",
		"candidate_state=observed",
		"source=provider_keypackage",
		"source_detail=test-detail",
		"provider_event=provider.public_bundle.exported",
	} {
		if !stringsContainsForCandidateEvents(draft.Note, want) {
			t.Fatalf("note %q missing %q", draft.Note, want)
		}
	}
}

func TestBuildIdentityCandidateReviewHistoryDraft(t *testing.T) {
	draft, err := BuildIdentityCandidateReviewHistoryDraft(IdentityCandidateReviewResult{
		Updated: true,
		Candidate: IdentityCandidate{
			CandidateID:     "candidate-1",
			ClaimedDeviceID: "device-1",
			Fingerprint:     "CSFP-TEST",
			CandidateState:  CandidateStateRejected,
			Source:          "provider_keypackage",
			ObservedAt:      "2026-06-07T00:00:00Z",
		},
	})
	if err != nil {
		t.Fatalf("build review draft: %v", err)
	}

	if draft.EventType != IdentityCandidateEventRejected {
		t.Fatalf("event type = %q", draft.EventType)
	}
	if draft.NewTrustState != CandidateStateRejected {
		t.Fatalf("new trust state = %q", draft.NewTrustState)
	}
	if draft.Source != "identity_candidate_review" {
		t.Fatalf("source = %q", draft.Source)
	}
	if !stringsContainsForCandidateEvents(draft.Note, "context=candidate_review_update") {
		t.Fatalf("note missing review context: %q", draft.Note)
	}
}

func TestBuildIdentityCandidateReviewHistoryDraftRejectsUnsupportedState(t *testing.T) {
	_, err := BuildIdentityCandidateReviewHistoryDraft(IdentityCandidateReviewResult{
		Updated: true,
		Candidate: IdentityCandidate{
			CandidateID:    "candidate-1",
			Fingerprint:    "CSFP-TEST",
			CandidateState: CandidateStateObserved,
			Source:         "provider_keypackage",
		},
	})
	if !errors.Is(err, ErrIdentityCandidateHistoryDraftInvalid) {
		t.Fatalf("err = %v, want ErrIdentityCandidateHistoryDraftInvalid", err)
	}
}

func TestBuildIdentityMismatchHistoryDraftReverifyRequired(t *testing.T) {
	candidate := IdentityCandidate{
		CandidateID:     "candidate-1",
		AccountID:       "account-1",
		ClaimedDeviceID: "device-1",
		Fingerprint:     "CSFP-NEW",
		CandidateState:  CandidateStateObserved,
		Source:          "provider_keypackage",
		ObservedAt:      "2026-06-07T00:00:00Z",
	}

	decision := IdentityMismatchDecision{
		Classification:   IdentityMismatchClassificationReverifyRequired,
		KnownTrustState:  StateVerified,
		RequiresReview:   true,
		RequiresReverify: true,
		BlocksSend:       true,
		Reason:           "candidate identity conflicts with known verified device material",
	}

	draft, err := BuildIdentityMismatchHistoryDraft(candidate, decision)
	if err != nil {
		t.Fatalf("build mismatch draft: %v", err)
	}

	if draft.EventType != IdentityCandidateEventReverifyRequired {
		t.Fatalf("event type = %q", draft.EventType)
	}
	if draft.PreviousTrustState != StateVerified {
		t.Fatalf("previous trust state = %q", draft.PreviousTrustState)
	}
	if draft.Source != "identity_mismatch_classifier" {
		t.Fatalf("source = %q", draft.Source)
	}
	for _, want := range []string{
		"classification=reverify_required",
		"known_trust_state=verified",
		"requires_review=true",
		"requires_reverify=true",
		"blocks_send=true",
	} {
		if !stringsContainsForCandidateEvents(draft.Note, want) {
			t.Fatalf("note %q missing %q", draft.Note, want)
		}
	}
}

func TestBuildIdentityMismatchHistoryDraftCoversClassifierCases(t *testing.T) {
	tests := []struct {
		classification string
		eventType      string
	}{
		{IdentityMismatchClassificationCandidateOnly, IdentityCandidateEventObserved},
		{IdentityMismatchClassificationContinuity, IdentityCandidateEventContinuityObserved},
		{IdentityMismatchClassificationReviewRequiredConflict, IdentityCandidateEventConflict},
		{IdentityMismatchClassificationReverifyRequired, IdentityCandidateEventReverifyRequired},
		{IdentityMismatchClassificationChangedCandidate, IdentityCandidateEventChangedCandidate},
		{IdentityMismatchClassificationBlockedRevoked, IdentityCandidateEventBlockedRevoked},
		{IdentityMismatchClassificationBlockedCompromised, IdentityCandidateEventBlockedCompromised},
	}

	for _, tt := range tests {
		t.Run(tt.classification, func(t *testing.T) {
			draft, err := BuildIdentityMismatchHistoryDraft(IdentityCandidate{
				CandidateID:    "candidate-1",
				Fingerprint:    "CSFP-TEST",
				CandidateState: CandidateStateObserved,
				Source:         "provider_keypackage",
			}, IdentityMismatchDecision{
				Classification:  tt.classification,
				KnownTrustState: StateUnknown,
			})
			if err != nil {
				t.Fatalf("build mismatch draft: %v", err)
			}
			if draft.EventType != tt.eventType {
				t.Fatalf("event type = %q, want %q", draft.EventType, tt.eventType)
			}
		})
	}
}

func TestBuildIdentityCandidateHistoryEventRejectsDeviceTrustMutationEvents(t *testing.T) {
	for _, eventType := range []string{
		"device_verified",
		"device_key_changed",
		"device_revoked",
	} {
		t.Run(eventType, func(t *testing.T) {
			_, err := BuildIdentityCandidateHistoryEvent(IdentityCandidateHistoryDraft{
				EventType: eventType,
			})
			if !errors.Is(err, ErrIdentityCandidateHistoryDraftInvalid) {
				t.Fatalf("err = %v, want ErrIdentityCandidateHistoryDraftInvalid", err)
			}
		})
	}
}

func TestAppendIdentityCandidateHistoryEventWritesOnlyEventLog(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}

	event, err := AppendIdentityCandidateHistoryEvent(paths, IdentityCandidateHistoryDraft{
		EventType:     IdentityCandidateEventRejected,
		DeviceID:      "device-1",
		Fingerprint:   "CSFP-TEST",
		Source:        "identity_candidate_review",
		Note:          "context=candidate_review_update candidate_id=candidate-1",
		NowUTC:        "2026-06-07T00:00:00Z",
		NewTrustState: CandidateStateRejected,
	})
	if err != nil {
		t.Fatalf("append candidate history event: %v", err)
	}

	if event.EventType != IdentityCandidateEventRejected {
		t.Fatalf("event type = %q", event.EventType)
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventType != IdentityCandidateEventRejected {
		t.Fatalf("loaded event type = %q", events[0].EventType)
	}
	if events[0].Source != "identity_candidate_review" {
		t.Fatalf("loaded source = %q", events[0].Source)
	}

	store, err := LoadStore(paths.TrustPath)
	if err != nil {
		t.Fatalf("load store: %v", err)
	}
	if len(store.TrustedDevices) != 0 {
		t.Fatalf("candidate history append must not mutate trust store, got %#v", store.TrustedDevices)
	}
}

func TestAppendIdentityCandidateHistoryEventDoesNotWriteCandidateStore(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	_, err := AppendIdentityCandidateHistoryEvent(paths, IdentityCandidateHistoryDraft{
		EventType:   IdentityCandidateEventConflict,
		Fingerprint: "CSFP-TEST",
		Source:      "identity_mismatch_classifier",
		Note:        "classification=review_required_conflict",
		NowUTC:      "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("append candidate history event: %v", err)
	}

	if _, err := LoadIdentityCandidateStore(candidatesPath); err != nil {
		t.Fatalf("missing candidate store should load as empty: %v", err)
	}
}

func stringsContainsForCandidateEvents(s string, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && containsSubstringForCandidateEvents(s, sub))
}

func containsSubstringForCandidateEvents(s string, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
