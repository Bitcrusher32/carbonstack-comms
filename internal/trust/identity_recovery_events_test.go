package trust

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestBuildIdentityRecoveryHistoryDraftMissingTrustStore(t *testing.T) {
	draft, err := BuildIdentityRecoveryHistoryDraft(IdentityRecoveryClassification{
		Classification:        RecoveryClassificationMissingTrustStore,
		Severity:              "warning",
		TrustStorePresent:     false,
		TrustHistoryPresent:   true,
		CandidateStorePresent: true,
		RequiresReview:        true,
		RequiresReenrollment:  true,
		BlocksSend:            true,
		Reason:                "trust store is missing; no verified trust continuity can be assumed",
	})
	if err != nil {
		t.Fatalf("build recovery history draft: %v", err)
	}

	if draft.EventType != RecoveryClassificationMissingTrustStore {
		t.Fatalf("event type = %q", draft.EventType)
	}
	if draft.Source != "identity_recovery_classifier" {
		t.Fatalf("source = %q", draft.Source)
	}
	if draft.NewTrustState != RecoveryClassificationMissingTrustStore {
		t.Fatalf("new trust state = %q", draft.NewTrustState)
	}

	for _, want := range []string{
		"classification=recovery_missing_trust_store",
		"severity=warning",
		"trust_store_present=false",
		"trust_history_present=true",
		"candidate_store_present=true",
		"requires_review=true",
		"requires_reenrollment=true",
		"blocks_send=true",
		"may_mutate_trust_store=false",
		"may_append_trust_history=false",
		"may_mutate_candidate_store=false",
		"may_verify_identity=false",
		"may_replace_key_material=false",
	} {
		if !stringsContainsForRecoveryEvents(draft.Note, want) {
			t.Fatalf("note %q missing %q", draft.Note, want)
		}
	}
}

func TestBuildIdentityRecoveryHistoryDraftCleanLocalStateIsBuildable(t *testing.T) {
	draft, err := BuildIdentityRecoveryHistoryDraft(IdentityRecoveryClassification{
		Classification:        RecoveryClassificationCleanLocalState,
		Severity:              "info",
		TrustStorePresent:     true,
		TrustHistoryPresent:   true,
		CandidateStorePresent: true,
		Reason:                "local trust, history, and candidate stores are present",
	})
	if err != nil {
		t.Fatalf("build clean recovery history draft: %v", err)
	}

	if draft.EventType != RecoveryClassificationCleanLocalState {
		t.Fatalf("event type = %q", draft.EventType)
	}
	if !stringsContainsForRecoveryEvents(draft.Note, "classification=recovery_clean_local_state") {
		t.Fatalf("note missing clean classification: %q", draft.Note)
	}
}

func TestBuildIdentityRecoveryHistoryDraftCoversRecoveryClassifications(t *testing.T) {
	tests := []string{
		RecoveryClassificationCleanLocalState,
		RecoveryClassificationMissingTrustStore,
		RecoveryClassificationMissingTrustHistory,
		RecoveryClassificationMissingCandidateStore,
		RecoveryClassificationCorruptTrustStore,
		RecoveryClassificationCorruptTrustHistory,
		RecoveryClassificationCorruptCandidateStore,
		RecoveryClassificationProviderIdentityMismatch,
		RecoveryClassificationCandidateConflict,
		RecoveryClassificationRequiresReverify,
		RecoveryClassificationRequiresReenrollment,
		RecoveryClassificationBlockedRevoked,
		RecoveryClassificationBlockedCompromised,
	}

	for _, classification := range tests {
		t.Run(classification, func(t *testing.T) {
			draft, err := BuildIdentityRecoveryHistoryDraft(IdentityRecoveryClassification{
				Classification: classification,
				Severity:       "warning",
				Reason:         "test reason",
			})
			if err != nil {
				t.Fatalf("build recovery draft: %v", err)
			}
			if draft.EventType != classification {
				t.Fatalf("event type = %q, want %q", draft.EventType, classification)
			}
		})
	}
}

func TestBuildIdentityRecoveryHistoryDraftRejectsUnknownClassification(t *testing.T) {
	_, err := BuildIdentityRecoveryHistoryDraft(IdentityRecoveryClassification{
		Classification: "recovery_unknown_new_case",
	})
	if !errors.Is(err, ErrIdentityRecoveryHistoryDraftInvalid) {
		t.Fatalf("err = %v, want ErrIdentityRecoveryHistoryDraftInvalid", err)
	}
}

func TestBuildIdentityRecoveryHistoryEventRejectsDeviceTrustMutationEvents(t *testing.T) {
	for _, eventType := range []string{
		"device_verified",
		"device_key_changed",
		"device_revoked",
	} {
		t.Run(eventType, func(t *testing.T) {
			_, err := BuildIdentityRecoveryHistoryEvent(IdentityRecoveryHistoryDraft{
				EventType: eventType,
			})
			if !errors.Is(err, ErrIdentityRecoveryHistoryDraftInvalid) {
				t.Fatalf("err = %v, want ErrIdentityRecoveryHistoryDraftInvalid", err)
			}
		})
	}
}

func TestBuildIdentityRecoveryHistoryEventPreservesContext(t *testing.T) {
	event, err := BuildIdentityRecoveryHistoryEvent(IdentityRecoveryHistoryDraft{
		EventType:          RecoveryClassificationRequiresReverify,
		AccountID:          "account-1",
		DeviceID:           "device-1",
		PreviousTrustState: StateVerified,
		NewTrustState:      RecoveryClassificationRequiresReverify,
		Fingerprint:        "CSFP-TEST",
		Source:             "identity_recovery_classifier",
		Note:               "classification=recovery_requires_reverify requires_reverify=true",
		NowUTC:             "2026-06-07T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("build recovery history event: %v", err)
	}

	if event.EventType != RecoveryClassificationRequiresReverify {
		t.Fatalf("event type = %q", event.EventType)
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
	if event.NewTrustState != RecoveryClassificationRequiresReverify {
		t.Fatalf("new trust state = %q", event.NewTrustState)
	}
	if event.Fingerprint != "CSFP-TEST" {
		t.Fatalf("fingerprint = %q", event.Fingerprint)
	}
	if event.Source != "identity_recovery_classifier" {
		t.Fatalf("source = %q", event.Source)
	}
	if event.EventTime != "2026-06-07T00:00:00Z" {
		t.Fatalf("event time = %q", event.EventTime)
	}
}

func TestAppendIdentityRecoveryHistoryEventWritesOnlyEventLog(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	event, err := AppendIdentityRecoveryHistoryEvent(paths, IdentityRecoveryHistoryDraft{
		EventType:     RecoveryClassificationCorruptTrustStore,
		Source:        "identity_recovery_classifier",
		Note:          "classification=recovery_corrupt_trust_store blocks_send=true",
		NowUTC:        "2026-06-07T00:00:00Z",
		NewTrustState: RecoveryClassificationCorruptTrustStore,
	})
	if err != nil {
		t.Fatalf("append recovery history event: %v", err)
	}

	if event.EventType != RecoveryClassificationCorruptTrustStore {
		t.Fatalf("event type = %q", event.EventType)
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventType != RecoveryClassificationCorruptTrustStore {
		t.Fatalf("loaded event type = %q", events[0].EventType)
	}

	store, err := LoadStore(paths.TrustPath)
	if err != nil {
		t.Fatalf("load trust store: %v", err)
	}
	if len(store.TrustedDevices) != 0 {
		t.Fatalf("recovery history append must not mutate trust store, got %#v", store.TrustedDevices)
	}

	candidateStore, err := LoadIdentityCandidateStore(candidatesPath)
	if err != nil {
		t.Fatalf("load candidate store: %v", err)
	}
	if len(candidateStore.IdentityCandidates) != 0 {
		t.Fatalf("recovery history append must not mutate candidate store, got %#v", candidateStore.IdentityCandidates)
	}
}

func TestAppendIdentityRecoveryHistoryEventCanAppendCleanButDoesNotDecideDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	paths := Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}

	draft, err := BuildIdentityRecoveryHistoryDraft(IdentityRecoveryClassification{
		Classification:        RecoveryClassificationCleanLocalState,
		Severity:              "info",
		TrustStorePresent:     true,
		TrustHistoryPresent:   true,
		CandidateStorePresent: true,
		Reason:                "explicit diagnostic clean check",
	})
	if err != nil {
		t.Fatalf("build clean draft: %v", err)
	}

	_, err = AppendIdentityRecoveryHistoryEvent(paths, draft)
	if err != nil {
		t.Fatalf("append clean recovery event explicitly: %v", err)
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected explicit clean append, got %d events", len(events))
	}
	if events[0].EventType != RecoveryClassificationCleanLocalState {
		t.Fatalf("event type = %q", events[0].EventType)
	}
}

func stringsContainsForRecoveryEvents(s string, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && containsSubstringForRecoveryEvents(s, sub))
}

func containsSubstringForRecoveryEvents(s string, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
