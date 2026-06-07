package trust

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyIdentityRecoveryCleanLocalState(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")
	writeRecoveryBaseline(t, paths, candidatesPath)

	result, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:          paths,
		CandidatesPath: candidatesPath,
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}

	if result.Classification != RecoveryClassificationCleanLocalState {
		t.Fatalf("classification = %q", result.Classification)
	}
	if !result.TrustStorePresent || !result.TrustHistoryPresent || !result.CandidateStorePresent {
		t.Fatalf("expected all stores present: %#v", result)
	}
	if result.MayMutateTrustStore || result.MayAppendTrustHistory || result.MayMutateCandidateStore {
		t.Fatalf("classifier must not authorize mutation: %#v", result)
	}
	if result.MayVerifyIdentity || result.MayReplaceKeyMaterial {
		t.Fatalf("classifier must not authorize verification/key replacement: %#v", result)
	}
}

func TestClassifyIdentityRecoveryMissingTrustStore(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := AppendEvent(paths.EventsPath, Event{
		EventType: "test_event",
		Source:    "test",
	}); err != nil {
		t.Fatalf("append setup event: %v", err)
	}
	if err := SaveIdentityCandidateStore(candidatesPath, IdentityCandidateStore{}); err != nil {
		t.Fatalf("save candidate setup: %v", err)
	}

	result, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:          paths,
		CandidatesPath: candidatesPath,
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}
	if result.Classification != RecoveryClassificationMissingTrustStore {
		t.Fatalf("classification = %q", result.Classification)
	}
	if !result.RequiresReenrollment {
		t.Fatal("missing trust store should require reenrollment consideration")
	}
	if !result.BlocksSend {
		t.Fatal("missing trust store should block send")
	}
}

func TestClassifyIdentityRecoveryMissingTrustHistory(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := SaveStore(paths.TrustPath, Store{}); err != nil {
		t.Fatalf("save trust setup: %v", err)
	}
	if err := SaveIdentityCandidateStore(candidatesPath, IdentityCandidateStore{}); err != nil {
		t.Fatalf("save candidate setup: %v", err)
	}

	result, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:          paths,
		CandidatesPath: candidatesPath,
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}
	if result.Classification != RecoveryClassificationMissingTrustHistory {
		t.Fatalf("classification = %q", result.Classification)
	}
	if !result.RequiresReview {
		t.Fatal("missing trust history should require review")
	}
}

func TestClassifyIdentityRecoveryMissingCandidateStore(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)

	if err := SaveStore(paths.TrustPath, Store{}); err != nil {
		t.Fatalf("save trust setup: %v", err)
	}
	if err := AppendEvent(paths.EventsPath, Event{
		EventType: "test_event",
		Source:    "test",
	}); err != nil {
		t.Fatalf("append setup event: %v", err)
	}

	result, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:          paths,
		CandidatesPath: filepath.Join(dir, "identity-candidates.json"),
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}
	if result.Classification != RecoveryClassificationMissingCandidateStore {
		t.Fatalf("classification = %q", result.Classification)
	}
	if !result.RequiresReview {
		t.Fatal("missing candidate store should require review")
	}
}

func TestClassifyIdentityRecoveryCorruptTrustStore(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := os.WriteFile(paths.TrustPath, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("write corrupt trust: %v", err)
	}
	if err := AppendEvent(paths.EventsPath, Event{
		EventType: "test_event",
		Source:    "test",
	}); err != nil {
		t.Fatalf("append setup event: %v", err)
	}
	if err := SaveIdentityCandidateStore(candidatesPath, IdentityCandidateStore{}); err != nil {
		t.Fatalf("save candidate setup: %v", err)
	}

	result, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:          paths,
		CandidatesPath: candidatesPath,
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}
	if result.Classification != RecoveryClassificationCorruptTrustStore {
		t.Fatalf("classification = %q", result.Classification)
	}
	if !result.BlocksSend {
		t.Fatal("corrupt trust store should block send")
	}
}

func TestClassifyIdentityRecoveryCorruptTrustHistory(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := SaveStore(paths.TrustPath, Store{}); err != nil {
		t.Fatalf("save trust setup: %v", err)
	}
	if err := os.WriteFile(paths.EventsPath, []byte("{not-json\n"), 0600); err != nil {
		t.Fatalf("write corrupt history: %v", err)
	}
	if err := SaveIdentityCandidateStore(candidatesPath, IdentityCandidateStore{}); err != nil {
		t.Fatalf("save candidate setup: %v", err)
	}

	result, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:          paths,
		CandidatesPath: candidatesPath,
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}
	if result.Classification != RecoveryClassificationCorruptTrustHistory {
		t.Fatalf("classification = %q", result.Classification)
	}
	if !result.RequiresReview {
		t.Fatal("corrupt trust history should require review")
	}
}

func TestClassifyIdentityRecoveryCorruptCandidateStore(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := SaveStore(paths.TrustPath, Store{}); err != nil {
		t.Fatalf("save trust setup: %v", err)
	}
	if err := AppendEvent(paths.EventsPath, Event{
		EventType: "test_event",
		Source:    "test",
	}); err != nil {
		t.Fatalf("append setup event: %v", err)
	}
	if err := os.WriteFile(candidatesPath, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("write corrupt candidate store: %v", err)
	}

	result, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:          paths,
		CandidatesPath: candidatesPath,
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}
	if result.Classification != RecoveryClassificationCorruptCandidateStore {
		t.Fatalf("classification = %q", result.Classification)
	}
}

func TestClassifyIdentityRecoveryCandidateConflict(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")
	writeRecoveryBaseline(t, paths, candidatesPath)

	candidate := IdentityCandidate{
		Fingerprint:     "CSFP-TEST",
		Source:          "provider_keypackage",
		CandidateState:  CandidateStateConflictsKnownDevice,
		ClaimedDeviceID: "device-1",
	}

	result, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:          paths,
		CandidatesPath: candidatesPath,
		Candidate:      &candidate,
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}
	if result.Classification != RecoveryClassificationCandidateConflict {
		t.Fatalf("classification = %q", result.Classification)
	}
	if !result.RequiresReview || !result.BlocksSend {
		t.Fatalf("expected review + send block: %#v", result)
	}
}

func TestClassifyIdentityRecoveryMismatchRequiresReverify(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")
	writeRecoveryBaseline(t, paths, candidatesPath)

	decision := IdentityMismatchDecision{
		Classification:   IdentityMismatchClassificationReverifyRequired,
		KnownTrustState:  StateVerified,
		BlocksSend:       true,
		RequiresReverify: true,
	}

	result, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:            paths,
		CandidatesPath:   candidatesPath,
		MismatchDecision: &decision,
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}
	if result.Classification != RecoveryClassificationRequiresReverify {
		t.Fatalf("classification = %q", result.Classification)
	}
	if !result.RequiresReverify || !result.BlocksSend {
		t.Fatalf("expected reverify + send block: %#v", result)
	}
}

func TestClassifyIdentityRecoveryKnownRevokedBlocks(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")
	writeRecoveryBaseline(t, paths, candidatesPath)

	known := DeviceRecord{
		DeviceID:   "device-1",
		TrustState: StateRevoked,
	}

	result, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:          paths,
		CandidatesPath: candidatesPath,
		KnownDevice:    &known,
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}
	if result.Classification != RecoveryClassificationBlockedRevoked {
		t.Fatalf("classification = %q", result.Classification)
	}
	if !result.BlocksPromotion || !result.BlocksSend {
		t.Fatalf("expected promotion + send block: %#v", result)
	}
}

func TestClassifyIdentityRecoveryKnownCompromisedBlocks(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")
	writeRecoveryBaseline(t, paths, candidatesPath)

	known := DeviceRecord{
		DeviceID:   "device-1",
		TrustState: StateCompromised,
	}

	result, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:          paths,
		CandidatesPath: candidatesPath,
		KnownDevice:    &known,
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}
	if result.Classification != RecoveryClassificationBlockedCompromised {
		t.Fatalf("classification = %q", result.Classification)
	}
	if !result.BlocksPromotion || !result.BlocksSend {
		t.Fatalf("expected promotion + send block: %#v", result)
	}
}

func TestClassifyIdentityRecoveryDoesNotMutateFiles(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")
	writeRecoveryBaseline(t, paths, candidatesPath)

	trustBefore := mustReadFile(t, paths.TrustPath)
	historyBefore := mustReadFile(t, paths.EventsPath)
	candidatesBefore := mustReadFile(t, candidatesPath)

	_, err := ClassifyIdentityRecovery(IdentityRecoveryInput{
		Paths:          paths,
		CandidatesPath: candidatesPath,
	})
	if err != nil {
		t.Fatalf("classify recovery: %v", err)
	}

	if string(mustReadFile(t, paths.TrustPath)) != string(trustBefore) {
		t.Fatal("trust store mutated")
	}
	if string(mustReadFile(t, paths.EventsPath)) != string(historyBefore) {
		t.Fatal("trust history mutated")
	}
	if string(mustReadFile(t, candidatesPath)) != string(candidatesBefore) {
		t.Fatal("candidate store mutated")
	}
}

func TestClassifyIdentityRecoveryRejectsInvalidInput(t *testing.T) {
	_, err := ClassifyIdentityRecovery(IdentityRecoveryInput{})
	if !errors.Is(err, ErrIdentityRecoveryInputInvalid) {
		t.Fatalf("err = %v, want ErrIdentityRecoveryInputInvalid", err)
	}
}

func recoveryTestPaths(dir string) Paths {
	return Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}
}

func writeRecoveryBaseline(t *testing.T, paths Paths, candidatesPath string) {
	t.Helper()

	if err := SaveStore(paths.TrustPath, Store{
		TrustedDevices: []DeviceRecord{
			{
				AccountID:   "account-1",
				DeviceID:    "device-1",
				Fingerprint: "CSFP-TEST",
				TrustState:  StateVerified,
			},
		},
	}); err != nil {
		t.Fatalf("save trust baseline: %v", err)
	}

	if err := AppendEvent(paths.EventsPath, Event{
		EventType: "test_baseline",
		Source:    "test",
	}); err != nil {
		t.Fatalf("append history baseline: %v", err)
	}

	if err := SaveIdentityCandidateStore(candidatesPath, IdentityCandidateStore{
		IdentityCandidates: []IdentityCandidate{
			{
				CandidateID:    "candidate-1",
				Fingerprint:    "CSFP-TEST",
				Source:         "provider_keypackage",
				CandidateState: CandidateStateObserved,
			},
		},
	}); err != nil {
		t.Fatalf("save candidate baseline: %v", err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return body
}
