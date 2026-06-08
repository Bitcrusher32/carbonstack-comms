package trust

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOrchestrateIdentityRecoveryCleanLocalStateSkipsHistoryByDefault(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryOrchestrationTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")
	writeRecoveryOrchestrationBaseline(t, paths, candidatesPath)

	beforeEvents, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events before: %v", err)
	}

	result, err := OrchestrateIdentityRecovery(IdentityRecoveryOrchestrationInput{
		RecoveryInput: IdentityRecoveryInput{
			Paths:          paths,
			CandidatesPath: candidatesPath,
		},
	})
	if err != nil {
		t.Fatalf("orchestrate recovery: %v", err)
	}

	if result.Classification.Classification != RecoveryClassificationCleanLocalState {
		t.Fatalf("classification = %q", result.Classification.Classification)
	}
	if result.HistoryAppended || result.HistoryEvent != nil {
		t.Fatal("clean local state should not append history by default")
	}
	if result.HistorySkippedReason == "" {
		t.Fatal("expected skip reason")
	}

	afterEvents, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events after: %v", err)
	}
	if len(afterEvents) != len(beforeEvents) {
		t.Fatalf("clean check appended history; before=%d after=%d", len(beforeEvents), len(afterEvents))
	}
}

func TestOrchestrateIdentityRecoveryCanExplicitlyAppendCleanLocalState(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryOrchestrationTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")
	writeRecoveryOrchestrationBaseline(t, paths, candidatesPath)

	result, err := OrchestrateIdentityRecovery(IdentityRecoveryOrchestrationInput{
		RecoveryInput: IdentityRecoveryInput{
			Paths:          paths,
			CandidatesPath: candidatesPath,
		},
		AppendClean: true,
	})
	if err != nil {
		t.Fatalf("orchestrate recovery: %v", err)
	}

	if !result.HistoryAppended || result.HistoryEvent == nil {
		t.Fatal("expected explicit clean append")
	}
	if result.HistoryEvent.EventType != RecoveryClassificationCleanLocalState {
		t.Fatalf("event type = %q", result.HistoryEvent.EventType)
	}
}

func TestOrchestrateIdentityRecoveryMissingTrustStoreAppendsHistory(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryOrchestrationTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := AppendEvent(paths.EventsPath, Event{
		EventType: "test_baseline",
		Source:    "test",
	}); err != nil {
		t.Fatalf("append history baseline: %v", err)
	}
	if err := SaveIdentityCandidateStore(candidatesPath, IdentityCandidateStore{}); err != nil {
		t.Fatalf("save candidate baseline: %v", err)
	}

	result, err := OrchestrateIdentityRecovery(IdentityRecoveryOrchestrationInput{
		RecoveryInput: IdentityRecoveryInput{
			Paths:          paths,
			CandidatesPath: candidatesPath,
		},
	})
	if err != nil {
		t.Fatalf("orchestrate recovery: %v", err)
	}

	if result.Classification.Classification != RecoveryClassificationMissingTrustStore {
		t.Fatalf("classification = %q", result.Classification.Classification)
	}
	if !result.HistoryAppended || result.HistoryEvent == nil {
		t.Fatal("expected history append for missing trust store")
	}
	if result.HistoryEvent.EventType != RecoveryClassificationMissingTrustStore {
		t.Fatalf("event type = %q", result.HistoryEvent.EventType)
	}

	if _, err := os.Stat(paths.TrustPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("trust.json should not be created, err=%v", err)
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected baseline + recovery event, got %d", len(events))
	}
}

func TestOrchestrateIdentityRecoveryMissingTrustHistoryAppendsHistory(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryOrchestrationTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := SaveStore(paths.TrustPath, Store{}); err != nil {
		t.Fatalf("save trust baseline: %v", err)
	}
	if err := SaveIdentityCandidateStore(candidatesPath, IdentityCandidateStore{}); err != nil {
		t.Fatalf("save candidate baseline: %v", err)
	}

	result, err := OrchestrateIdentityRecovery(IdentityRecoveryOrchestrationInput{
		RecoveryInput: IdentityRecoveryInput{
			Paths:          paths,
			CandidatesPath: candidatesPath,
		},
	})
	if err != nil {
		t.Fatalf("orchestrate recovery: %v", err)
	}

	if result.Classification.Classification != RecoveryClassificationMissingTrustHistory {
		t.Fatalf("classification = %q", result.Classification.Classification)
	}
	if !result.HistoryAppended || result.HistoryEvent == nil {
		t.Fatal("expected history append for missing trust history")
	}
	if result.HistoryEvent.EventType != RecoveryClassificationMissingTrustHistory {
		t.Fatalf("event type = %q", result.HistoryEvent.EventType)
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 created recovery event, got %d", len(events))
	}
}

func TestOrchestrateIdentityRecoveryMissingCandidateStoreAppendsHistory(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryOrchestrationTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := SaveStore(paths.TrustPath, Store{}); err != nil {
		t.Fatalf("save trust baseline: %v", err)
	}
	if err := AppendEvent(paths.EventsPath, Event{
		EventType: "test_baseline",
		Source:    "test",
	}); err != nil {
		t.Fatalf("append history baseline: %v", err)
	}

	result, err := OrchestrateIdentityRecovery(IdentityRecoveryOrchestrationInput{
		RecoveryInput: IdentityRecoveryInput{
			Paths:          paths,
			CandidatesPath: candidatesPath,
		},
	})
	if err != nil {
		t.Fatalf("orchestrate recovery: %v", err)
	}

	if result.Classification.Classification != RecoveryClassificationMissingCandidateStore {
		t.Fatalf("classification = %q", result.Classification.Classification)
	}
	if !result.HistoryAppended || result.HistoryEvent == nil {
		t.Fatal("expected history append for missing candidate store")
	}

	if _, err := os.Stat(candidatesPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity-candidates.json should not be created, err=%v", err)
	}
}

func TestOrchestrateIdentityRecoveryCorruptTrustStoreAppendsWithoutMutatingTrustStore(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryOrchestrationTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := os.WriteFile(paths.TrustPath, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("write corrupt trust: %v", err)
	}
	if err := AppendEvent(paths.EventsPath, Event{
		EventType: "test_baseline",
		Source:    "test",
	}); err != nil {
		t.Fatalf("append history baseline: %v", err)
	}
	if err := SaveIdentityCandidateStore(candidatesPath, IdentityCandidateStore{}); err != nil {
		t.Fatalf("save candidate baseline: %v", err)
	}

	trustBefore := mustReadRecoveryOrchestrationFile(t, paths.TrustPath)

	result, err := OrchestrateIdentityRecovery(IdentityRecoveryOrchestrationInput{
		RecoveryInput: IdentityRecoveryInput{
			Paths:          paths,
			CandidatesPath: candidatesPath,
		},
	})
	if err != nil {
		t.Fatalf("orchestrate recovery: %v", err)
	}

	if result.Classification.Classification != RecoveryClassificationCorruptTrustStore {
		t.Fatalf("classification = %q", result.Classification.Classification)
	}
	if !result.HistoryAppended || result.HistoryEvent == nil {
		t.Fatal("expected history append for corrupt trust store")
	}
	if string(mustReadRecoveryOrchestrationFile(t, paths.TrustPath)) != string(trustBefore) {
		t.Fatal("trust store mutated")
	}
}

func TestOrchestrateIdentityRecoveryCorruptTrustHistoryAppendsWithoutRepairingHistory(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryOrchestrationTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := SaveStore(paths.TrustPath, Store{}); err != nil {
		t.Fatalf("save trust baseline: %v", err)
	}
	if err := os.WriteFile(paths.EventsPath, []byte("{not-json\n"), 0600); err != nil {
		t.Fatalf("write corrupt history: %v", err)
	}
	if err := SaveIdentityCandidateStore(candidatesPath, IdentityCandidateStore{}); err != nil {
		t.Fatalf("save candidate baseline: %v", err)
	}

	historyBefore := string(mustReadRecoveryOrchestrationFile(t, paths.EventsPath))

	result, err := OrchestrateIdentityRecovery(IdentityRecoveryOrchestrationInput{
		RecoveryInput: IdentityRecoveryInput{
			Paths:          paths,
			CandidatesPath: candidatesPath,
		},
	})
	if err != nil {
		t.Fatalf("orchestrate recovery: %v", err)
	}

	if result.Classification.Classification != RecoveryClassificationCorruptTrustHistory {
		t.Fatalf("classification = %q", result.Classification.Classification)
	}
	if !result.HistoryAppended || result.HistoryEvent == nil {
		t.Fatal("expected append attempt for corrupt trust history")
	}

	historyAfter := string(mustReadRecoveryOrchestrationFile(t, paths.EventsPath))
	if !strings.HasPrefix(historyAfter, historyBefore) {
		t.Fatal("corrupt history prefix should be preserved")
	}
	if !strings.Contains(historyAfter, RecoveryClassificationCorruptTrustHistory) {
		t.Fatalf("expected appended corrupt-history event in raw history, got %q", historyAfter)
	}
}

func TestOrchestrateIdentityRecoveryCorruptCandidateStoreAppendsWithoutMutatingCandidateStore(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryOrchestrationTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := SaveStore(paths.TrustPath, Store{}); err != nil {
		t.Fatalf("save trust baseline: %v", err)
	}
	if err := AppendEvent(paths.EventsPath, Event{
		EventType: "test_baseline",
		Source:    "test",
	}); err != nil {
		t.Fatalf("append history baseline: %v", err)
	}
	if err := os.WriteFile(candidatesPath, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("write corrupt candidate store: %v", err)
	}

	candidatesBefore := mustReadRecoveryOrchestrationFile(t, candidatesPath)

	result, err := OrchestrateIdentityRecovery(IdentityRecoveryOrchestrationInput{
		RecoveryInput: IdentityRecoveryInput{
			Paths:          paths,
			CandidatesPath: candidatesPath,
		},
	})
	if err != nil {
		t.Fatalf("orchestrate recovery: %v", err)
	}

	if result.Classification.Classification != RecoveryClassificationCorruptCandidateStore {
		t.Fatalf("classification = %q", result.Classification.Classification)
	}
	if !result.HistoryAppended || result.HistoryEvent == nil {
		t.Fatal("expected history append for corrupt candidate store")
	}
	if string(mustReadRecoveryOrchestrationFile(t, candidatesPath)) != string(candidatesBefore) {
		t.Fatal("candidate store mutated")
	}
}

func TestOrchestrateIdentityRecoveryDisableHistoryAppend(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryOrchestrationTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := AppendEvent(paths.EventsPath, Event{
		EventType: "test_baseline",
		Source:    "test",
	}); err != nil {
		t.Fatalf("append history baseline: %v", err)
	}
	if err := SaveIdentityCandidateStore(candidatesPath, IdentityCandidateStore{}); err != nil {
		t.Fatalf("save candidate baseline: %v", err)
	}

	result, err := OrchestrateIdentityRecovery(IdentityRecoveryOrchestrationInput{
		RecoveryInput: IdentityRecoveryInput{
			Paths:          paths,
			CandidatesPath: candidatesPath,
		},
		DisableHistoryAppend: true,
	})
	if err != nil {
		t.Fatalf("orchestrate recovery: %v", err)
	}

	if result.Classification.Classification != RecoveryClassificationMissingTrustStore {
		t.Fatalf("classification = %q", result.Classification.Classification)
	}
	if result.HistoryAppended || result.HistoryEvent != nil {
		t.Fatal("history append should be disabled")
	}
	if result.HistorySkippedReason != "history append disabled" {
		t.Fatalf("skip reason = %q", result.HistorySkippedReason)
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected only baseline event, got %d", len(events))
	}
}

func TestOrchestrateIdentityRecoveryDoesNotEmitDeviceMutationEvents(t *testing.T) {
	dir := t.TempDir()
	paths := recoveryOrchestrationTestPaths(dir)
	candidatesPath := filepath.Join(dir, "identity-candidates.json")

	if err := AppendEvent(paths.EventsPath, Event{
		EventType: "test_baseline",
		Source:    "test",
	}); err != nil {
		t.Fatalf("append history baseline: %v", err)
	}
	if err := SaveIdentityCandidateStore(candidatesPath, IdentityCandidateStore{}); err != nil {
		t.Fatalf("save candidate baseline: %v", err)
	}

	_, err := OrchestrateIdentityRecovery(IdentityRecoveryOrchestrationInput{
		RecoveryInput: IdentityRecoveryInput{
			Paths:          paths,
			CandidatesPath: candidatesPath,
		},
	})
	if err != nil {
		t.Fatalf("orchestrate recovery: %v", err)
	}

	events, err := LoadEvents(paths.EventsPath)
	if err != nil {
		t.Fatalf("load events: %v", err)
	}

	for _, event := range events {
		switch event.EventType {
		case "device_verified", "device_key_changed", "device_revoked":
			t.Fatalf("recovery orchestration must not emit device mutation event: %#v", event)
		}
	}
}

func TestShouldAppendIdentityRecoveryHistoryByDefault(t *testing.T) {
	if ShouldAppendIdentityRecoveryHistoryByDefault(IdentityRecoveryClassification{
		Classification: RecoveryClassificationCleanLocalState,
	}) {
		t.Fatal("clean local state should not append by default")
	}

	if !ShouldAppendIdentityRecoveryHistoryByDefault(IdentityRecoveryClassification{
		Classification: RecoveryClassificationMissingTrustStore,
	}) {
		t.Fatal("missing trust store should append by default")
	}

	if ShouldAppendIdentityRecoveryHistoryByDefault(IdentityRecoveryClassification{}) {
		t.Fatal("empty classification should not append by default")
	}
}

func recoveryOrchestrationTestPaths(dir string) Paths {
	return Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}
}

func writeRecoveryOrchestrationBaseline(t *testing.T, paths Paths, candidatesPath string) {
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

func mustReadRecoveryOrchestrationFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return body
}
