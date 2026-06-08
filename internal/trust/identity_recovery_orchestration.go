package trust

import "strings"

type IdentityRecoveryOrchestrationInput struct {
	RecoveryInput        IdentityRecoveryInput
	DisableHistoryAppend bool
	AppendClean          bool
}

type IdentityRecoveryOrchestrationResult struct {
	Classification       IdentityRecoveryClassification
	HistoryEvent         *Event
	HistoryAppended      bool
	HistorySkippedReason string
}

// OrchestrateIdentityRecovery composes recovery classification with optional
// append-only recovery-history recording.
//
// It may read local state through ClassifyIdentityRecovery.
// It may append trust-events.jsonl through AppendIdentityRecoveryHistoryEvent.
//
// It does not delete files.
// It does not restore files.
// It does not reset files.
// It does not mutate trust.json.
// It does not mutate identity-candidates.json.
// It does not verify identity.
// It does not replace key material.
// It does not affect send/open/ack behavior.
// It does not expose CLI/registry behavior.
func OrchestrateIdentityRecovery(input IdentityRecoveryOrchestrationInput) (IdentityRecoveryOrchestrationResult, error) {
	classification, err := ClassifyIdentityRecovery(input.RecoveryInput)
	if err != nil {
		return IdentityRecoveryOrchestrationResult{}, err
	}

	result := IdentityRecoveryOrchestrationResult{
		Classification: classification,
	}

	if input.DisableHistoryAppend {
		result.HistorySkippedReason = "history append disabled"
		return result, nil
	}

	if !ShouldAppendIdentityRecoveryHistoryByDefault(classification) && !input.AppendClean {
		result.HistorySkippedReason = "clean recovery classification not appended by default"
		return result, nil
	}

	draft, err := BuildIdentityRecoveryHistoryDraft(classification)
	if err != nil {
		return IdentityRecoveryOrchestrationResult{}, err
	}

	event, err := AppendIdentityRecoveryHistoryEvent(input.RecoveryInput.Paths, draft)
	if err != nil {
		return IdentityRecoveryOrchestrationResult{}, err
	}

	result.HistoryEvent = &event
	result.HistoryAppended = true

	return result, nil
}

// ShouldAppendIdentityRecoveryHistoryByDefault describes the orchestration
// default: recovery_clean_local_state is buildable/testable but not appended
// automatically, to avoid trust-history noise from routine clean checks.
func ShouldAppendIdentityRecoveryHistoryByDefault(classification IdentityRecoveryClassification) bool {
	return strings.TrimSpace(classification.Classification) != "" &&
		classification.Classification != RecoveryClassificationCleanLocalState
}
