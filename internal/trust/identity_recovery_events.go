package trust

import (
	"errors"
	"strings"
)

type IdentityRecoveryHistoryDraft struct {
	EventType          string
	AccountID          string
	DeviceID           string
	PreviousTrustState string
	NewTrustState      string
	Fingerprint        string
	Source             string
	Note               string
	NowUTC             string
}

var ErrIdentityRecoveryHistoryDraftInvalid = errors.New("identity recovery history draft invalid")

// BuildIdentityRecoveryHistoryDraft converts a recovery classification into an
// append-only trust-history draft.
//
// This helper does not write trust-events.jsonl.
// It does not mutate trust.json.
// It does not mutate identity-candidates.json.
// It does not delete, restore, or reset files.
// It does not verify identity.
// It does not replace key material.
// It does not affect send/open/ack behavior.
func BuildIdentityRecoveryHistoryDraft(classification IdentityRecoveryClassification) (IdentityRecoveryHistoryDraft, error) {
	eventType, ok := identityRecoveryEventType(classification.Classification)
	if !ok {
		return IdentityRecoveryHistoryDraft{}, ErrIdentityRecoveryHistoryDraftInvalid
	}

	return IdentityRecoveryHistoryDraft{
		EventType:     eventType,
		Source:        "identity_recovery_classifier",
		Note:          identityRecoveryHistoryNote(classification),
		NewTrustState: classification.Classification,
	}, nil
}

// BuildIdentityRecoveryHistoryEvent converts a recovery-history draft into a
// trust.Event-compatible shape without writing it.
func BuildIdentityRecoveryHistoryEvent(draft IdentityRecoveryHistoryDraft) (Event, error) {
	providerDraft, err := identityRecoveryHistoryProviderDraft(draft)
	if err != nil {
		return Event{}, err
	}

	return BuildProviderEvent(providerDraft)
}

// AppendIdentityRecoveryHistoryEvent appends a recovery-history event to
// trust-events.jsonl.
//
// This writes only trust-events.jsonl through AppendProviderEvent.
func AppendIdentityRecoveryHistoryEvent(paths Paths, draft IdentityRecoveryHistoryDraft) (Event, error) {
	providerDraft, err := identityRecoveryHistoryProviderDraft(draft)
	if err != nil {
		return Event{}, err
	}

	return AppendProviderEvent(paths, providerDraft)
}

func identityRecoveryHistoryProviderDraft(draft IdentityRecoveryHistoryDraft) (ProviderEventAppendDraft, error) {
	eventType := strings.TrimSpace(draft.EventType)
	if eventType == "" {
		return ProviderEventAppendDraft{}, ErrIdentityRecoveryHistoryDraftInvalid
	}

	if eventType == "device_verified" || eventType == "device_key_changed" || eventType == "device_revoked" {
		return ProviderEventAppendDraft{}, ErrIdentityRecoveryHistoryDraftInvalid
	}

	source := strings.TrimSpace(draft.Source)
	if source == "" {
		source = "identity_recovery_history"
	}

	return ProviderEventAppendDraft{
		EventType:          eventType,
		AccountID:          draft.AccountID,
		DeviceID:           draft.DeviceID,
		PreviousTrustState: draft.PreviousTrustState,
		NewTrustState:      draft.NewTrustState,
		Fingerprint:        draft.Fingerprint,
		Source:             source,
		Note:               draft.Note,
		NowUTC:             draft.NowUTC,
	}, nil
}

func identityRecoveryEventType(classification string) (string, bool) {
	switch strings.TrimSpace(classification) {
	case RecoveryClassificationCleanLocalState:
		return RecoveryClassificationCleanLocalState, true
	case RecoveryClassificationMissingTrustStore:
		return RecoveryClassificationMissingTrustStore, true
	case RecoveryClassificationMissingTrustHistory:
		return RecoveryClassificationMissingTrustHistory, true
	case RecoveryClassificationMissingCandidateStore:
		return RecoveryClassificationMissingCandidateStore, true
	case RecoveryClassificationCorruptTrustStore:
		return RecoveryClassificationCorruptTrustStore, true
	case RecoveryClassificationCorruptTrustHistory:
		return RecoveryClassificationCorruptTrustHistory, true
	case RecoveryClassificationCorruptCandidateStore:
		return RecoveryClassificationCorruptCandidateStore, true
	case RecoveryClassificationProviderIdentityMismatch:
		return RecoveryClassificationProviderIdentityMismatch, true
	case RecoveryClassificationCandidateConflict:
		return RecoveryClassificationCandidateConflict, true
	case RecoveryClassificationRequiresReverify:
		return RecoveryClassificationRequiresReverify, true
	case RecoveryClassificationRequiresReenrollment:
		return RecoveryClassificationRequiresReenrollment, true
	case RecoveryClassificationBlockedRevoked:
		return RecoveryClassificationBlockedRevoked, true
	case RecoveryClassificationBlockedCompromised:
		return RecoveryClassificationBlockedCompromised, true
	default:
		return "", false
	}
}

func identityRecoveryHistoryNote(classification IdentityRecoveryClassification) string {
	parts := []string{
		"classification=" + classification.Classification,
		"severity=" + classification.Severity,
	}

	if classification.TrustStorePresent {
		parts = append(parts, "trust_store_present=true")
	} else {
		parts = append(parts, "trust_store_present=false")
	}

	if classification.TrustHistoryPresent {
		parts = append(parts, "trust_history_present=true")
	} else {
		parts = append(parts, "trust_history_present=false")
	}

	if classification.CandidateStorePresent {
		parts = append(parts, "candidate_store_present=true")
	} else {
		parts = append(parts, "candidate_store_present=false")
	}

	if classification.RequiresReview {
		parts = append(parts, "requires_review=true")
	}
	if classification.RequiresReverify {
		parts = append(parts, "requires_reverify=true")
	}
	if classification.RequiresReenrollment {
		parts = append(parts, "requires_reenrollment=true")
	}
	if classification.BlocksSend {
		parts = append(parts, "blocks_send=true")
	}
	if classification.BlocksPromotion {
		parts = append(parts, "blocks_promotion=true")
	}

	parts = append(parts,
		"may_mutate_trust_store=false",
		"may_append_trust_history=false",
		"may_mutate_candidate_store=false",
		"may_verify_identity=false",
		"may_replace_key_material=false",
	)

	if classification.Reason != "" {
		parts = append(parts, "reason="+strings.ReplaceAll(classification.Reason, " ", "_"))
	}

	return strings.Join(parts, " ")
}
