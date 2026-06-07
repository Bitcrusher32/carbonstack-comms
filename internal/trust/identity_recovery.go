package trust

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

const (
	RecoveryClassificationCleanLocalState          = "recovery_clean_local_state"
	RecoveryClassificationMissingTrustStore        = "recovery_missing_trust_store"
	RecoveryClassificationMissingTrustHistory      = "recovery_missing_trust_history"
	RecoveryClassificationMissingCandidateStore    = "recovery_missing_candidate_store"
	RecoveryClassificationCorruptTrustStore        = "recovery_corrupt_trust_store"
	RecoveryClassificationCorruptTrustHistory      = "recovery_corrupt_trust_history"
	RecoveryClassificationCorruptCandidateStore    = "recovery_corrupt_candidate_store"
	RecoveryClassificationProviderIdentityMismatch = "recovery_provider_identity_mismatch"
	RecoveryClassificationCandidateConflict        = "recovery_candidate_conflict"
	RecoveryClassificationRequiresReverify         = "recovery_requires_reverify"
	RecoveryClassificationRequiresReenrollment     = "recovery_requires_reenrollment"
	RecoveryClassificationBlockedRevoked           = "recovery_blocked_revoked"
	RecoveryClassificationBlockedCompromised       = "recovery_blocked_compromised"
)

type IdentityRecoveryInput struct {
	Paths          Paths
	CandidatesPath string

	Candidate        *IdentityCandidate
	KnownDevice      *DeviceRecord
	MismatchDecision *IdentityMismatchDecision
}

type IdentityRecoveryClassification struct {
	Classification string `json:"classification"`
	Severity       string `json:"severity"`

	TrustStorePresent     bool `json:"trust_store_present"`
	TrustHistoryPresent   bool `json:"trust_history_present"`
	CandidateStorePresent bool `json:"candidate_store_present"`

	RequiresReview       bool `json:"requires_review"`
	RequiresReverify     bool `json:"requires_reverify"`
	RequiresReenrollment bool `json:"requires_reenrollment"`
	BlocksSend           bool `json:"blocks_send"`
	BlocksPromotion      bool `json:"blocks_promotion"`

	MayMutateTrustStore     bool `json:"may_mutate_trust_store"`
	MayAppendTrustHistory   bool `json:"may_append_trust_history"`
	MayMutateCandidateStore bool `json:"may_mutate_candidate_store"`
	MayVerifyIdentity       bool `json:"may_verify_identity"`
	MayReplaceKeyMaterial   bool `json:"may_replace_key_material"`

	Reason string `json:"reason"`
}

var ErrIdentityRecoveryInputInvalid = errors.New("identity recovery input invalid")

// ClassifyIdentityRecovery is a pure/non-mutating reset/recovery classifier.
//
// It may read local state files.
//
// It does not delete files.
// It does not restore files.
// It does not mutate trust.json.
// It does not append trust-events.jsonl.
// It does not mutate identity-candidates.json.
// It does not verify identity.
// It does not replace key material.
// It does not affect send/open/ack behavior.
func ClassifyIdentityRecovery(input IdentityRecoveryInput) (IdentityRecoveryClassification, error) {
	if strings.TrimSpace(input.Paths.TrustPath) == "" ||
		strings.TrimSpace(input.Paths.EventsPath) == "" ||
		strings.TrimSpace(input.CandidatesPath) == "" {
		return IdentityRecoveryClassification{}, ErrIdentityRecoveryInputInvalid
	}

	base := IdentityRecoveryClassification{
		Severity:                "info",
		MayMutateTrustStore:     false,
		MayAppendTrustHistory:   false,
		MayMutateCandidateStore: false,
		MayVerifyIdentity:       false,
		MayReplaceKeyMaterial:   false,
	}

	trustPresent, trustCorrupt, err := classifyTrustStoreFile(input.Paths.TrustPath)
	if err != nil {
		return IdentityRecoveryClassification{}, err
	}
	base.TrustStorePresent = trustPresent
	if trustCorrupt {
		base.Classification = RecoveryClassificationCorruptTrustStore
		base.Severity = "security"
		base.RequiresReview = true
		base.BlocksSend = true
		base.Reason = "trust store is present but cannot be decoded"
		return base, nil
	}
	if !trustPresent {
		base.Classification = RecoveryClassificationMissingTrustStore
		base.Severity = "warning"
		base.RequiresReview = true
		base.RequiresReenrollment = true
		base.BlocksSend = true
		base.Reason = "trust store is missing; no verified trust continuity can be assumed"
		return base, nil
	}

	historyPresent, historyCorrupt, err := classifyTrustHistoryFile(input.Paths.EventsPath)
	if err != nil {
		return IdentityRecoveryClassification{}, err
	}
	base.TrustHistoryPresent = historyPresent
	if historyCorrupt {
		base.Classification = RecoveryClassificationCorruptTrustHistory
		base.Severity = "warning"
		base.RequiresReview = true
		base.Reason = "trust history is present but contains invalid event data"
		return base, nil
	}
	if !historyPresent {
		base.Classification = RecoveryClassificationMissingTrustHistory
		base.Severity = "notice"
		base.RequiresReview = true
		base.Reason = "trust history is missing; history continuity cannot be assumed"
		return base, nil
	}

	candidatePresent, candidateCorrupt, err := classifyCandidateStoreFile(input.CandidatesPath)
	if err != nil {
		return IdentityRecoveryClassification{}, err
	}
	base.CandidateStorePresent = candidatePresent
	if candidateCorrupt {
		base.Classification = RecoveryClassificationCorruptCandidateStore
		base.Severity = "warning"
		base.RequiresReview = true
		base.Reason = "candidate store is present but cannot be decoded"
		return base, nil
	}
	if !candidatePresent {
		base.Classification = RecoveryClassificationMissingCandidateStore
		base.Severity = "notice"
		base.RequiresReview = true
		base.Reason = "candidate store is missing; candidate review continuity cannot be assumed"
		return base, nil
	}

	if input.KnownDevice != nil {
		switch input.KnownDevice.TrustState {
		case StateRevoked:
			base.Classification = RecoveryClassificationBlockedRevoked
			base.Severity = "security"
			base.RequiresReview = true
			base.BlocksSend = true
			base.BlocksPromotion = true
			base.Reason = "known device is revoked; recovery promotion is blocked"
			return base, nil

		case StateCompromised:
			base.Classification = RecoveryClassificationBlockedCompromised
			base.Severity = "security"
			base.RequiresReview = true
			base.BlocksSend = true
			base.BlocksPromotion = true
			base.Reason = "known device is compromised-reserved; recovery promotion is blocked"
			return base, nil

		case StateChanged:
			base.Classification = RecoveryClassificationRequiresReverify
			base.Severity = "security"
			base.RequiresReview = true
			base.RequiresReverify = true
			base.BlocksSend = true
			base.Reason = "known device is changed and requires reverification"
			return base, nil
		}
	}

	if input.MismatchDecision != nil {
		switch input.MismatchDecision.Classification {
		case IdentityMismatchClassificationReverifyRequired:
			base.Classification = RecoveryClassificationRequiresReverify
			base.Severity = "security"
			base.RequiresReview = true
			base.RequiresReverify = true
			base.BlocksSend = true
			base.Reason = "mismatch decision requires reverification"
			return base, nil

		case IdentityMismatchClassificationReviewRequiredConflict:
			base.Classification = RecoveryClassificationCandidateConflict
			base.Severity = "warning"
			base.RequiresReview = true
			base.BlocksSend = input.MismatchDecision.BlocksSend
			base.Reason = "mismatch decision requires candidate conflict review"
			return base, nil

		case IdentityMismatchClassificationChangedCandidate:
			base.Classification = RecoveryClassificationProviderIdentityMismatch
			base.Severity = "security"
			base.RequiresReview = true
			base.RequiresReverify = true
			base.BlocksSend = true
			base.Reason = "provider/candidate identity changed relative to known local state"
			return base, nil

		case IdentityMismatchClassificationBlockedRevoked:
			base.Classification = RecoveryClassificationBlockedRevoked
			base.Severity = "security"
			base.RequiresReview = true
			base.BlocksSend = true
			base.BlocksPromotion = true
			base.Reason = "mismatch decision blocks recovery because known device is revoked"
			return base, nil

		case IdentityMismatchClassificationBlockedCompromised:
			base.Classification = RecoveryClassificationBlockedCompromised
			base.Severity = "security"
			base.RequiresReview = true
			base.BlocksSend = true
			base.BlocksPromotion = true
			base.Reason = "mismatch decision blocks recovery because known device is compromised-reserved"
			return base, nil
		}
	}

	if input.Candidate != nil {
		normalized, err := NormalizeIdentityCandidate(*input.Candidate)
		if err != nil {
			return IdentityRecoveryClassification{}, err
		}

		switch normalized.CandidateState {
		case CandidateStateConflictsKnownDevice:
			base.Classification = RecoveryClassificationCandidateConflict
			base.Severity = "warning"
			base.RequiresReview = true
			base.BlocksSend = true
			base.Reason = "candidate state conflicts with known device"
			return base, nil

		case CandidateStateRejected:
			base.Classification = RecoveryClassificationRequiresReenrollment
			base.Severity = "warning"
			base.RequiresReview = true
			base.RequiresReenrollment = true
			base.BlocksSend = true
			base.Reason = "candidate was rejected and requires re-enrollment for future use"
			return base, nil

		case CandidateStateUnverified:
			base.Classification = RecoveryClassificationRequiresReverify
			base.Severity = "notice"
			base.RequiresReview = true
			base.RequiresReverify = true
			base.BlocksSend = true
			base.Reason = "candidate is unverified and requires verification before trust continuity"
			return base, nil
		}
	}

	base.Classification = RecoveryClassificationCleanLocalState
	base.Reason = "local trust, history, and candidate stores are present and no recovery conflict input was provided"
	return base, nil
}

func classifyTrustStoreFile(path string) (present bool, corrupt bool, err error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, false, nil
		}
		return false, false, err
	}

	var store Store
	if err := json.Unmarshal(body, &store); err != nil {
		return true, true, nil
	}

	return true, false, nil
}

func classifyTrustHistoryFile(path string) (present bool, corrupt bool, err error) {
	_, err = os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, false, nil
		}
		return false, false, err
	}

	if _, err := LoadEvents(path); err != nil {
		return true, true, nil
	}

	return true, false, nil
}

func classifyCandidateStoreFile(path string) (present bool, corrupt bool, err error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, false, nil
		}
		return false, false, err
	}

	var store IdentityCandidateStore
	if err := json.Unmarshal(body, &store); err != nil {
		return true, true, nil
	}

	return true, false, nil
}
