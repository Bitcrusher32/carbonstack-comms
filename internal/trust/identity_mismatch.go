package trust

import (
	"errors"
	"strings"
)

const (
	IdentityMismatchClassificationCandidateOnly          = "candidate_only"
	IdentityMismatchClassificationContinuity             = "continuity_observation"
	IdentityMismatchClassificationReviewRequiredConflict = "review_required_conflict"
	IdentityMismatchClassificationReverifyRequired       = "reverify_required"
	IdentityMismatchClassificationChangedCandidate       = "changed_candidate"
	IdentityMismatchClassificationBlockedRevoked         = "blocked_revoked"
	IdentityMismatchClassificationBlockedCompromised     = "blocked_compromised"
)

type IdentityMismatchInput struct {
	Candidate      IdentityCandidate
	KnownDevice    *DeviceRecord
	MappingPresent bool
}

type IdentityMismatchDecision struct {
	Classification  string `json:"classification"`
	KnownTrustState string `json:"known_trust_state"`
	CandidateState  string `json:"candidate_state"`

	HasKnownDevice  bool `json:"has_known_device"`
	MaterialMatches bool `json:"material_matches"`

	RequiresReview   bool `json:"requires_review"`
	RequiresReverify bool `json:"requires_reverify"`
	BlocksSend       bool `json:"blocks_send"`
	BlocksPromotion  bool `json:"blocks_promotion"`

	MayAppendHistory      bool `json:"may_append_history"`
	MayMutateTrustStore   bool `json:"may_mutate_trust_store"`
	MayVerifyIdentity     bool `json:"may_verify_identity"`
	MayReplaceKeyMaterial bool `json:"may_replace_key_material"`

	Reason string `json:"reason"`
}

var ErrIdentityMismatchInputInvalid = errors.New("identity mismatch input invalid")

// ClassifyIdentityMismatch is a pure decision helper.
//
// It does not mutate trust.json.
// It does not append trust-events.jsonl.
// It does not verify identity.
// It does not replace key material.
// It does not affect send/open/ack behavior.
func ClassifyIdentityMismatch(input IdentityMismatchInput) (IdentityMismatchDecision, error) {
	candidate, err := NormalizeIdentityCandidate(input.Candidate)
	if err != nil {
		return IdentityMismatchDecision{}, err
	}

	decision := IdentityMismatchDecision{
		CandidateState:        candidate.CandidateState,
		MayAppendHistory:      true,
		MayMutateTrustStore:   false,
		MayVerifyIdentity:     false,
		MayReplaceKeyMaterial: false,
	}

	if !input.MappingPresent || input.KnownDevice == nil {
		decision.Classification = IdentityMismatchClassificationCandidateOnly
		decision.KnownTrustState = StateUnknown
		decision.HasKnownDevice = false
		decision.BlocksSend = true
		decision.Reason = "candidate identity has no known local device mapping"
		return decision, nil
	}

	known := *input.KnownDevice
	decision.HasKnownDevice = true
	decision.KnownTrustState = known.TrustState
	decision.MaterialMatches = identityCandidateMatchesKnownDevice(candidate, known)

	switch known.TrustState {
	case StateVerified:
		if decision.MaterialMatches {
			decision.Classification = IdentityMismatchClassificationContinuity
			decision.BlocksSend = false
			decision.Reason = "candidate identity matches known verified device material"
			return decision, nil
		}

		decision.Classification = IdentityMismatchClassificationReverifyRequired
		decision.RequiresReview = true
		decision.RequiresReverify = true
		decision.BlocksSend = true
		decision.Reason = "candidate identity conflicts with known verified device material"
		return decision, nil

	case StateUnverified, StateUnknown, "":
		if decision.MaterialMatches {
			decision.Classification = IdentityMismatchClassificationContinuity
			decision.BlocksSend = true
			decision.Reason = "candidate identity matches known unverified or unknown device material"
			return decision, nil
		}

		decision.Classification = IdentityMismatchClassificationReviewRequiredConflict
		decision.RequiresReview = true
		decision.BlocksSend = true
		decision.Reason = "candidate identity conflicts with known unverified or unknown device material"
		return decision, nil

	case StateChanged:
		decision.Classification = IdentityMismatchClassificationChangedCandidate
		decision.RequiresReview = true
		decision.RequiresReverify = true
		decision.BlocksSend = true
		decision.Reason = "known device is already changed and requires reverification"
		return decision, nil

	case StateRevoked:
		decision.Classification = IdentityMismatchClassificationBlockedRevoked
		decision.RequiresReview = true
		decision.BlocksSend = true
		decision.BlocksPromotion = true
		decision.Reason = "known device is revoked; candidate promotion is blocked"
		return decision, nil

	case StateCompromised:
		decision.Classification = IdentityMismatchClassificationBlockedCompromised
		decision.RequiresReview = true
		decision.BlocksSend = true
		decision.BlocksPromotion = true
		decision.Reason = "known device is compromised-reserved; candidate promotion is blocked"
		return decision, nil

	default:
		if decision.MaterialMatches {
			decision.Classification = IdentityMismatchClassificationContinuity
			decision.BlocksSend = true
			decision.Reason = "candidate identity matches known device material with non-verified trust state"
			return decision, nil
		}

		decision.Classification = IdentityMismatchClassificationReviewRequiredConflict
		decision.RequiresReview = true
		decision.BlocksSend = true
		decision.Reason = "candidate identity conflicts with known device material with non-verified trust state"
		return decision, nil
	}
}

func identityCandidateMatchesKnownDevice(candidate IdentityCandidate, known DeviceRecord) bool {
	candidateFingerprint := strings.TrimSpace(candidate.Fingerprint)
	knownFingerprint := strings.TrimSpace(known.Fingerprint)

	if candidateFingerprint != "" && knownFingerprint != "" && candidateFingerprint == knownFingerprint {
		return true
	}

	candidateMaterial := strings.TrimSpace(candidate.PublicIdentityMaterial)
	knownMaterial := strings.TrimSpace(known.PublicIdentityKey)

	return candidateMaterial != "" && knownMaterial != "" && candidateMaterial == knownMaterial
}
