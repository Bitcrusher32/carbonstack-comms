package trust

import (
	"errors"
	"strings"
)

const (
	IdentityCandidateEventObserved           = "provider_identity_candidate_observed"
	IdentityCandidateEventReviewStarted      = "provider_identity_candidate_review_started"
	IdentityCandidateEventRejected           = "provider_identity_candidate_rejected"
	IdentityCandidateEventMarkedUnverified   = "provider_identity_candidate_marked_unverified"
	IdentityCandidateEventConflict           = "provider_identity_candidate_conflict"
	IdentityCandidateEventReverifyRequired   = "provider_identity_reverify_required"
	IdentityCandidateEventContinuityObserved = "provider_identity_continuity_observed"
	IdentityCandidateEventBlockedRevoked     = "provider_identity_promotion_blocked_revoked"
	IdentityCandidateEventBlockedCompromised = "provider_identity_promotion_blocked_compromised"
	IdentityCandidateEventChangedCandidate   = "provider_identity_changed_candidate"
)

type IdentityCandidateHistoryDraft struct {
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

var ErrIdentityCandidateHistoryDraftInvalid = errors.New("identity candidate history draft invalid")

// BuildIdentityCandidateObservedHistoryDraft converts a candidate observation
// into a trust-history append draft.
//
// This helper does not write trust-events.jsonl.
// It does not mutate trust.json.
// It does not write identity-candidates.json.
// It does not verify identity.
// It does not replace key material.
// It does not affect send/open/ack behavior.
func BuildIdentityCandidateObservedHistoryDraft(candidate IdentityCandidate) (IdentityCandidateHistoryDraft, error) {
	normalized, err := NormalizeIdentityCandidate(candidate)
	if err != nil {
		return IdentityCandidateHistoryDraft{}, err
	}

	return IdentityCandidateHistoryDraft{
		EventType:     IdentityCandidateEventObserved,
		AccountID:     normalized.AccountID,
		DeviceID:      normalized.ClaimedDeviceID,
		Fingerprint:   normalized.Fingerprint,
		Source:        "identity_candidate",
		Note:          identityCandidateHistoryNote(normalized, nil, "candidate_observed"),
		NowUTC:        normalized.ObservedAt,
		NewTrustState: CandidateStateObserved,
	}, nil
}

// BuildIdentityCandidateReviewHistoryDraft converts a candidate review/update
// result into an append-only trust-history draft.
//
// The caller is responsible for performing any candidate-store update first.
// This helper only creates the future trust-history event shape.
func BuildIdentityCandidateReviewHistoryDraft(result IdentityCandidateReviewResult) (IdentityCandidateHistoryDraft, error) {
	candidate, err := NormalizeIdentityCandidate(result.Candidate)
	if err != nil {
		return IdentityCandidateHistoryDraft{}, err
	}

	eventType, ok := identityCandidateReviewEventType(candidate.CandidateState)
	if !ok {
		return IdentityCandidateHistoryDraft{}, ErrIdentityCandidateHistoryDraftInvalid
	}

	return IdentityCandidateHistoryDraft{
		EventType:     eventType,
		AccountID:     candidate.AccountID,
		DeviceID:      candidate.ClaimedDeviceID,
		Fingerprint:   candidate.Fingerprint,
		Source:        "identity_candidate_review",
		Note:          identityCandidateHistoryNote(candidate, nil, "candidate_review_update"),
		NowUTC:        candidate.ObservedAt,
		NewTrustState: candidate.CandidateState,
	}, nil
}

// BuildIdentityMismatchHistoryDraft converts a pure mismatch classifier decision
// into an append-only trust-history draft.
//
// This helper records the decision. It does not apply the decision.
func BuildIdentityMismatchHistoryDraft(candidate IdentityCandidate, decision IdentityMismatchDecision) (IdentityCandidateHistoryDraft, error) {
	normalized, err := NormalizeIdentityCandidate(candidate)
	if err != nil {
		return IdentityCandidateHistoryDraft{}, err
	}

	eventType, ok := identityMismatchEventType(decision.Classification)
	if !ok {
		return IdentityCandidateHistoryDraft{}, ErrIdentityCandidateHistoryDraftInvalid
	}

	return IdentityCandidateHistoryDraft{
		EventType:          eventType,
		AccountID:          normalized.AccountID,
		DeviceID:           normalized.ClaimedDeviceID,
		PreviousTrustState: decision.KnownTrustState,
		NewTrustState:      normalized.CandidateState,
		Fingerprint:        normalized.Fingerprint,
		Source:             "identity_mismatch_classifier",
		Note:               identityCandidateHistoryNote(normalized, &decision, "identity_mismatch_classified"),
		NowUTC:             normalized.ObservedAt,
	}, nil
}

func AppendIdentityCandidateHistoryEvent(paths Paths, draft IdentityCandidateHistoryDraft) (Event, error) {
	providerDraft, err := identityCandidateHistoryProviderDraft(draft)
	if err != nil {
		return Event{}, err
	}

	return AppendProviderEvent(paths, providerDraft)
}

func BuildIdentityCandidateHistoryEvent(draft IdentityCandidateHistoryDraft) (Event, error) {
	providerDraft, err := identityCandidateHistoryProviderDraft(draft)
	if err != nil {
		return Event{}, err
	}

	return BuildProviderEvent(providerDraft)
}

func identityCandidateHistoryProviderDraft(draft IdentityCandidateHistoryDraft) (ProviderEventAppendDraft, error) {
	eventType := strings.TrimSpace(draft.EventType)
	if eventType == "" {
		return ProviderEventAppendDraft{}, ErrIdentityCandidateHistoryDraftInvalid
	}

	if eventType == "device_verified" || eventType == "device_key_changed" || eventType == "device_revoked" {
		return ProviderEventAppendDraft{}, ErrIdentityCandidateHistoryDraftInvalid
	}

	source := strings.TrimSpace(draft.Source)
	if source == "" {
		source = "identity_candidate_history"
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

func identityCandidateReviewEventType(state string) (string, bool) {
	switch strings.TrimSpace(state) {
	case CandidateStatePendingReview:
		return IdentityCandidateEventReviewStarted, true
	case CandidateStateRejected:
		return IdentityCandidateEventRejected, true
	case CandidateStateUnverified:
		return IdentityCandidateEventMarkedUnverified, true
	case CandidateStateConflictsKnownDevice:
		return IdentityCandidateEventConflict, true
	default:
		return "", false
	}
}

func identityMismatchEventType(classification string) (string, bool) {
	switch strings.TrimSpace(classification) {
	case IdentityMismatchClassificationCandidateOnly:
		return IdentityCandidateEventObserved, true
	case IdentityMismatchClassificationContinuity:
		return IdentityCandidateEventContinuityObserved, true
	case IdentityMismatchClassificationReviewRequiredConflict:
		return IdentityCandidateEventConflict, true
	case IdentityMismatchClassificationReverifyRequired:
		return IdentityCandidateEventReverifyRequired, true
	case IdentityMismatchClassificationChangedCandidate:
		return IdentityCandidateEventChangedCandidate, true
	case IdentityMismatchClassificationBlockedRevoked:
		return IdentityCandidateEventBlockedRevoked, true
	case IdentityMismatchClassificationBlockedCompromised:
		return IdentityCandidateEventBlockedCompromised, true
	default:
		return "", false
	}
}

func identityCandidateHistoryNote(candidate IdentityCandidate, decision *IdentityMismatchDecision, context string) string {
	parts := []string{
		"context=" + context,
		"candidate_id=" + candidate.CandidateID,
		"candidate_state=" + candidate.CandidateState,
		"source=" + candidate.Source,
	}

	if candidate.SourceDetail != "" {
		parts = append(parts, "source_detail="+candidate.SourceDetail)
	}
	if candidate.ProviderEventName != "" {
		parts = append(parts, "provider_event="+candidate.ProviderEventName)
	}
	if candidate.ClaimedDeviceID != "" {
		parts = append(parts, "claimed_device_id="+candidate.ClaimedDeviceID)
	}
	if candidate.Fingerprint != "" {
		parts = append(parts, "fingerprint="+candidate.Fingerprint)
	}
	if candidate.ConflictStatus != "" {
		parts = append(parts, "conflict_status="+candidate.ConflictStatus)
	}
	if candidate.ConversationLabel != "" {
		parts = append(parts, "conversation_label="+candidate.ConversationLabel)
	}
	if candidate.EnvelopeID != "" {
		parts = append(parts, "envelope_id="+candidate.EnvelopeID)
	}
	if candidate.KeyPackageRef != "" {
		parts = append(parts, "keypackage_ref="+candidate.KeyPackageRef)
	}
	if candidate.WelcomeRef != "" {
		parts = append(parts, "welcome_ref="+candidate.WelcomeRef)
	}

	if decision != nil {
		parts = append(parts,
			"classification="+decision.Classification,
			"known_trust_state="+decision.KnownTrustState,
		)

		if decision.MaterialMatches {
			parts = append(parts, "material_matches=true")
		}
		if decision.RequiresReview {
			parts = append(parts, "requires_review=true")
		}
		if decision.RequiresReverify {
			parts = append(parts, "requires_reverify=true")
		}
		if decision.BlocksSend {
			parts = append(parts, "blocks_send=true")
		}
		if decision.BlocksPromotion {
			parts = append(parts, "blocks_promotion=true")
		}
		if decision.Reason != "" {
			parts = append(parts, "reason="+strings.ReplaceAll(decision.Reason, " ", "_"))
		}
	}

	return strings.Join(parts, " ")
}
