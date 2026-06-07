package trust

import (
	"errors"
	"strings"
)

var (
	ErrIdentityCandidateNotFound          = errors.New("identity candidate not found")
	ErrIdentityCandidateTransitionInvalid = errors.New("identity candidate transition invalid")
)

type IdentityCandidateReviewUpdate struct {
	CandidateID     string
	DedupeCandidate IdentityCandidate
	NewState        string
	Reviewer        string
	ReviewNote      string
	UpdatedAt       string
}

type IdentityCandidateReviewResult struct {
	Candidate IdentityCandidate
	Updated   bool
}

// UpdateIdentityCandidateState updates one candidate record inside
// identity-candidates.json.
//
// This helper only writes identity-candidates.json.
// It does not mutate trust.json.
// It does not append trust-events.jsonl.
// It does not verify identity.
// It does not replace key material.
// It does not affect send/open/ack behavior.
func UpdateIdentityCandidateState(path string, update IdentityCandidateReviewUpdate) (IdentityCandidateReviewResult, error) {
	normalizedUpdate, err := normalizeIdentityCandidateReviewUpdate(update)
	if err != nil {
		return IdentityCandidateReviewResult{}, err
	}

	store, err := LoadIdentityCandidateStore(path)
	if err != nil {
		return IdentityCandidateReviewResult{}, err
	}

	index := -1
	for i, candidate := range store.IdentityCandidates {
		if identityCandidateMatchesReviewTarget(candidate, normalizedUpdate) {
			index = i
			break
		}
	}

	if index < 0 {
		return IdentityCandidateReviewResult{}, ErrIdentityCandidateNotFound
	}

	current := store.IdentityCandidates[index]
	currentState := strings.TrimSpace(current.CandidateState)
	if currentState == "" {
		currentState = CandidateStateObserved
	}

	if !IsAllowedIdentityCandidateTransition(currentState, normalizedUpdate.NewState) {
		return IdentityCandidateReviewResult{}, ErrIdentityCandidateTransitionInvalid
	}

	current.CandidateState = normalizedUpdate.NewState
	if normalizedUpdate.UpdatedAt != "" {
		current.ObservedAt = current.ObservedAt
		if current.Note == "" {
			current.Note = "updated_at=" + normalizedUpdate.UpdatedAt
		} else if !strings.Contains(current.Note, "updated_at=") {
			current.Note = current.Note + " updated_at=" + normalizedUpdate.UpdatedAt
		}
	}
	if normalizedUpdate.Reviewer != "" {
		if current.Note == "" {
			current.Note = "reviewer=" + normalizedUpdate.Reviewer
		} else if !strings.Contains(current.Note, "reviewer=") {
			current.Note = current.Note + " reviewer=" + normalizedUpdate.Reviewer
		}
	}
	if normalizedUpdate.ReviewNote != "" {
		if current.Note == "" {
			current.Note = normalizedUpdate.ReviewNote
		} else if !strings.Contains(current.Note, normalizedUpdate.ReviewNote) {
			current.Note = current.Note + " " + normalizedUpdate.ReviewNote
		}
	}

	store.IdentityCandidates[index] = current
	if err := SaveIdentityCandidateStore(path, store); err != nil {
		return IdentityCandidateReviewResult{}, err
	}

	return IdentityCandidateReviewResult{
		Candidate: current,
		Updated:   true,
	}, nil
}

func MarkIdentityCandidatePendingReview(path string, candidateID string, note string) (IdentityCandidateReviewResult, error) {
	return UpdateIdentityCandidateState(path, IdentityCandidateReviewUpdate{
		CandidateID: candidateID,
		NewState:    CandidateStatePendingReview,
		ReviewNote:  note,
	})
}

func RejectIdentityCandidate(path string, candidateID string, note string) (IdentityCandidateReviewResult, error) {
	return UpdateIdentityCandidateState(path, IdentityCandidateReviewUpdate{
		CandidateID: candidateID,
		NewState:    CandidateStateRejected,
		ReviewNote:  note,
	})
}

func MarkIdentityCandidateUnverified(path string, candidateID string, note string) (IdentityCandidateReviewResult, error) {
	return UpdateIdentityCandidateState(path, IdentityCandidateReviewUpdate{
		CandidateID: candidateID,
		NewState:    CandidateStateUnverified,
		ReviewNote:  note,
	})
}

func MarkIdentityCandidateConflictsKnownDevice(path string, candidateID string, note string) (IdentityCandidateReviewResult, error) {
	return UpdateIdentityCandidateState(path, IdentityCandidateReviewUpdate{
		CandidateID: candidateID,
		NewState:    CandidateStateConflictsKnownDevice,
		ReviewNote:  note,
	})
}

func IsAllowedIdentityCandidateTransition(from string, to string) bool {
	from = strings.TrimSpace(from)
	to = strings.TrimSpace(to)

	if from == "" {
		from = CandidateStateObserved
	}

	if !IsAllowedIdentityCandidateState(from) || !IsAllowedIdentityCandidateState(to) {
		return false
	}

	if to == StateVerified {
		return false
	}

	switch from {
	case CandidateStateObserved:
		return to == CandidateStatePendingReview ||
			to == CandidateStateRejected ||
			to == CandidateStateUnverified ||
			to == CandidateStateConflictsKnownDevice

	case CandidateStatePendingReview:
		return to == CandidateStateRejected ||
			to == CandidateStateUnverified ||
			to == CandidateStateConflictsKnownDevice

	case CandidateStateConflictsKnownDevice:
		return to == CandidateStatePendingReview ||
			to == CandidateStateRejected

	case CandidateStateUnverified:
		return to == CandidateStateRejected

	case CandidateStateRejected:
		return false

	default:
		return false
	}
}

func normalizeIdentityCandidateReviewUpdate(update IdentityCandidateReviewUpdate) (IdentityCandidateReviewUpdate, error) {
	update.CandidateID = strings.TrimSpace(update.CandidateID)
	update.NewState = strings.TrimSpace(update.NewState)
	update.Reviewer = strings.TrimSpace(update.Reviewer)
	update.ReviewNote = strings.TrimSpace(update.ReviewNote)
	update.UpdatedAt = strings.TrimSpace(update.UpdatedAt)

	if update.NewState == "" {
		return IdentityCandidateReviewUpdate{}, ErrIdentityCandidateInvalid
	}
	if !IsAllowedIdentityCandidateState(update.NewState) {
		return IdentityCandidateReviewUpdate{}, ErrIdentityCandidateInvalid
	}
	if update.NewState == StateVerified {
		return IdentityCandidateReviewUpdate{}, ErrIdentityCandidateInvalid
	}

	if update.CandidateID == "" {
		normalizedCandidate, err := NormalizeIdentityCandidate(update.DedupeCandidate)
		if err != nil {
			return IdentityCandidateReviewUpdate{}, err
		}
		update.DedupeCandidate = normalizedCandidate
	}

	return update, nil
}

func identityCandidateMatchesReviewTarget(candidate IdentityCandidate, update IdentityCandidateReviewUpdate) bool {
	if update.CandidateID != "" {
		return strings.TrimSpace(candidate.CandidateID) == update.CandidateID
	}

	return IdentityCandidateDedupeKey(candidate) == IdentityCandidateDedupeKey(update.DedupeCandidate)
}
