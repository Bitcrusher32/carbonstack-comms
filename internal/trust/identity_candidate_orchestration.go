package trust

import (
	"errors"
	"strings"
)

var ErrIdentityCandidateObservationInvalid = errors.New("identity candidate observation invalid")

type IdentityCandidateObservationResult struct {
	Candidate        IdentityCandidate
	CandidateAdded   bool
	KnownDeviceFound bool
	Decision         IdentityMismatchDecision
	HistoryEvent     *Event
	HistoryAppended  bool
}

// ObserveIdentityCandidate is a narrow internal orchestration helper for
// candidate identity observations.
//
// It may write identity-candidates.json through AddIdentityCandidate.
// It may append trust-events.jsonl through AppendIdentityCandidateHistoryEvent.
//
// It does not mutate trust.json.
// It does not verify identity.
// It does not replace key material.
// It does not emit device_verified, device_key_changed, or device_revoked.
// It does not affect send/open/ack behavior.
// It does not expose CLI/registry behavior.
func ObserveIdentityCandidate(paths Paths, candidatesPath string, candidate IdentityCandidate) (IdentityCandidateObservationResult, error) {
	if err := validateIdentityCandidateObservationInputs(paths, candidatesPath); err != nil {
		return IdentityCandidateObservationResult{}, err
	}

	storedCandidate, added, err := AddIdentityCandidate(candidatesPath, candidate)
	if err != nil {
		return IdentityCandidateObservationResult{}, err
	}

	var knownDevice *DeviceRecord
	knownDeviceFound := false

	if strings.TrimSpace(storedCandidate.ClaimedDeviceID) != "" {
		record, found, err := LookupDevice(paths, storedCandidate.ClaimedDeviceID)
		if err != nil {
			return IdentityCandidateObservationResult{}, err
		}
		if found {
			knownDevice = &record
			knownDeviceFound = true
		}
	}

	decision, err := ClassifyIdentityMismatch(IdentityMismatchInput{
		Candidate:      storedCandidate,
		KnownDevice:    knownDevice,
		MappingPresent: knownDeviceFound,
	})
	if err != nil {
		return IdentityCandidateObservationResult{}, err
	}

	result := IdentityCandidateObservationResult{
		Candidate:        storedCandidate,
		CandidateAdded:   added,
		KnownDeviceFound: knownDeviceFound,
		Decision:         decision,
	}

	if !added {
		return result, nil
	}

	var draft IdentityCandidateHistoryDraft
	if knownDeviceFound {
		draft, err = BuildIdentityMismatchHistoryDraft(storedCandidate, decision)
	} else {
		draft, err = BuildIdentityCandidateObservedHistoryDraft(storedCandidate)
	}
	if err != nil {
		return IdentityCandidateObservationResult{}, err
	}

	event, err := AppendIdentityCandidateHistoryEvent(paths, draft)
	if err != nil {
		return IdentityCandidateObservationResult{}, err
	}

	result.HistoryEvent = &event
	result.HistoryAppended = true

	return result, nil
}

func validateIdentityCandidateObservationInputs(paths Paths, candidatesPath string) error {
	if strings.TrimSpace(candidatesPath) == "" {
		return ErrIdentityCandidateObservationInvalid
	}
	if strings.TrimSpace(paths.TrustPath) == "" {
		return ErrIdentityCandidateObservationInvalid
	}
	if strings.TrimSpace(paths.EventsPath) == "" {
		return ErrIdentityCandidateObservationInvalid
	}

	return nil
}
