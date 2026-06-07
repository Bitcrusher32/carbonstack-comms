package trust

import (
	"errors"
	"strings"
)

// ProviderEventAppendDraft is the trust-package input shape for a future
// provider-originated trust-history event.
//
// This shape mirrors Event without importing protocol. Protocol remains
// policy/draft-only; trust owns append behavior.
//
// This helper layer does not mutate trust.json.
// It does not import provider identity.
// It does not verify or revoke devices.
// It does not ack, open, or quarantine messages.
type ProviderEventAppendDraft struct {
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

// ErrProviderEventAppendDraftInvalid is returned when the provider append draft
// does not contain enough information to create a trust-history event.
var ErrProviderEventAppendDraftInvalid = errors.New("provider event append draft invalid")

// BuildProviderEvent converts a provider append draft into a trust.Event without
// writing it to disk.
func BuildProviderEvent(draft ProviderEventAppendDraft) (Event, error) {
	eventType := strings.TrimSpace(draft.EventType)
	if eventType == "" {
		return Event{}, ErrProviderEventAppendDraftInvalid
	}

	source := strings.TrimSpace(draft.Source)
	if source == "" {
		source = "provider_event_append"
	}

	eventTime := strings.TrimSpace(draft.NowUTC)
	if eventTime == "" {
		eventTime = NowUTC()
	}

	return Event{
		EventID:            EventID(),
		EventType:          eventType,
		AccountID:          draft.AccountID,
		DeviceID:           draft.DeviceID,
		PreviousTrustState: draft.PreviousTrustState,
		NewTrustState:      draft.NewTrustState,
		Fingerprint:        draft.Fingerprint,
		EventTime:          eventTime,
		Source:             source,
		Note:               draft.Note,
	}, nil
}

// AppendProviderEvent appends a provider-originated trust-history event.
//
// This function only writes trust-events.jsonl through AppendEvent. It does not
// mutate trust.json or provider state.
func AppendProviderEvent(paths Paths, draft ProviderEventAppendDraft) (Event, error) {
	event, err := BuildProviderEvent(draft)
	if err != nil {
		return Event{}, err
	}

	if err := AppendEvent(paths.EventsPath, event); err != nil {
		return Event{}, err
	}

	return event, nil
}
