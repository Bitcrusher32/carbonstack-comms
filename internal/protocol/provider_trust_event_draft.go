package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ProviderTrustEventDraft is a trust.Event-compatible draft shape.
//
// It intentionally mirrors the current trust.Event JSON fields without
// importing or writing the trust package. This keeps v0.5.12 non-mutating and
// avoids coupling provider policy directly to trust storage writes.
//
// It does not append trust-events.jsonl.
// It does not mutate trust.json.
// It does not import provider identity.
// It does not ack, open, or quarantine messages.
type ProviderTrustEventDraft struct {
	EventID            string `json:"event_id"`
	EventType          string `json:"event_type"`
	AccountID          string `json:"account_id"`
	DeviceID           string `json:"device_id"`
	PreviousTrustState string `json:"previous_trust_state"`
	NewTrustState      string `json:"new_trust_state"`
	Fingerprint        string `json:"fingerprint"`
	EventTime          string `json:"event_time"`
	Source             string `json:"source"`
	Note               string `json:"note"`
}

// ProviderTrustEventDraftContext carries optional local trust context needed to
// produce a trust.Event-compatible draft. Provider events often do not yet have
// a mature Comms device mapping; empty fields are allowed and must not invent
// identity.
type ProviderTrustEventDraftContext struct {
	AccountID          string
	DeviceID           string
	PreviousTrustState string
	NewTrustState      string
	Fingerprint        string
	Source             string
	NowUTC             string
}

// ErrProviderTrustEventDraftUnsupported is returned when a provider history
// draft is not eligible for a trust-event-compatible draft.
var ErrProviderTrustEventDraftUnsupported = errors.New("provider trust event draft unsupported")

// BuildProviderTrustEventDraft converts an eligible ProviderTrustHistoryDraft
// into a trust.Event-compatible draft. It is intentionally side-effect free.
func BuildProviderTrustEventDraft(history ProviderTrustHistoryDraft, ctx ProviderTrustEventDraftContext) (ProviderTrustEventDraft, error) {
	if strings.TrimSpace(history.EventType) == "" {
		return ProviderTrustEventDraft{}, ErrProviderTrustEventDraftUnsupported
	}
	if strings.TrimSpace(history.ProviderEvent) == "" {
		return ProviderTrustEventDraft{}, ErrProviderTrustEventDraftUnsupported
	}

	now := strings.TrimSpace(ctx.NowUTC)
	if now == "" {
		now = time.Now().UTC().Format(time.RFC3339)
	}

	source := strings.TrimSpace(ctx.Source)
	if source == "" {
		source = "provider_trust_history_draft"
	}

	eventID := providerTrustEventDraftID(history, ctx, now)

	return ProviderTrustEventDraft{
		EventID:            eventID,
		EventType:          history.EventType,
		AccountID:          ctx.AccountID,
		DeviceID:           ctx.DeviceID,
		PreviousTrustState: ctx.PreviousTrustState,
		NewTrustState:      ctx.NewTrustState,
		Fingerprint:        ctx.Fingerprint,
		EventTime:          now,
		Source:             source,
		Note:               providerTrustEventDraftNote(history),
	}, nil
}

// BuildProviderTrustEventDraftForReport converts a ProviderTrustReport through
// the v0.5.11 history-draft allowlist and into a trust.Event-compatible draft.
func BuildProviderTrustEventDraftForReport(report ProviderTrustReport, ctx ProviderTrustEventDraftContext) (ProviderTrustEventDraft, error) {
	result := BuildProviderTrustHistoryDraft(report)
	if !result.Eligible || result.Draft == nil {
		return ProviderTrustEventDraft{}, ErrProviderTrustEventDraftUnsupported
	}
	return BuildProviderTrustEventDraft(*result.Draft, ctx)
}

// BuildProviderTrustEventDraftForEvent runs the full non-mutating conversion
// path for a provider event name.
func BuildProviderTrustEventDraftForEvent(name ProviderEventName, ctx ProviderTrustEventDraftContext) (ProviderTrustEventDraft, error) {
	return BuildProviderTrustEventDraftForReport(BuildProviderTrustReportForEvent(name), ctx)
}

func providerTrustEventDraftID(history ProviderTrustHistoryDraft, ctx ProviderTrustEventDraftContext, now string) string {
	seed := fmt.Sprintf("%s|%s|%s|%s|%s", history.EventType, history.ProviderEvent, ctx.AccountID, ctx.DeviceID, now)
	sum := sha256.Sum256([]byte(seed))
	return "provider-event-" + hex.EncodeToString(sum[:8])
}

func providerTrustEventDraftNote(history ProviderTrustHistoryDraft) string {
	parts := []string{
		"provider_event=" + history.ProviderEvent,
		"provider_class=" + history.ProviderClass,
		"provider_severity=" + history.ProviderSeverity,
	}

	if history.RequiresReverify {
		parts = append(parts, "requires_reverify=true")
	}
	if history.BlocksSend {
		parts = append(parts, "blocks_send=true")
	}
	if history.BlocksReceive {
		parts = append(parts, "blocks_receive=true")
	}
	if history.BlocksOpen {
		parts = append(parts, "blocks_open=true")
	}
	if history.UserVisible {
		parts = append(parts, "user_visible=true")
	}
	if history.HistoryRelevant {
		parts = append(parts, "history_relevant=true")
	}
	if len(history.Actions) > 0 {
		parts = append(parts, "actions="+strings.Join(history.Actions, ","))
	}
	if strings.TrimSpace(history.Note) != "" {
		parts = append(parts, "draft_note={"+history.Note+"}")
	}

	return strings.Join(parts, " ")
}
