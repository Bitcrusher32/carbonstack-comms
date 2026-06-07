package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	CandidateStateObserved             = "observed"
	CandidateStatePendingReview        = "pending_review"
	CandidateStateUnverified           = "unverified"
	CandidateStateConflictsKnownDevice = "conflicts_known_device"
	CandidateStateRejected             = "rejected"
)

// IdentityCandidate is local trust-adjacent candidate identity state.
//
// Candidate identity material is not verified trust.
//
// This dev/pre-alpha store may contain raw candidate public identity material
// for comparison. Treat it as future-vault-bound local state.
type IdentityCandidate struct {
	CandidateID            string `json:"candidate_id"`
	AccountID              string `json:"account_id"`
	ClaimedDeviceID        string `json:"claimed_device_id"`
	SidecarDeviceLabel     string `json:"sidecar_device_label"`
	ProviderIdentityLabel  string `json:"provider_identity_label"`
	PublicIdentityMaterial string `json:"public_identity_material"`
	Fingerprint            string `json:"fingerprint"`
	CandidateState         string `json:"candidate_state"`
	ConflictStatus         string `json:"conflict_status"`
	ObservedAt             string `json:"observed_at"`
	Source                 string `json:"source"`
	SourceDetail           string `json:"source_detail"`
	ProviderEventName      string `json:"provider_event_name"`
	ConversationLabel      string `json:"conversation_label"`
	EnvelopeID             string `json:"envelope_id"`
	KeyPackageRef          string `json:"keypackage_ref"`
	WelcomeRef             string `json:"welcome_ref"`
	Note                   string `json:"note"`
}

type IdentityCandidateStore struct {
	IdentityCandidates []IdentityCandidate `json:"identity_candidates"`
}

var ErrIdentityCandidateInvalid = errors.New("identity candidate invalid")

func IdentityCandidatesPathForStatePath(statePath string) string {
	dir := filepath.Dir(statePath)
	if dir == "" || dir == "." {
		dir = ".carbonstack-comms"
	}

	return filepath.Join(dir, "identity-candidates.json")
}

func LoadIdentityCandidateStore(path string) (IdentityCandidateStore, error) {
	var store IdentityCandidateStore

	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return IdentityCandidateStore{IdentityCandidates: []IdentityCandidate{}}, nil
		}
		return store, err
	}

	if err := json.Unmarshal(body, &store); err != nil {
		return store, err
	}

	if store.IdentityCandidates == nil {
		store.IdentityCandidates = []IdentityCandidate{}
	}

	return store, nil
}

func SaveIdentityCandidateStore(path string, store IdentityCandidateStore) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	if store.IdentityCandidates == nil {
		store.IdentityCandidates = []IdentityCandidate{}
	}

	body, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, body, 0600)
}

// AddIdentityCandidate stores a candidate identity record with deterministic
// dedupe. It does not mutate trust.json, append trust-events.jsonl, verify a
// device, mark a device changed, or affect send/open/ack behavior.
func AddIdentityCandidate(path string, candidate IdentityCandidate) (IdentityCandidate, bool, error) {
	normalized, err := NormalizeIdentityCandidate(candidate)
	if err != nil {
		return IdentityCandidate{}, false, err
	}

	store, err := LoadIdentityCandidateStore(path)
	if err != nil {
		return IdentityCandidate{}, false, err
	}

	dedupeKey := IdentityCandidateDedupeKey(normalized)
	for _, existing := range store.IdentityCandidates {
		if IdentityCandidateDedupeKey(existing) == dedupeKey {
			return existing, false, nil
		}
	}

	store.IdentityCandidates = append(store.IdentityCandidates, normalized)
	if err := SaveIdentityCandidateStore(path, store); err != nil {
		return IdentityCandidate{}, false, err
	}

	return normalized, true, nil
}

func NormalizeIdentityCandidate(candidate IdentityCandidate) (IdentityCandidate, error) {
	candidate.Fingerprint = strings.TrimSpace(candidate.Fingerprint)
	candidate.Source = strings.TrimSpace(candidate.Source)
	candidate.ClaimedDeviceID = strings.TrimSpace(candidate.ClaimedDeviceID)
	candidate.CandidateState = strings.TrimSpace(candidate.CandidateState)
	candidate.CandidateID = strings.TrimSpace(candidate.CandidateID)
	candidate.ObservedAt = strings.TrimSpace(candidate.ObservedAt)

	if candidate.Fingerprint == "" {
		return IdentityCandidate{}, ErrIdentityCandidateInvalid
	}
	if candidate.Source == "" {
		return IdentityCandidate{}, ErrIdentityCandidateInvalid
	}

	if candidate.CandidateState == "" {
		candidate.CandidateState = CandidateStateObserved
	}
	if !IsAllowedIdentityCandidateState(candidate.CandidateState) {
		return IdentityCandidate{}, ErrIdentityCandidateInvalid
	}

	if candidate.ObservedAt == "" {
		candidate.ObservedAt = NowUTC()
	}
	if candidate.CandidateID == "" {
		candidate.CandidateID = IdentityCandidateID(candidate)
	}

	return candidate, nil
}

func IsAllowedIdentityCandidateState(state string) bool {
	switch state {
	case CandidateStateObserved,
		CandidateStatePendingReview,
		CandidateStateUnverified,
		CandidateStateConflictsKnownDevice,
		CandidateStateRejected:
		return true
	default:
		return false
	}
}

func IdentityCandidateDedupeKey(candidate IdentityCandidate) string {
	fingerprint := strings.TrimSpace(candidate.Fingerprint)
	source := strings.TrimSpace(candidate.Source)
	claimedDeviceID := strings.TrimSpace(candidate.ClaimedDeviceID)

	if claimedDeviceID == "" {
		return fingerprint + "|" + source
	}

	return claimedDeviceID + "|" + fingerprint + "|" + source
}

func IdentityCandidateID(candidate IdentityCandidate) string {
	sum := sha256.Sum256([]byte(IdentityCandidateDedupeKey(candidate)))
	return "candidate-" + hex.EncodeToString(sum[:8])
}
