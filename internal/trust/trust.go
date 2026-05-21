package trust

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	StateUnknown     = "unknown"
	StateUnverified  = "unverified"
	StateVerified    = "verified"
	StateChanged     = "changed"
	StateRevoked     = "revoked"
	StateCompromised = "compromised"
)

type Paths struct {
	TrustPath  string
	EventsPath string
}

type DeviceRecord struct {
	AccountID         string `json:"account_id"`
	DeviceID          string `json:"device_id"`
	DisplayLabel      string `json:"display_label"`
	PublicIdentityKey string `json:"public_identity_key"`
	Fingerprint       string `json:"fingerprint"`
	TrustState        string `json:"trust_state"`
	FirstSeenAt       string `json:"first_seen_at"`
	LastSeenAt        string `json:"last_seen_at"`
}

type Store struct {
	TrustedDevices []DeviceRecord `json:"trusted_devices"`
}

type Event struct {
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

type SendDecision struct {
	Allowed    bool
	Warning    string
	TrustState string
}

func PathsForStatePath(statePath string) Paths {
	dir := filepath.Dir(statePath)
	if dir == "" || dir == "." {
		dir = ".carbonstack-comms"
	}

	return Paths{
		TrustPath:  filepath.Join(dir, "trust.json"),
		EventsPath: filepath.Join(dir, "trust-events.jsonl"),
	}
}

func Fingerprint(publicIdentityKey string) string {
	sum := sha256.Sum256([]byte(publicIdentityKey))
	encoded := strings.ToUpper(hex.EncodeToString(sum[:]))

	short := encoded[:32]
	groups := make([]string, 0, 8)
	for i := 0; i < len(short); i += 4 {
		groups = append(groups, short[i:i+4])
	}

	return "CSFP-" + strings.Join(groups, "-")
}

func LoadStore(path string) (Store, error) {
	var store Store

	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Store{TrustedDevices: []DeviceRecord{}}, nil
		}
		return store, err
	}

	if err := json.Unmarshal(body, &store); err != nil {
		return store, err
	}

	if store.TrustedDevices == nil {
		store.TrustedDevices = []DeviceRecord{}
	}

	return store, nil
}

func SaveStore(path string, store Store) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	body, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, body, 0600)
}

func LookupDevice(paths Paths, deviceID string) (DeviceRecord, bool, error) {
	store, err := LoadStore(paths.TrustPath)
	if err != nil {
		return DeviceRecord{}, false, err
	}

	for _, record := range store.TrustedDevices {
		if record.DeviceID == deviceID {
			return record, true, nil
		}
	}

	return DeviceRecord{}, false, nil
}

func VerifyDevice(paths Paths, accountID string, deviceID string, label string, publicIdentityKey string, source string) (DeviceRecord, error) {
	if strings.TrimSpace(deviceID) == "" {
		return DeviceRecord{}, errors.New("device_id is required")
	}
	if strings.TrimSpace(publicIdentityKey) == "" {
		return DeviceRecord{}, errors.New("public_identity_key is required")
	}

	now := NowUTC()
	fp := Fingerprint(publicIdentityKey)

	store, err := LoadStore(paths.TrustPath)
	if err != nil {
		return DeviceRecord{}, err
	}

	previous := StateUnknown
	updated := false
	var record DeviceRecord

	for i, existing := range store.TrustedDevices {
		if existing.DeviceID == deviceID {
			previous = existing.TrustState
			if existing.FirstSeenAt == "" {
				existing.FirstSeenAt = now
			}
			existing.LastSeenAt = now
			existing.AccountID = accountID
			existing.DisplayLabel = label
			existing.PublicIdentityKey = publicIdentityKey
			existing.Fingerprint = fp
			existing.TrustState = StateVerified
			store.TrustedDevices[i] = existing
			record = existing
			updated = true
			break
		}
	}

	if !updated {
		record = DeviceRecord{
			AccountID:         accountID,
			DeviceID:          deviceID,
			DisplayLabel:      label,
			PublicIdentityKey: publicIdentityKey,
			Fingerprint:       fp,
			TrustState:        StateVerified,
			FirstSeenAt:       now,
			LastSeenAt:        now,
		}
		store.TrustedDevices = append(store.TrustedDevices, record)
	}

	if err := SaveStore(paths.TrustPath, store); err != nil {
		return DeviceRecord{}, err
	}

	event := Event{
		EventID:            EventID(),
		EventType:          "device_verified",
		AccountID:          accountID,
		DeviceID:           deviceID,
		PreviousTrustState: previous,
		NewTrustState:      StateVerified,
		Fingerprint:        fp,
		EventTime:          now,
		Source:             source,
		Note:               "manual fingerprint verification",
	}

	if err := AppendEvent(paths.EventsPath, event); err != nil {
		return DeviceRecord{}, err
	}

	return record, nil
}

func MarkDeviceChanged(paths Paths, deviceID string, newPublicIdentityKey string, source string) (DeviceRecord, error) {
	if strings.TrimSpace(deviceID) == "" {
		return DeviceRecord{}, errors.New("device_id is required")
	}
	if strings.TrimSpace(newPublicIdentityKey) == "" {
		return DeviceRecord{}, errors.New("new public identity key is required")
	}

	now := NowUTC()
	newFingerprint := Fingerprint(newPublicIdentityKey)

	store, err := LoadStore(paths.TrustPath)
	if err != nil {
		return DeviceRecord{}, err
	}

	for i, existing := range store.TrustedDevices {
		if existing.DeviceID == deviceID {
			previous := existing.TrustState
			existing.PublicIdentityKey = newPublicIdentityKey
			existing.Fingerprint = newFingerprint
			existing.TrustState = StateChanged
			existing.LastSeenAt = now
			store.TrustedDevices[i] = existing

			if err := SaveStore(paths.TrustPath, store); err != nil {
				return DeviceRecord{}, err
			}

			event := Event{
				EventID:            EventID(),
				EventType:          "device_key_changed",
				AccountID:          existing.AccountID,
				DeviceID:           deviceID,
				PreviousTrustState: previous,
				NewTrustState:      StateChanged,
				Fingerprint:        newFingerprint,
				EventTime:          now,
				Source:             source,
				Note:               "simulated device key change",
			}

			if err := AppendEvent(paths.EventsPath, event); err != nil {
				return DeviceRecord{}, err
			}

			return existing, nil
		}
	}

	return DeviceRecord{}, fmt.Errorf("device not found in trust store: %s", deviceID)
}

func RevokeDevice(paths Paths, deviceID string, source string) (DeviceRecord, error) {
	if strings.TrimSpace(deviceID) == "" {
		return DeviceRecord{}, errors.New("device_id is required")
	}

	now := NowUTC()

	store, err := LoadStore(paths.TrustPath)
	if err != nil {
		return DeviceRecord{}, err
	}

	for i, existing := range store.TrustedDevices {
		if existing.DeviceID == deviceID {
			previous := existing.TrustState
			existing.TrustState = StateRevoked
			existing.LastSeenAt = now
			store.TrustedDevices[i] = existing

			if err := SaveStore(paths.TrustPath, store); err != nil {
				return DeviceRecord{}, err
			}

			event := Event{
				EventID:            EventID(),
				EventType:          "device_revoked",
				AccountID:          existing.AccountID,
				DeviceID:           deviceID,
				PreviousTrustState: previous,
				NewTrustState:      StateRevoked,
				Fingerprint:        existing.Fingerprint,
				EventTime:          now,
				Source:             source,
				Note:               "manual development revocation",
			}

			if err := AppendEvent(paths.EventsPath, event); err != nil {
				return DeviceRecord{}, err
			}

			return existing, nil
		}
	}

	return DeviceRecord{}, fmt.Errorf("device not found in trust store: %s", deviceID)
}

func EvaluateSend(paths Paths, recipientDeviceID string, strict bool) (SendDecision, error) {
	record, found, err := LookupDevice(paths, recipientDeviceID)
	if err != nil {
		return SendDecision{}, err
	}

	if !found {
		if strict {
			return SendDecision{
				Allowed:    false,
				TrustState: StateUnknown,
				Warning:    "recipient device is unknown",
			}, nil
		}

		return SendDecision{
			Allowed:    true,
			TrustState: StateUnknown,
			Warning:    "recipient device is unknown; dev mode allows sending but mature mode should block until verification",
		}, nil
	}

	switch record.TrustState {
	case StateVerified:
		return SendDecision{Allowed: true, TrustState: StateVerified}, nil

	case StateRevoked, StateCompromised:
		return SendDecision{
			Allowed:    false,
			TrustState: record.TrustState,
			Warning:    "recipient device is " + record.TrustState,
		}, nil

	case StateChanged:
		if strict {
			return SendDecision{
				Allowed:    false,
				TrustState: StateChanged,
				Warning:    "recipient device identity changed and must be reverified",
			}, nil
		}
		return SendDecision{
			Allowed:    true,
			TrustState: StateChanged,
			Warning:    "recipient device identity changed; dev mode allows override but mature mode should block until reverified",
		}, nil

	default:
		if strict {
			return SendDecision{
				Allowed:    false,
				TrustState: record.TrustState,
				Warning:    "recipient device is not verified",
			}, nil
		}
		return SendDecision{
			Allowed:    true,
			TrustState: record.TrustState,
			Warning:    "recipient device is not verified; dev mode allows sending but mature mode should block",
		}, nil
	}
}

func AppendEvent(path string, event Event) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	body, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if _, err := file.Write(append(body, '\n')); err != nil {
		return err
	}

	return nil
}

func LoadEvents(path string) ([]Event, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Event{}, nil
		}
		return nil, err
	}
	defer file.Close()

	events := []Event{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, err
		}

		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

func NowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func EventID() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	return "event-" + hex.EncodeToString(sum[:8])
}
