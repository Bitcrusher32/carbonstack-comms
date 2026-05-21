package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultServerURL = "http://localhost:8080"
	DefaultStatePath = ".carbonstack-comms/state.json"
	ProtocolVersion  = "stub-v0"
)

type State struct {
	ServerURL          string `json:"server_url"`
	AccountID          string `json:"account_id"`
	DisplayName        string `json:"display_name"`
	DeviceID           string `json:"device_id"`
	DeviceLabel        string `json:"device_label"`
	PublicIdentityKey  string `json:"public_identity_key"`
	PublicPrekeyBundle string `json:"public_prekey_bundle"`
	ProtocolVersion    string `json:"protocol_version"`
}

func Load(path string) (State, error) {
	var s State

	body, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}

	if err := json.Unmarshal(body, &s); err != nil {
		return s, err
	}

	return s, nil
}

func Require(path string) (State, error) {
	s, err := Load(path)
	if err != nil {
		return State{}, fmt.Errorf("load state %s: %w", path, err)
	}
	Normalize(&s)
	return s, nil
}

func RequireReadyDevice(path string) (State, error) {
	s, err := Require(path)
	if err != nil {
		return State{}, err
	}
	if s.DeviceID == "" {
		return State{}, fmt.Errorf("state has no device_id; run register-device first")
	}
	return s, nil
}

func Save(path string, s State) error {
	Normalize(&s)

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, body, 0600)
}

func Normalize(s *State) {
	if s.ServerURL == "" {
		s.ServerURL = DefaultServerURL
	}
	s.ServerURL = strings.TrimRight(s.ServerURL, "/")
	if s.ProtocolVersion == "" {
		s.ProtocolVersion = ProtocolVersion
	}
}

func ServerFromStateOrFlag(statePath string, serverFlag string) string {
	server := strings.TrimRight(serverFlag, "/")
	if server != "" {
		return server
	}

	s, err := Load(statePath)
	if err == nil && s.ServerURL != "" {
		return strings.TrimRight(s.ServerURL, "/")
	}

	return DefaultServerURL
}
