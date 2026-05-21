package state

import (
	"path/filepath"
	"testing"
)

func TestSaveLoadAndNormalizeState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")

	input := State{
		ServerURL:   "http://localhost:8080/",
		AccountID:   "account-1",
		DisplayName: "alice",
	}

	if err := Save(path, input); err != nil {
		t.Fatalf("save state: %v", err)
	}

	got, err := Require(path)
	if err != nil {
		t.Fatalf("require state: %v", err)
	}

	if got.ServerURL != "http://localhost:8080" {
		t.Fatalf("expected normalized server URL, got %q", got.ServerURL)
	}

	if got.ProtocolVersion != ProtocolVersion {
		t.Fatalf("expected protocol version %q, got %q", ProtocolVersion, got.ProtocolVersion)
	}

	if got.AccountID != input.AccountID {
		t.Fatalf("expected account_id %q, got %q", input.AccountID, got.AccountID)
	}
}

func TestRequireReadyDeviceRejectsMissingDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	input := State{
		ServerURL: "http://localhost:8080",
		AccountID: "account-1",
	}

	if err := Save(path, input); err != nil {
		t.Fatalf("save state: %v", err)
	}

	_, err := RequireReadyDevice(path)
	if err == nil {
		t.Fatalf("expected error for missing device_id")
	}
}

func TestServerFromStateOrFlagPrefersFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	input := State{
		ServerURL: "http://localhost:8080",
	}

	if err := Save(path, input); err != nil {
		t.Fatalf("save state: %v", err)
	}

	got := ServerFromStateOrFlag(path, "http://example.test/")
	if got != "http://example.test" {
		t.Fatalf("expected flag server URL, got %q", got)
	}
}

func TestServerFromStateOrFlagFallsBackToState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	input := State{
		ServerURL: "http://localhost:9090/",
	}

	if err := Save(path, input); err != nil {
		t.Fatalf("save state: %v", err)
	}

	got := ServerFromStateOrFlag(path, "")
	if got != "http://localhost:9090" {
		t.Fatalf("expected state server URL, got %q", got)
	}
}
