package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildStatePathContractIsNonEncryptingAndNonMutating(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, ".carbonstack-comms", "state.json")

	contract := BuildStatePathContract(StateAuditOptions{
		StatePath: statePath,
	})

	if contract.SchemaVersion != StatePathContractSchemaVersion {
		t.Fatalf("schema_version = %q", contract.SchemaVersion)
	}
	if contract.StatePath != statePath {
		t.Fatalf("state_path = %q", contract.StatePath)
	}
	if len(contract.Domains) == 0 {
		t.Fatal("expected contract domains")
	}

	if contract.Capabilities.EncryptionEnabled {
		t.Fatal("path contract must not claim encryption")
	}
	if contract.Capabilities.CanReadSecretContents {
		t.Fatal("path contract must not read secret contents")
	}
	if contract.Capabilities.CanWriteSecretContent {
		t.Fatal("path contract must not write secret contents")
	}
	if contract.Capabilities.CanDeleteDomains {
		t.Fatal("path contract must not delete domains")
	}

	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path contract should not create state file, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(statePath), "trust.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path contract should not create trust file, stat err=%v", err)
	}
}

func TestStatePathContractResolvesExpectedLocalDomains(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, ".carbonstack-comms", "state.json")
	opts := StateAuditOptions{StatePath: statePath}

	tests := []struct {
		name   string
		domain StateDomainID
		want   string
	}{
		{
			name:   "comms state",
			domain: StateDomainCommsState,
			want:   statePath,
		},
		{
			name:   "trust store",
			domain: StateDomainTrustStore,
			want:   filepath.Join(filepath.Dir(statePath), "trust.json"),
		},
		{
			name:   "trust history",
			domain: StateDomainTrustHistory,
			want:   filepath.Join(filepath.Dir(statePath), "trust-events.jsonl"),
		},
		{
			name:   "candidate store",
			domain: StateDomainCandidateStore,
			want:   filepath.Join(filepath.Dir(statePath), "identity-candidates.json"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveStateDomainPath(opts, tt.domain)
			if err != nil {
				t.Fatalf("resolve domain: %v", err)
			}
			if got != tt.want {
				t.Fatalf("path = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStatePathContractJSONDoesNotReadOrLeakFileContents(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, ".carbonstack-comms", "state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	if err := os.WriteFile(statePath, []byte(`{"device_id":"secret-device-marker"}`), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	contract := BuildStatePathContract(StateAuditOptions{
		StatePath: statePath,
	})

	body, err := json.Marshal(contract)
	if err != nil {
		t.Fatalf("marshal contract: %v", err)
	}

	if strings.Contains(string(body), "secret-device-marker") {
		t.Fatalf("path contract leaked state file contents: %s", string(body))
	}
	if !strings.Contains(string(body), "carbonstack-comms-state-path-contract/v0") {
		t.Fatalf("contract JSON missing schema marker: %s", string(body))
	}
}

func TestResolveStateDomainPathRejectsUnknownDomain(t *testing.T) {
	_, err := ResolveStateDomainPath(StateAuditOptions{}, StateDomainID("missing_domain"))
	if err == nil || !strings.Contains(err.Error(), "unknown state domain") {
		t.Fatalf("expected unknown domain error, got %v", err)
	}
}
