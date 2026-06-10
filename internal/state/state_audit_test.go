package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditStateDomainsReportsKnownDomainsWithoutReadingContents(t *testing.T) {
	dir := t.TempDir()

	statePath := filepath.Join(dir, ".carbonstack-comms", "state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	if err := os.WriteFile(statePath, []byte(`{"device_id":"device-1"}`), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	sidecarRoot := filepath.Join(dir, "sidecar-state")
	if err := os.MkdirAll(sidecarRoot, 0o700); err != nil {
		t.Fatalf("mkdir sidecar root: %v", err)
	}

	cypherDB := filepath.Join(dir, "cypher.db")
	if err := os.WriteFile(cypherDB, []byte("sqlite-placeholder"), 0o600); err != nil {
		t.Fatalf("write cypher db placeholder: %v", err)
	}

	domains := AuditStateDomains(StateAuditOptions{
		StatePath:        statePath,
		SidecarStateRoot: sidecarRoot,
		CypherDBPath:     cypherDB,
	})

	byName := map[string]StateAuditDomain{}
	for _, domain := range domains {
		byName[domain.Domain] = domain
		if domain.MutationAllowed {
			t.Fatalf("audit domain %s unexpectedly allows mutation", domain.Domain)
		}
		if domain.SafeToPrintContents {
			t.Fatalf("audit domain %s unexpectedly allows printing raw contents", domain.Domain)
		}
	}

	for _, name := range []string{
		"comms_state",
		"trust_store",
		"trust_history",
		"candidate_store",
		"sidecar_generated_state",
		"sidecar_build_output",
		"local_cypher_db",
	} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("missing audit domain %s", name)
		}
	}

	if !byName["comms_state"].Present {
		t.Fatal("expected comms_state to be present")
	}
	if byName["comms_state"].Kind != "file" {
		t.Fatalf("comms_state kind = %q", byName["comms_state"].Kind)
	}
	if !byName["sidecar_generated_state"].Present {
		t.Fatal("expected sidecar_generated_state to be present")
	}
	if byName["sidecar_generated_state"].Kind != "directory" {
		t.Fatalf("sidecar_generated_state kind = %q", byName["sidecar_generated_state"].Kind)
	}
	if !byName["local_cypher_db"].Present {
		t.Fatal("expected local_cypher_db to be present")
	}
	if byName["candidate_store"].Present {
		t.Fatal("candidate_store should be absent in this setup")
	}
}

func TestBuildStateAuditReportIsMachineReadableAndNonMutating(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	if err := os.WriteFile(statePath, []byte(`{"device_id":"secret-device-marker"}`), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	report := BuildStateAuditReport(StateAuditOptions{
		StatePath: statePath,
	})

	if report.SchemaVersion != StateAuditSchemaVersion {
		t.Fatalf("schema version = %q", report.SchemaVersion)
	}
	if report.Command != "state-audit-dev" {
		t.Fatalf("command = %q", report.Command)
	}
	if report.MutationAllowed {
		t.Fatal("state audit report must not allow mutation")
	}
	if report.RawSecretContentsPrinted {
		t.Fatal("state audit report must not print raw secret contents")
	}
	if report.DomainsTotal != len(report.Domains) {
		t.Fatalf("domains_total = %d, len domains = %d", report.DomainsTotal, len(report.Domains))
	}

	body, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if string(body) == "" {
		t.Fatal("expected JSON body")
	}
	if containsStateAuditTestString(string(body), "secret-device-marker") {
		t.Fatalf("machine-readable report leaked state contents: %s", string(body))
	}
}

func TestAuditStateDomainsDefaultsPaths(t *testing.T) {
	domains := AuditStateDomains(StateAuditOptions{})

	if len(domains) == 0 {
		t.Fatal("expected default audit domains")
	}

	foundState := false
	foundSidecar := false
	foundCypher := false

	for _, domain := range domains {
		switch domain.Domain {
		case "comms_state":
			foundState = domain.Path == DefaultStatePath
		case "sidecar_generated_state":
			foundSidecar = domain.Path == DefaultSidecarStateRoot
		case "local_cypher_db":
			foundCypher = domain.Path == DefaultCypherDBPath
		}
	}

	if !foundState {
		t.Fatalf("expected default comms state path %q", DefaultStatePath)
	}
	if !foundSidecar {
		t.Fatalf("expected default sidecar path %q", DefaultSidecarStateRoot)
	}
	if !foundCypher {
		t.Fatalf("expected default cypher db path %q", DefaultCypherDBPath)
	}
}

func containsStateAuditTestString(s string, needle string) bool {
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
