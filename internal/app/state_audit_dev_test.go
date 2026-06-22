package app

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func TestStateAuditDevReportsDomainsAndDoesNotPrintContents(t *testing.T) {
	dir := t.TempDir()

	statePath := filepath.Join(dir, ".carbonstack-comms", "state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	if err := os.WriteFile(statePath, []byte(`{"device_id":"secret-device-marker"}`), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	sidecarRoot := filepath.Join(dir, ".carbonstack-openmls-sidecar-state")
	if err := os.MkdirAll(sidecarRoot, 0o700); err != nil {
		t.Fatalf("mkdir sidecar root: %v", err)
	}

	output := captureStateAuditDevOutput(t, func() error {
		return cmdStateAuditDev([]string{
			"--state", statePath,
			"--sidecar-state-root", sidecarRoot,
			"--sidecar-target-root", filepath.Join(dir, "target"),
			"--cypher-db", filepath.Join(dir, "cypher.db"),
		})
	})

	for _, want := range []string{
		"command: state-audit-dev",
		"state_boundary_model_version: v0.6.29-state-boundary-v0",
		"state_boundary_role: proto_substrate_inventory_check",
		"proto_substrate: true",
		"pq_tags_reserved_not_implemented: true",
		"schema_version: carbonstack-comms-state-audit/v0",
		"mutation_allowed: false",
		"raw_secret_contents_printed: false",
		"domain: comms_state",
		"domain: trust_store",
		"domain: trust_history",
		"domain: candidate_store",
		"domain: sidecar_generated_state",
		"domain: sidecar_build_output",
		"domain: local_cypher_db",
		"authority_class: server_side_coordination_authority_inventory_only",
		"cypher_inventory_only: true",
		"classification: generated-dev-provider-state",
		"authority_class: dev_runtime_authority_container",
		"sensitivity_class: secret_bearing_safety_sensitive_dev_scope",
		"no_silent_rule: no_silent_runtime_authority_regeneration",
		"boundary_warning: dev_generated_state_not_production_vault",
		"vault_class: generated_secret_state",
		"future_vault_required: true",
		"status: inspected",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q\n%s", want, output)
		}
	}

	if strings.Contains(output, "secret-device-marker") {
		t.Fatalf("state-audit-dev printed raw state contents:\n%s", output)
	}
}

func TestStateAuditDevJSONFormatIsMachineReadableAndDoesNotPrintContents(t *testing.T) {
	dir := t.TempDir()

	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(statePath, []byte(`{"device_id":"secret-device-marker"}`), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	output := captureStateAuditDevOutput(t, func() error {
		return cmdStateAuditDev([]string{
			"--state", statePath,
			"--format", "json",
		})
	})

	if strings.Contains(output, "secret-device-marker") {
		t.Fatalf("state-audit-dev JSON printed raw state contents:\n%s", output)
	}

	var report state.StateAuditReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("unmarshal JSON report: %v\n%s", err, output)
	}

	if report.SchemaVersion != state.StateAuditSchemaVersion {
		t.Fatalf("schema_version = %q", report.SchemaVersion)
	}
	if report.Command != "state-audit-dev" {
		t.Fatalf("command = %q", report.Command)
	}
	if report.StateBoundaryModelVersion != "v0.6.29-state-boundary-v0" {
		t.Fatalf("state_boundary_model_version = %q", report.StateBoundaryModelVersion)
	}
	if !report.ProtoSubstrate {
		t.Fatal("expected proto_substrate=true")
	}
	if !report.PQTagsReservedNotImpl {
		t.Fatal("expected pq_tags_reserved_not_implemented=true")
	}
	if report.RawSecretContentsPrinted {
		t.Fatal("JSON report claims raw secret contents were printed")
	}
	if report.MutationAllowed {
		t.Fatal("JSON report claims mutation is allowed")
	}
	if report.DomainsTotal != len(report.Domains) {
		t.Fatalf("domains_total = %d, len domains = %d", report.DomainsTotal, len(report.Domains))
	}
	if report.DomainsTotal == 0 {
		t.Fatal("expected domains in JSON report")
	}
	if report.Domains[0].VaultClass == "" {
		t.Fatal("expected vault_class in JSON report domain")
	}
	if report.Domains[0].AuthorityClass == "" {
		t.Fatal("expected authority_class in JSON report domain")
	}
	if report.Domains[0].SensitivityClass == "" {
		t.Fatal("expected sensitivity_class in JSON report domain")
	}
	if report.Domains[0].NoSilentRule == "" {
		t.Fatal("expected no_silent_rule in JSON report domain")
	}
}

func TestStateAuditDevRejectsUnknownFormat(t *testing.T) {
	err := cmdStateAuditDev([]string{
		"--format", "yaml",
	})
	if err == nil || !strings.Contains(err.Error(), "--format must be text or json") {
		t.Fatalf("expected format error, got %v", err)
	}
}

func TestDispatchStateAuditDev(t *testing.T) {
	output := captureStateAuditDevOutput(t, func() error {
		return Run([]string{
			"state-audit-dev",
			"--state", filepath.Join(t.TempDir(), "state.json"),
		})
	})

	if !strings.Contains(output, "command: state-audit-dev") {
		t.Fatalf("dispatch output missing command marker:\n%s", output)
	}
}

func captureStateAuditDevOutput(t *testing.T, fn func() error) string {
	t.Helper()

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	os.Stdout = writer

	runErr := fn()

	if closeErr := writer.Close(); closeErr != nil {
		t.Fatalf("close writer: %v", closeErr)
	}
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		t.Fatalf("copy output: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close reader: %v", err)
	}

	if runErr != nil {
		t.Fatalf("command failed: %v\noutput:\n%s", runErr, buf.String())
	}

	return buf.String()
}
