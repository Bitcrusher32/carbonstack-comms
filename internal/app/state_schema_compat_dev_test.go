package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStateSchemaCompatibilityAllowsSupportedKeyPackageReceipt(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "receipt.json")
	writeSchemaCompatJSON(t, path, map[string]any{
		"schema_version": "carbonstack-keypackage-consume-receipt/v0",
	})

	report := evaluateStateSchemaCompatibility(stateSchemaCompatibilityInput{
		Kind: "keypackage-receipt",
		Path: path,
	})
	if report.Action != "allow" || !report.SupportedSchema {
		t.Fatalf("expected allow/supported, got %+v", report)
	}
	if report.MigrationPerformed || report.RepairPerformed || report.MutationPerformed {
		t.Fatalf("compat check mutated/repaired/migrated: %+v", report)
	}
}

func TestStateSchemaCompatibilityRefusesUnsupportedWelcomeReceipt(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "receipt.json")
	writeSchemaCompatJSON(t, path, map[string]any{
		"schema_version": "carbonstack-welcome-consume-receipt/v99",
	})

	report := evaluateStateSchemaCompatibility(stateSchemaCompatibilityInput{
		Kind: "welcome-receipt",
		Path: path,
	})
	if report.Action != "refuse" {
		t.Fatalf("expected refusal, got %+v", report)
	}
	if report.SchemaStatus != "unsupported_schema_version" {
		t.Fatalf("schema status = %q", report.SchemaStatus)
	}
	if report.MigrationPerformed || report.RepairPerformed {
		t.Fatalf("unsupported schema was migrated/repaired: %+v", report)
	}
}

func TestStateSchemaCompatibilityRefusesMissingSchemaForWorkflowReport(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "workflow-report.json")
	writeSchemaCompatJSON(t, path, map[string]any{
		"workflow_id": "wf",
	})

	report := evaluateStateSchemaCompatibility(stateSchemaCompatibilityInput{
		Kind: "workflow-report",
		Path: path,
	})
	if report.Action != "refuse" {
		t.Fatalf("expected refusal, got %+v", report)
	}
	if report.Classification != "missing_schema_refused" {
		t.Fatalf("classification = %q", report.Classification)
	}
}

func TestStateSchemaCompatibilityClassifiesLegacyCommsStateWithoutMigration(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "state.json")
	writeSchemaCompatJSON(t, path, map[string]any{
		"server_url": "http://127.0.0.1:1",
		"account_id": "acct",
		"device_id":  "dev",
	})

	report := evaluateStateSchemaCompatibility(stateSchemaCompatibilityInput{
		Kind: "comms-state",
		Path: path,
	})
	if report.Action != "classify" {
		t.Fatalf("expected classify action, got %+v", report)
	}
	if !report.LegacyClassifiedOnly {
		t.Fatalf("expected legacy classify only: %+v", report)
	}
	if report.MigrationPerformed || report.RepairPerformed || report.MutationPerformed {
		t.Fatalf("legacy comms state was migrated/repaired/mutated: %+v", report)
	}
}

func TestStateSchemaCompatibilityRefusesInvalidJSON(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "receipt.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}

	report := evaluateStateSchemaCompatibility(stateSchemaCompatibilityInput{
		Kind: "keypackage-receipt",
		Path: path,
	})
	if report.Action != "refuse" || report.SchemaStatus != "invalid_json" {
		t.Fatalf("expected invalid JSON refusal, got %+v", report)
	}
}

func TestStateSchemaCompatibilityWritesReportAtomically(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "inventory.json")
	output := filepath.Join(tmp, "out", "compat.json")
	writeSchemaCompatJSON(t, path, map[string]any{
		"schema_version": "carbonstack-state-substrate-inventory/v0",
	})

	report := evaluateStateSchemaCompatibility(stateSchemaCompatibilityInput{
		Kind:       "state-substrate-inventory",
		Path:       path,
		OutputPath: output,
	})
	report.OutputPath = output

	if err := writeStateSchemaCompatibilityReportAtomic(output, report); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	loaded := map[string]any{}
	if err := json.Unmarshal(body, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded["schema_version"] != stateSchemaCompatibilityReportSchema {
		t.Fatalf("schema_version = %v", loaded["schema_version"])
	}
	if _, err := os.Stat(output + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary report file remained: %v", err)
	}
}

func writeSchemaCompatJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStateSchemaCompatibilityAllowsPathAndWritePolicyReports(t *testing.T) {
	tmp := t.TempDir()

	pathPolicy := filepath.Join(tmp, "path-policy.json")
	writeSchemaCompatJSON(t, pathPolicy, map[string]any{
		"schema_version": "carbonstack-state-path-policy-report/v0",
	})
	pathReport := evaluateStateSchemaCompatibility(stateSchemaCompatibilityInput{
		Kind: "path-policy-report",
		Path: pathPolicy,
	})
	if pathReport.Action != "allow" || !pathReport.SupportedSchema {
		t.Fatalf("expected path-policy report allow/supported, got %+v", pathReport)
	}

	writePolicy := filepath.Join(tmp, "write-policy.json")
	writeSchemaCompatJSON(t, writePolicy, map[string]any{
		"schema_version": "carbonstack-state-write-policy-report/v0",
	})
	writeReport := evaluateStateSchemaCompatibility(stateSchemaCompatibilityInput{
		Kind: "write-policy-report",
		Path: writePolicy,
	})
	if writeReport.Action != "allow" || !writeReport.SupportedSchema {
		t.Fatalf("expected write-policy report allow/supported, got %+v", writeReport)
	}
}
