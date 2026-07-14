package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStateSubstrateInventoryMissingStateIsClassified(t *testing.T) {
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".carbonstack-comms", "state.json")

	report, err := evaluateStateSubstrateInventory(stateSubstrateInventoryInput{
		StatePath:  statePath,
		SidecarDir: filepath.Join(tmp, "sidecar"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.StateRoot != filepath.Dir(statePath) {
		t.Fatalf("state root = %q", report.StateRoot)
	}
	item := findStateSubstrateItem(t, report, "comms.state_file")
	if item.Exists {
		t.Fatalf("missing state file classified as existing: %+v", item)
	}
	if !report.ExplicitStateCompatibility || !report.DeepReconFriendly {
		t.Fatalf("compat/recon flags not preserved: %+v", report)
	}
}

func TestStateSubstrateInventoryDetectsSupportedReceiptSchemas(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, ".carbonstack-comms")
	kpReceipt := filepath.Join(root, "keypackage-receipts", "env1", "receipt.json")
	welcomeReceipt := filepath.Join(root, "welcome-receipts", "env2", "receipt.json")
	workflowReport := filepath.Join(root, "workflow-reports", "wf", "workflow-report.json")

	writeInventoryJSON(t, filepath.Join(root, "state.json"), map[string]any{
		"server_url": "http://127.0.0.1:1",
		"account_id": "acct",
		"device_id":  "dev",
	})
	writeInventoryJSON(t, kpReceipt, map[string]any{
		"schema_version": "carbonstack-keypackage-consume-receipt/v0",
	})
	writeInventoryJSON(t, welcomeReceipt, map[string]any{
		"schema_version": "carbonstack-welcome-consume-receipt/v0",
	})
	writeInventoryJSON(t, workflowReport, map[string]any{
		"schema_version": "carbonstack-workflow-relay-onboarding-report/v0",
	})

	report, err := evaluateStateSubstrateInventory(stateSubstrateInventoryInput{
		StatePath:  filepath.Join(root, "state.json"),
		SidecarDir: filepath.Join(tmp, "sidecar"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.UnsupportedSchemaItems != 0 {
		t.Fatalf("unexpected unsupported schemas: %+v", report.Summary)
	}
	if report.Summary.ExistingItems < 4 {
		t.Fatalf("expected existing items, got summary: %+v", report.Summary)
	}
	if item := findStateSubstrateItem(t, report, "discovered.keypackage_receipt.env1_receipt.json"); !item.SupportedSchema {
		t.Fatalf("keypackage receipt not supported: %+v", item)
	}
	if item := findStateSubstrateItem(t, report, "discovered.welcome_receipt.env2_receipt.json"); !item.SupportedSchema {
		t.Fatalf("welcome receipt not supported: %+v", item)
	}
	if item := findStateSubstrateItem(t, report, "discovered.workflow_report.wf_workflow-report.json"); !item.SupportedSchema {
		t.Fatalf("workflow report not supported: %+v", item)
	}
}

func TestStateSubstrateInventoryClassifiesUnsupportedSchema(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, ".carbonstack-comms")
	receipt := filepath.Join(root, "welcome-receipts", "env", "receipt.json")
	writeInventoryJSON(t, receipt, map[string]any{
		"schema_version": "carbonstack-welcome-consume-receipt/v99",
	})

	report, err := evaluateStateSubstrateInventory(stateSubstrateInventoryInput{
		StatePath:  filepath.Join(root, "state.json"),
		SidecarDir: filepath.Join(tmp, "sidecar"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.UnsupportedSchemaItems != 1 {
		t.Fatalf("unsupported schema count = %d", report.Summary.UnsupportedSchemaItems)
	}
	item := findStateSubstrateItem(t, report, "discovered.welcome_receipt.env_receipt.json")
	if item.SchemaStatus != "unsupported_schema_version" {
		t.Fatalf("schema status = %q", item.SchemaStatus)
	}
}

func TestStateSubstrateInventoryWritesReportAtomically(t *testing.T) {
	tmp := t.TempDir()
	output := filepath.Join(tmp, "out", "inventory.json")
	report, err := evaluateStateSubstrateInventory(stateSubstrateInventoryInput{
		StatePath:  filepath.Join(tmp, ".carbonstack-comms", "state.json"),
		SidecarDir: filepath.Join(tmp, "sidecar"),
		OutputPath: output,
	})
	if err != nil {
		t.Fatal(err)
	}
	report.OutputPath = output
	if err := writeStateSubstrateInventoryReportAtomic(output, report); err != nil {
		t.Fatal(err)
	}
	loaded := map[string]any{}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded["schema_version"] != stateSubstrateInventorySchema {
		t.Fatalf("schema_version = %v", loaded["schema_version"])
	}
	if _, err := os.Stat(output + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary report file remained: %v", err)
	}
}

func findStateSubstrateItem(t *testing.T, report stateSubstrateInventoryReport, id string) stateSubstrateInventoryItem {
	t.Helper()
	for _, item := range report.Items {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("item %q not found in report with %d items", id, len(report.Items))
	return stateSubstrateInventoryItem{}
}

func writeInventoryJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
