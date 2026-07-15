package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStateWritePolicyClassifiesCoreSurfaces(t *testing.T) {
	report := evaluateStateWritePolicy(stateWritePolicyInput{
		StateRoot:    ".carbonstack-comms",
		SidecarDir:   "internal/protocol/mls/openmls-sidecar",
		CypherDBPath: "cypher.db",
	})

	if report.Action != "classify" {
		t.Fatalf("expected classify, got %+v", report)
	}
	if report.Summary.TotalSurfaces < 10 {
		t.Fatalf("expected core surfaces, got %+v", report.Summary)
	}
	requireWritePolicySurface(t, report, "b5d.keypackage_consume_receipt", "atomic_receipt_writer", "lock_guarded_writer", "exact_replay_from_local_receipt_already_consumed")
	requireWritePolicySurface(t, report, "b6.welcome_consume_receipt", "atomic_receipt_writer", "lock_guarded_writer", "exact_replay_from_local_receipt_already_joined")
	requireWritePolicySurface(t, report, "b8.workflow_relay_onboarding_report", "atomic_json_report_writer", "report_idempotence_without_global_lock", "exact_replay_from_local_report_already_reported")
}

func TestStateWritePolicyClassifiesDirectWritesAsFutureHardening(t *testing.T) {
	report := evaluateStateWritePolicy(stateWritePolicyInput{
		StateRoot:  ".carbonstack-comms",
		SidecarDir: "internal/protocol/mls/openmls-sidecar",
	})

	for _, id := range []string{"comms.local_state_file", "comms.trust_store", "comms.identity_candidates"} {
		item := findWritePolicySurface(t, report, id)
		if !item.FutureHardeningWarning {
			t.Fatalf("expected future hardening warning for %s: %+v", id, item)
		}
		if item.MigrationPerformedByC4 || item.RepairPerformedByC4 || item.MutationPerformedByC4 {
			t.Fatalf("C4 mutated direct write surface %s: %+v", id, item)
		}
	}
	if report.Summary.FutureHardeningWarnings < 3 {
		t.Fatalf("expected direct-write warnings: %+v", report.Summary)
	}
}

func TestStateWritePolicyNonClaimsHold(t *testing.T) {
	report := evaluateStateWritePolicy(stateWritePolicyInput{
		StateRoot:  ".carbonstack-comms",
		SidecarDir: "internal/protocol/mls/openmls-sidecar",
	})
	if report.RuntimeWriterRewired || report.MutationPerformed || report.MigrationPerformed || report.RepairPerformed || report.StateRelocationPerformed {
		t.Fatalf("unexpected mutation/rewire claim: %+v", report)
	}
	if report.CleanupImplemented || report.DestructiveCleanupPerformed {
		t.Fatalf("unexpected cleanup claim: %+v", report)
	}
	if report.VerifiedIdentityClaimed || report.VaultClaimed || report.BackupRestoreClaimed || report.DeploymentClaimed || report.FullRuntimeDevPromoted || report.GateDStarted {
		t.Fatalf("unexpected downstream claim: %+v", report)
	}
}

func TestStateWritePolicyOutputIsAtomicGeneratedEvidence(t *testing.T) {
	tmp := t.TempDir()
	output := filepath.Join(tmp, "out", "write-policy.json")
	report := evaluateStateWritePolicy(stateWritePolicyInput{
		StateRoot:         filepath.Join(tmp, ".carbonstack-comms"),
		SidecarDir:        filepath.Join(tmp, "sidecar"),
		CypherDBPath:      filepath.Join(tmp, "cypher.db"),
		ValidatorTempRoot: filepath.Join(tmp, "validator"),
		EvidenceRoot:      filepath.Join(tmp, "evidence"),
		OutputPath:        output,
	})
	report.OutputPath = output

	if err := writeStateWritePolicyReportAtomic(output, report); err != nil {
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
	if loaded["schema_version"] != stateWritePolicyReportSchema {
		t.Fatalf("schema_version = %v", loaded["schema_version"])
	}
	if _, err := os.Stat(output + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary report file remained: %v", err)
	}
}

func requireWritePolicySurface(t *testing.T, report stateWritePolicyReport, id, writer, lock, replay string) {
	t.Helper()
	item := findWritePolicySurface(t, report, id)
	if item.WriterClass != writer || item.LockDiscipline != lock || item.ReplaySemantics != replay {
		t.Fatalf("surface %s mismatch: %+v", id, item)
	}
}

func findWritePolicySurface(t *testing.T, report stateWritePolicyReport, id string) stateWritePolicyItem {
	t.Helper()
	for _, item := range report.Surfaces {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("surface %q not found", id)
	return stateWritePolicyItem{}
}
