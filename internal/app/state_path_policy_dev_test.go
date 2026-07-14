package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStatePathPolicyDerivedRootPreservesStateCompatibility(t *testing.T) {
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".carbonstack-comms", "state.json")

	report := evaluateStatePathPolicy(statePathPolicyInput{
		StatePath:  statePath,
		SidecarDir: filepath.Join(tmp, "sidecar"),
	})

	if report.Action != "allow" {
		t.Fatalf("expected allow, got %+v", report)
	}
	if report.StateRoot != filepath.Dir(statePath) {
		t.Fatalf("state root = %q", report.StateRoot)
	}
	if report.StateRootSource != "derived_from_state_path" {
		t.Fatalf("state root source = %q", report.StateRootSource)
	}
	if !report.ExplicitStateCompatibility || report.CanonicalRootBrittleChokepoint {
		t.Fatalf("policy flags wrong: %+v", report)
	}
}

func TestStatePathPolicyExplicitRootMismatchClassifiesNotRefuses(t *testing.T) {
	tmp := t.TempDir()
	report := evaluateStatePathPolicy(statePathPolicyInput{
		StatePath:    filepath.Join(tmp, "custom-state", "state.json"),
		StateRoot:    filepath.Join(tmp, "custom-root"),
		SidecarDir:   filepath.Join(tmp, "sidecar"),
		CypherDBPath: filepath.Join(tmp, "cypher.db"),
		EvidenceRoot: tmp,
	})

	if report.Action != "classify" {
		t.Fatalf("expected classify for explicit root mismatch, got %+v", report)
	}
	if report.StateRootRelationship != "explicit_root_differs_from_state_directory" {
		t.Fatalf("relationship = %q", report.StateRootRelationship)
	}
	if report.StateRelocationPerformed || report.MigrationPerformed || report.RepairPerformed {
		t.Fatalf("C3 performed mutation semantics: %+v", report)
	}
}

func TestStatePathPolicyParentTraversalRefuses(t *testing.T) {
	report := evaluateStatePathPolicy(statePathPolicyInput{
		StatePath:  "../bad/state.json",
		SidecarDir: "sidecar",
	})

	if report.Action != "refuse" {
		t.Fatalf("expected refusal, got %+v", report)
	}
	if report.Summary.RefuseItems == 0 {
		t.Fatalf("expected refused item: %+v", report.Summary)
	}
}

func TestStatePathPolicyOutputIsAtomicGeneratedEvidence(t *testing.T) {
	tmp := t.TempDir()
	output := filepath.Join(tmp, "out", "path-policy.json")
	report := evaluateStatePathPolicy(statePathPolicyInput{
		StatePath:  filepath.Join(tmp, ".carbonstack-comms", "state.json"),
		SidecarDir: filepath.Join(tmp, "sidecar"),
		OutputPath: output,
	})
	report.OutputPath = output

	if err := writeStatePathPolicyReportAtomic(output, report); err != nil {
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
	if loaded["schema_version"] != statePathPolicyReportSchema {
		t.Fatalf("schema_version = %v", loaded["schema_version"])
	}
	if _, err := os.Stat(output + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary report file remained: %v", err)
	}
}

func TestStatePathPolicyClassifiesExternalAuthoritiesOnly(t *testing.T) {
	tmp := t.TempDir()
	report := evaluateStatePathPolicy(statePathPolicyInput{
		StatePath:         filepath.Join(tmp, ".carbonstack-comms", "state.json"),
		SidecarDir:        filepath.Join(tmp, "sidecar"),
		CypherDBPath:      filepath.Join(tmp, "cypher.db"),
		ValidatorTempRoot: filepath.Join(tmp, "validator"),
		EvidenceRoot:      filepath.Join(tmp, "evidence"),
	})

	for _, item := range report.Items {
		if item.AuthorityDomain != "comms_owned" && item.Action == "allow" {
			t.Fatalf("external authority item allowed instead of classified: %+v", item)
		}
	}
	if !report.SidecarClassifiedOnly || !report.CypherClassifiedOnly {
		t.Fatalf("external authority flags not preserved: %+v", report)
	}
}
