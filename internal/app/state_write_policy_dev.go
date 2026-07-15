package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const stateWritePolicyReportSchema = "carbonstack-state-write-policy-report/v0"

type stateWritePolicyInput struct {
	StateRoot         string
	SidecarDir        string
	CypherDBPath      string
	ValidatorTempRoot string
	EvidenceRoot      string
	OutputPath        string
}

type stateWritePolicyReport struct {
	SchemaVersion               string                  `json:"schema_version"`
	Command                     string                  `json:"command"`
	CreatedAt                   string                  `json:"created_at"`
	StateRoot                   string                  `json:"state_root"`
	SidecarDir                  string                  `json:"sidecar_dir"`
	CypherDBPath                string                  `json:"cypher_db_path,omitempty"`
	ValidatorTempRoot           string                  `json:"validator_temp_root,omitempty"`
	EvidenceRoot                string                  `json:"evidence_root,omitempty"`
	OutputPath                  string                  `json:"output_path,omitempty"`
	Classification              string                  `json:"classification"`
	Action                      string                  `json:"action"`
	Surfaces                    []stateWritePolicyItem  `json:"surfaces"`
	Summary                     stateWritePolicySummary `json:"summary"`
	MutationPerformed           bool                    `json:"mutation_performed"`
	MigrationPerformed          bool                    `json:"migration_performed"`
	RepairPerformed             bool                    `json:"repair_performed"`
	StateRelocationPerformed    bool                    `json:"state_relocation_performed"`
	RuntimeWriterRewired        bool                    `json:"runtime_writer_rewired"`
	DestructiveCleanupPerformed bool                    `json:"destructive_cleanup_performed"`
	CleanupImplemented          bool                    `json:"cleanup_implemented"`
	NoSilentMigration           bool                    `json:"no_silent_migration"`
	NoSilentRepair              bool                    `json:"no_silent_repair"`
	TrustOrCandidateMutation    bool                    `json:"trust_or_candidate_state_mutated"`
	VerifiedIdentityClaimed     bool                    `json:"verified_identity_claimed"`
	CypherMLSReconciled         bool                    `json:"cypher_mls_reconciled"`
	VaultClaimed                bool                    `json:"vault_claimed"`
	BackupRestoreClaimed        bool                    `json:"backup_restore_claimed"`
	DeploymentClaimed           bool                    `json:"deployment_claimed"`
	FullRuntimeDevPromoted      bool                    `json:"full_runtime_dev_promoted"`
	GateDStarted                bool                    `json:"gate_d_started"`
	Notes                       []string                `json:"notes,omitempty"`
}

type stateWritePolicyItem struct {
	ID                     string   `json:"id"`
	SourcePath             string   `json:"source_path"`
	AuthorityDomain        string   `json:"authority_domain"`
	StateClass             string   `json:"state_class"`
	WriterClass            string   `json:"writer_class"`
	LockDiscipline         string   `json:"lock_discipline"`
	AtomicityDiscipline    string   `json:"atomicity_discipline"`
	PartialStateSemantics  string   `json:"partial_state_semantics"`
	ReplaySemantics        string   `json:"replay_semantics"`
	CleanupBoundary        string   `json:"cleanup_boundary"`
	Action                 string   `json:"action"`
	FutureHardeningWarning bool     `json:"future_hardening_warning"`
	CurrentClosureEvidence bool     `json:"current_closure_evidence"`
	RuntimeWriterRewired   bool     `json:"runtime_writer_rewired"`
	MutationPerformedByC4  bool     `json:"mutation_performed_by_c4"`
	MigrationPerformedByC4 bool     `json:"migration_performed_by_c4"`
	RepairPerformedByC4    bool     `json:"repair_performed_by_c4"`
	Notes                  []string `json:"notes,omitempty"`
}

type stateWritePolicySummary struct {
	TotalSurfaces               int            `json:"total_surfaces"`
	ClassifySurfaces            int            `json:"classify_surfaces"`
	AllowSurfaces               int            `json:"allow_surfaces"`
	RefuseSurfaces              int            `json:"refuse_surfaces"`
	FutureHardeningWarnings     int            `json:"future_hardening_warnings"`
	CurrentClosureEvidence      int            `json:"current_closure_evidence"`
	WriterClassCounts           map[string]int `json:"writer_class_counts"`
	LockDisciplineCounts        map[string]int `json:"lock_discipline_counts"`
	AtomicityDisciplineCounts   map[string]int `json:"atomicity_discipline_counts"`
	AuthorityDomainCounts       map[string]int `json:"authority_domain_counts"`
	ReplaySemanticsCounts       map[string]int `json:"replay_semantics_counts"`
	PartialStateSemanticsCounts map[string]int `json:"partial_state_semantics_counts"`
}

func cmdStateWritePolicyDev(args []string) error {
	fs := flag.NewFlagSet("state-write-policy-dev", flag.ContinueOnError)
	stateRoot := fs.String("state-root", ".carbonstack-comms", "Comms-owned state root to use when describing policy")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory to classify as sidecar-owned")
	cypherDBPath := fs.String("cypher-db", "", "optional Cypher DB path to classify as Cypher-owned")
	validatorTempRoot := fs.String("validator-temp-root", "", "optional validator temp root to classify as generated validation state")
	evidenceRoot := fs.String("evidence-root", "", "optional evidence root to classify as evidence-only")
	outputPath := fs.String("output", "", "optional machine-readable write-policy report path; generated evidence only")
	if err := fs.Parse(args); err != nil {
		return err
	}

	report := evaluateStateWritePolicy(stateWritePolicyInput{
		StateRoot:         *stateRoot,
		SidecarDir:        *sidecarDir,
		CypherDBPath:      *cypherDBPath,
		ValidatorTempRoot: *validatorTempRoot,
		EvidenceRoot:      *evidenceRoot,
		OutputPath:        *outputPath,
	})

	if report.OutputPath != "" {
		if err := writeStateWritePolicyReportAtomic(report.OutputPath, report); err != nil {
			return err
		}
	}

	printStateWritePolicyReport(report)
	return nil
}

func evaluateStateWritePolicy(input stateWritePolicyInput) stateWritePolicyReport {
	stateRoot := strings.TrimSpace(input.StateRoot)
	if stateRoot == "" {
		stateRoot = ".carbonstack-comms"
	}
	sidecarDir := strings.TrimSpace(input.SidecarDir)
	if sidecarDir == "" || sidecarDir == "." {
		sidecarDir = defaultOpenMLSSidecarDir
	}

	report := stateWritePolicyReport{
		SchemaVersion:               stateWritePolicyReportSchema,
		Command:                     "state-write-policy-dev",
		CreatedAt:                   time.Now().UTC().Format(time.RFC3339),
		StateRoot:                   filepath.Clean(stateRoot),
		SidecarDir:                  filepath.Clean(sidecarDir),
		CypherDBPath:                strings.TrimSpace(input.CypherDBPath),
		ValidatorTempRoot:           strings.TrimSpace(input.ValidatorTempRoot),
		EvidenceRoot:                strings.TrimSpace(input.EvidenceRoot),
		OutputPath:                  strings.TrimSpace(input.OutputPath),
		Classification:              "write_policy_classified",
		Action:                      "classify",
		MutationPerformed:           false,
		MigrationPerformed:          false,
		RepairPerformed:             false,
		StateRelocationPerformed:    false,
		RuntimeWriterRewired:        false,
		DestructiveCleanupPerformed: false,
		CleanupImplemented:          false,
		NoSilentMigration:           true,
		NoSilentRepair:              true,
		TrustOrCandidateMutation:    false,
		VerifiedIdentityClaimed:     false,
		CypherMLSReconciled:         false,
		VaultClaimed:                false,
		BackupRestoreClaimed:        false,
		DeploymentClaimed:           false,
		FullRuntimeDevPromoted:      false,
		GateDStarted:                false,
		Notes: []string{
			"C4 classifies write discipline and replay/partial-state policy; it does not rewrite runtime writers.",
		},
	}

	report.Surfaces = defaultStateWritePolicySurfaces(report.StateRoot, report.SidecarDir, report.CypherDBPath, report.ValidatorTempRoot, report.EvidenceRoot)
	sort.SliceStable(report.Surfaces, func(i, j int) bool {
		return report.Surfaces[i].ID < report.Surfaces[j].ID
	})
	report.Summary = summarizeStateWritePolicy(report.Surfaces)
	return report
}

func defaultStateWritePolicySurfaces(stateRoot, sidecarDir, cypherDBPath, validatorTempRoot, evidenceRoot string) []stateWritePolicyItem {
	items := []stateWritePolicyItem{
		{
			ID:                     "c1.state_substrate_inventory_report",
			SourcePath:             "carbonstack-comms/internal/app/state_substrate_inventory_dev.go",
			AuthorityDomain:        "comms_owned_generated_evidence",
			StateClass:             "state_inventory_report",
			WriterClass:            "generated_evidence_writer",
			LockDiscipline:         "no_lock_required_generated_report",
			AtomicityDiscipline:    "atomic_temp_write_then_rename",
			PartialStateSemantics:  "report_is_evidence_only_no_runtime_partial_state",
			ReplaySemantics:        "rerun_regenerates_report",
			CleanupBoundary:        "operator_generated_evidence_only",
			Action:                 "classify",
			CurrentClosureEvidence: true,
			Notes: []string{
				"C1 report writer uses temporary file and rename; no runtime state mutation claim.",
			},
		},
		{
			ID:                     "c2.state_schema_compatibility_report",
			SourcePath:             "carbonstack-comms/internal/app/state_schema_compat_dev.go",
			AuthorityDomain:        "comms_owned_generated_evidence",
			StateClass:             "schema_compatibility_report",
			WriterClass:            "generated_evidence_writer",
			LockDiscipline:         "no_lock_required_generated_report",
			AtomicityDiscipline:    "atomic_temp_write_then_rename",
			PartialStateSemantics:  "report_is_evidence_only_no_runtime_partial_state",
			ReplaySemantics:        "rerun_regenerates_report",
			CleanupBoundary:        "operator_generated_evidence_only",
			Action:                 "classify",
			CurrentClosureEvidence: true,
		},
		{
			ID:                     "c3.state_path_policy_report",
			SourcePath:             "carbonstack-comms/internal/app/state_path_policy_dev.go",
			AuthorityDomain:        "comms_owned_generated_evidence",
			StateClass:             "path_policy_report",
			WriterClass:            "generated_evidence_writer",
			LockDiscipline:         "no_lock_required_generated_report",
			AtomicityDiscipline:    "atomic_temp_write_then_rename",
			PartialStateSemantics:  "report_is_evidence_only_no_runtime_partial_state",
			ReplaySemantics:        "rerun_regenerates_report",
			CleanupBoundary:        "operator_generated_evidence_only",
			Action:                 "classify",
			CurrentClosureEvidence: true,
		},
		{
			ID:                     "b5d.keypackage_consume_receipt",
			SourcePath:             "carbonstack-comms/internal/app/openmls_keypackage_consume_dev.go",
			AuthorityDomain:        "comms_owned",
			StateClass:             "keypackage_consume_receipt",
			WriterClass:            "atomic_receipt_writer",
			LockDiscipline:         "lock_guarded_writer",
			AtomicityDiscipline:    "atomic_temp_write_then_rename",
			PartialStateSemantics:  "persisted_before_ack; ack_failure_leaves_local_receipt",
			ReplaySemantics:        "exact_replay_from_local_receipt_already_consumed",
			CleanupBoundary:        "do_not_delete_runtime_receipts_as_generated_artifacts",
			Action:                 "classify",
			CurrentClosureEvidence: true,
			Notes: []string{
				"C4 classifies existing B5d behavior; it does not change ACK or receipt writers.",
			},
		},
		{
			ID:                     "b6.welcome_consume_receipt",
			SourcePath:             "carbonstack-comms/internal/app/openmls_welcome_lifecycle_dev.go",
			AuthorityDomain:        "comms_owned",
			StateClass:             "welcome_consume_receipt",
			WriterClass:            "atomic_receipt_writer",
			LockDiscipline:         "lock_guarded_writer",
			AtomicityDiscipline:    "atomic_temp_write_then_rename",
			PartialStateSemantics:  "welcome_persisted_before_join; joined_evidence_before_ack; failed_join_leaves_unacked_receipt",
			ReplaySemantics:        "exact_replay_from_local_receipt_already_joined",
			CleanupBoundary:        "do_not_delete_runtime_receipts_as_generated_artifacts",
			Action:                 "classify",
			CurrentClosureEvidence: true,
		},
		{
			ID:                     "b8.workflow_relay_onboarding_report",
			SourcePath:             "carbonstack-comms/internal/app/workflow_relay_onboarding_dev.go",
			AuthorityDomain:        "comms_owned",
			StateClass:             "workflow_onboarding_report",
			WriterClass:            "atomic_json_report_writer",
			LockDiscipline:         "report_idempotence_without_global_lock",
			AtomicityDiscipline:    "atomic_temp_write_then_rename",
			PartialStateSemantics:  "stage_classification_preserves_partial_workflow_state",
			ReplaySemantics:        "exact_replay_from_local_report_already_reported",
			CleanupBoundary:        "do_not_delete_workflow_reports_as_generated_artifacts",
			Action:                 "classify",
			CurrentClosureEvidence: true,
		},
		{
			ID:                     "comms.local_state_file",
			SourcePath:             "carbonstack-comms/internal/state/state.go",
			AuthorityDomain:        "comms_owned",
			StateClass:             "local_comms_state",
			WriterClass:            "direct_state_writer",
			LockDiscipline:         "unknown_or_not_c4_closed",
			AtomicityDiscipline:    "direct_write_current_behavior",
			PartialStateSemantics:  "legacy_local_state_surface_classified",
			ReplaySemantics:        "not_a_replay_surface",
			CleanupBoundary:        "do_not_delete_runtime_state",
			Action:                 "classify",
			FutureHardeningWarning: true,
			Notes: []string{
				"C4 classifies direct state writes as future-hardening warnings rather than rewriting them in this subgate.",
			},
		},
		{
			ID:                     "comms.trust_store",
			SourcePath:             "carbonstack-comms/internal/trust/trust.go",
			AuthorityDomain:        "comms_owned",
			StateClass:             "trust_state",
			WriterClass:            "direct_state_writer_and_append_jsonl",
			LockDiscipline:         "unknown_or_not_c4_closed",
			AtomicityDiscipline:    "direct_write_and_append_current_behavior",
			PartialStateSemantics:  "trust_state_classified_not_promoted",
			ReplaySemantics:        "not_a_replay_surface",
			CleanupBoundary:        "do_not_delete_trust_state",
			Action:                 "classify",
			FutureHardeningWarning: true,
			Notes: []string{
				"C4 does not mutate trust or candidate state and does not claim verified identity.",
			},
		},
		{
			ID:                     "comms.identity_candidates",
			SourcePath:             "carbonstack-comms/internal/trust/identity_candidates.go",
			AuthorityDomain:        "comms_owned",
			StateClass:             "identity_candidate_state",
			WriterClass:            "direct_state_writer",
			LockDiscipline:         "unknown_or_not_c4_closed",
			AtomicityDiscipline:    "direct_write_current_behavior",
			PartialStateSemantics:  "candidate_state_classified_not_promoted",
			ReplaySemantics:        "not_a_replay_surface",
			CleanupBoundary:        "do_not_delete_candidate_state",
			Action:                 "classify",
			FutureHardeningWarning: true,
		},
		{
			ID:                     "validator.clean_generated",
			SourcePath:             "carbonstack/tools/carbonstack-validate",
			AuthorityDomain:        "validator_generated",
			StateClass:             "known_generated_artifact_cleanup",
			WriterClass:            "generated_artifact_cleanup_classifier",
			LockDiscipline:         "not_runtime_state",
			AtomicityDiscipline:    "not_applicable",
			PartialStateSemantics:  "not_runtime_state",
			ReplaySemantics:        "not_a_replay_surface",
			CleanupBoundary:        "explicit_clean_generated_only_known_roots",
			Action:                 "classify",
			CurrentClosureEvidence: true,
			Notes: []string{
				"Cleanup remains explicit and scoped to known generated/build artifact roots.",
			},
		},
		{
			ID:                     "sidecar.generated_state",
			SourcePath:             filepath.Join(sidecarDir, ".carbonstack-openmls-sidecar-state"),
			AuthorityDomain:        "sidecar_owned",
			StateClass:             "openmls_sidecar_generated_state",
			WriterClass:            "external_sidecar_owned",
			LockDiscipline:         "sidecar_owned",
			AtomicityDiscipline:    "sidecar_owned",
			PartialStateSemantics:  "sidecar_cryptographic_state_classified_only",
			ReplaySemantics:        "sidecar_owned",
			CleanupBoundary:        "explicit_known_generated_root_only",
			Action:                 "classify",
			CurrentClosureEvidence: true,
		},
		{
			ID:                     "cypher.database",
			SourcePath:             cypherDBPath,
			AuthorityDomain:        "cypher_owned",
			StateClass:             "server_database",
			WriterClass:            "external_cypher_owned",
			LockDiscipline:         "cypher_db_transaction_owned",
			AtomicityDiscipline:    "cypher_migrations_and_db_transactions_own_policy",
			PartialStateSemantics:  "server_state_classified_only",
			ReplaySemantics:        "not_comms_local_replay_surface",
			CleanupBoundary:        "do_not_delete_cypher_database_as_generated_artifact",
			Action:                 "classify",
			CurrentClosureEvidence: true,
		},
	}

	if validatorTempRoot != "" {
		items = append(items, stateWritePolicyItem{
			ID:                     "validator.temp_root",
			SourcePath:             validatorTempRoot,
			AuthorityDomain:        "validator_generated",
			StateClass:             "validator_temp_root",
			WriterClass:            "generated_evidence_writer",
			LockDiscipline:         "not_runtime_state",
			AtomicityDiscipline:    "not_runtime_state",
			PartialStateSemantics:  "not_runtime_state",
			ReplaySemantics:        "not_a_replay_surface",
			CleanupBoundary:        "explicit_clean_generated_or_temp_cleanup_only",
			Action:                 "classify",
			CurrentClosureEvidence: true,
		})
	}

	if evidenceRoot != "" {
		items = append(items, stateWritePolicyItem{
			ID:                     "evidence.root",
			SourcePath:             evidenceRoot,
			AuthorityDomain:        "evidence_generated",
			StateClass:             "operator_evidence_root",
			WriterClass:            "generated_evidence_writer",
			LockDiscipline:         "not_runtime_state",
			AtomicityDiscipline:    "not_runtime_state",
			PartialStateSemantics:  "not_runtime_state",
			ReplaySemantics:        "not_a_replay_surface",
			CleanupBoundary:        "operator_controlled_evidence",
			Action:                 "classify",
			CurrentClosureEvidence: true,
		})
	}

	return items
}

func summarizeStateWritePolicy(items []stateWritePolicyItem) stateWritePolicySummary {
	summary := stateWritePolicySummary{
		TotalSurfaces:               len(items),
		WriterClassCounts:           map[string]int{},
		LockDisciplineCounts:        map[string]int{},
		AtomicityDisciplineCounts:   map[string]int{},
		AuthorityDomainCounts:       map[string]int{},
		ReplaySemanticsCounts:       map[string]int{},
		PartialStateSemanticsCounts: map[string]int{},
	}
	for _, item := range items {
		switch item.Action {
		case "allow":
			summary.AllowSurfaces++
		case "refuse":
			summary.RefuseSurfaces++
		default:
			summary.ClassifySurfaces++
		}
		if item.FutureHardeningWarning {
			summary.FutureHardeningWarnings++
		}
		if item.CurrentClosureEvidence {
			summary.CurrentClosureEvidence++
		}
		summary.WriterClassCounts[item.WriterClass]++
		summary.LockDisciplineCounts[item.LockDiscipline]++
		summary.AtomicityDisciplineCounts[item.AtomicityDiscipline]++
		summary.AuthorityDomainCounts[item.AuthorityDomain]++
		summary.ReplaySemanticsCounts[item.ReplaySemantics]++
		summary.PartialStateSemanticsCounts[item.PartialStateSemantics]++
	}
	return summary
}

func writeStateWritePolicyReportAtomic(path string, report stateWritePolicyReport) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func printStateWritePolicyReport(report stateWritePolicyReport) {
	fmt.Println("state write policy dev")
	fmt.Println("command: state-write-policy-dev")
	fmt.Printf("schema_version: %s\n", report.SchemaVersion)
	fmt.Printf("state_root: %s\n", report.StateRoot)
	fmt.Printf("sidecar_dir: %s\n", report.SidecarDir)
	if report.CypherDBPath != "" {
		fmt.Printf("cypher_db_path: %s\n", report.CypherDBPath)
	}
	if report.OutputPath != "" {
		fmt.Printf("output_path: %s\n", report.OutputPath)
	}
	fmt.Printf("classification: %s\n", report.Classification)
	fmt.Printf("action: %s\n", report.Action)
	fmt.Printf("total_surfaces: %d\n", report.Summary.TotalSurfaces)
	fmt.Printf("classify_surfaces: %d\n", report.Summary.ClassifySurfaces)
	fmt.Printf("future_hardening_warnings: %d\n", report.Summary.FutureHardeningWarnings)
	fmt.Printf("current_closure_evidence: %d\n", report.Summary.CurrentClosureEvidence)
	for _, item := range report.Surfaces {
		fmt.Printf("surface: %s writer=%s lock=%s atomicity=%s partial=%s replay=%s action=%s future_warning=%t\n", item.ID, item.WriterClass, item.LockDiscipline, item.AtomicityDiscipline, item.PartialStateSemantics, item.ReplaySemantics, item.Action, item.FutureHardeningWarning)
	}
	fmt.Printf("runtime_writer_rewired: %t\n", report.RuntimeWriterRewired)
	fmt.Printf("destructive_cleanup_performed: %t\n", report.DestructiveCleanupPerformed)
	fmt.Printf("cleanup_implemented: %t\n", report.CleanupImplemented)
	fmt.Printf("state_relocation_performed: %t\n", report.StateRelocationPerformed)
	fmt.Printf("migration_performed: %t\n", report.MigrationPerformed)
	fmt.Printf("repair_performed: %t\n", report.RepairPerformed)
	fmt.Printf("no_silent_migration: %t\n", report.NoSilentMigration)
	fmt.Printf("no_silent_repair: %t\n", report.NoSilentRepair)
	fmt.Printf("trust_or_candidate_state_mutated: %t\n", report.TrustOrCandidateMutation)
	fmt.Printf("verified_identity_claimed: %t\n", report.VerifiedIdentityClaimed)
	fmt.Printf("cypher_mls_reconciled: %t\n", report.CypherMLSReconciled)
	fmt.Printf("vault_claimed: %t\n", report.VaultClaimed)
	fmt.Printf("backup_restore_claimed: %t\n", report.BackupRestoreClaimed)
	fmt.Printf("deployment_claimed: %t\n", report.DeploymentClaimed)
	fmt.Printf("full_runtime_dev_promoted: %t\n", report.FullRuntimeDevPromoted)
	fmt.Printf("gate_d_started: %t\n", report.GateDStarted)
	fmt.Println("warning: dev/pre-alpha write-policy classification only; no migration, repair, relocation, cleanup, writer rewiring, trust promotion, verified identity, vault, backup/restore, deployment, full-runtime-dev, or Gate D claim")
}
