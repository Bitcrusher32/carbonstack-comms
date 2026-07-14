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

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

const statePathPolicyReportSchema = "carbonstack-state-path-policy-report/v0"

type statePathPolicyInput struct {
	StatePath            string
	StateRoot            string
	SidecarDir           string
	CypherDBPath         string
	ValidatorTempRoot    string
	EvidenceRoot         string
	OutputPath           string
	AllowRefusalExitZero bool
}

type statePathPolicyReport struct {
	SchemaVersion                  string                 `json:"schema_version"`
	Command                        string                 `json:"command"`
	CreatedAt                      string                 `json:"created_at"`
	StatePath                      string                 `json:"state_path"`
	StateRoot                      string                 `json:"state_root"`
	StateRootSource                string                 `json:"state_root_source"`
	DerivedRootFromState           string                 `json:"derived_root_from_state"`
	CanonicalPreferredRoot         string                 `json:"canonical_preferred_root"`
	CanonicalRootPolicy            string                 `json:"canonical_root_policy"`
	StateRootRelationship          string                 `json:"state_root_relationship"`
	SidecarDir                     string                 `json:"sidecar_dir"`
	CypherDBPath                   string                 `json:"cypher_db_path,omitempty"`
	ValidatorTempRoot              string                 `json:"validator_temp_root,omitempty"`
	EvidenceRoot                   string                 `json:"evidence_root,omitempty"`
	OutputPath                     string                 `json:"output_path,omitempty"`
	Classification                 string                 `json:"classification"`
	Action                         string                 `json:"action"`
	Items                          []statePathPolicyItem  `json:"items"`
	Summary                        statePathPolicySummary `json:"summary"`
	ExplicitStateCompatibility     bool                   `json:"explicit_state_compatibility"`
	CanonicalRootBrittleChokepoint bool                   `json:"canonical_root_brittle_chokepoint"`
	DerivedSiblingRootsSupported   bool                   `json:"derived_sibling_roots_supported"`
	SidecarClassifiedOnly          bool                   `json:"sidecar_classified_only"`
	CypherClassifiedOnly           bool                   `json:"cypher_classified_only"`
	CleanupImplemented             bool                   `json:"cleanup_implemented"`
	StateRelocationPerformed       bool                   `json:"state_relocation_performed"`
	MigrationPerformed             bool                   `json:"migration_performed"`
	RepairPerformed                bool                   `json:"repair_performed"`
	NoSilentMigration              bool                   `json:"no_silent_migration"`
	NoSilentRepair                 bool                   `json:"no_silent_repair"`
	TrustOrCandidateMutation       bool                   `json:"trust_or_candidate_state_mutated"`
	VerifiedIdentityClaimed        bool                   `json:"verified_identity_claimed"`
	CypherMLSReconciled            bool                   `json:"cypher_mls_reconciled"`
	VaultClaimed                   bool                   `json:"vault_claimed"`
	BackupRestoreClaimed           bool                   `json:"backup_restore_claimed"`
	DeploymentClaimed              bool                   `json:"deployment_claimed"`
	FullRuntimeDevPromoted         bool                   `json:"full_runtime_dev_promoted"`
	GateDStarted                   bool                   `json:"gate_d_started"`
	Notes                          []string               `json:"notes,omitempty"`
}

type statePathPolicyItem struct {
	ID                  string   `json:"id"`
	Path                string   `json:"path,omitempty"`
	PathKind            string   `json:"path_kind"`
	AuthorityDomain     string   `json:"authority_domain"`
	Owner               string   `json:"owner"`
	Classification      string   `json:"classification"`
	Action              string   `json:"action"`
	RootRelation        string   `json:"root_relation"`
	MutationPolicy      string   `json:"mutation_policy"`
	CleanupPolicy       string   `json:"cleanup_policy"`
	CompatibilityPolicy string   `json:"compatibility_policy"`
	Exists              bool     `json:"exists"`
	IsDir               bool     `json:"is_dir"`
	UnsafeReason        string   `json:"unsafe_reason,omitempty"`
	Notes               []string `json:"notes,omitempty"`
}

type statePathPolicySummary struct {
	TotalItems            int            `json:"total_items"`
	AllowItems            int            `json:"allow_items"`
	ClassifyItems         int            `json:"classify_items"`
	RefuseItems           int            `json:"refuse_items"`
	ExistingItems         int            `json:"existing_items"`
	AuthorityDomainCounts map[string]int `json:"authority_domain_counts"`
	ClassificationCounts  map[string]int `json:"classification_counts"`
	ActionCounts          map[string]int `json:"action_counts"`
}

func cmdStatePathPolicyDev(args []string) error {
	fs := flag.NewFlagSet("state-path-policy-dev", flag.ContinueOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local Comms state path; explicit compatibility is preserved")
	stateRoot := fs.String("state-root", "", "optional Comms-owned root override for path-policy classification")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory to classify as sidecar-owned")
	cypherDBPath := fs.String("cypher-db", "", "optional Cypher DB path to classify as Cypher-owned")
	validatorTempRoot := fs.String("validator-temp-root", "", "optional validator temp root to classify as generated")
	evidenceRoot := fs.String("evidence-root", "", "optional evidence root to classify as evidence-only")
	outputPath := fs.String("output", "", "optional machine-readable path-policy report path; generated evidence only")
	allowRefusalExitZero := fs.Bool("allow-refusal-exit-zero", false, "print refusal classification but exit zero for validation/profiling")
	if err := fs.Parse(args); err != nil {
		return err
	}

	report := evaluateStatePathPolicy(statePathPolicyInput{
		StatePath:            *statePath,
		StateRoot:            *stateRoot,
		SidecarDir:           *sidecarDir,
		CypherDBPath:         *cypherDBPath,
		ValidatorTempRoot:    *validatorTempRoot,
		EvidenceRoot:         *evidenceRoot,
		OutputPath:           *outputPath,
		AllowRefusalExitZero: *allowRefusalExitZero,
	})

	if report.OutputPath != "" {
		if err := writeStatePathPolicyReportAtomic(report.OutputPath, report); err != nil {
			return err
		}
	}

	printStatePathPolicyReport(report)

	if report.Action == "refuse" && !*allowRefusalExitZero {
		return fmt.Errorf("state_path_policy_refused: classification=%s state=%s state_root=%s", report.Classification, report.StatePath, report.StateRoot)
	}
	return nil
}

func evaluateStatePathPolicy(input statePathPolicyInput) statePathPolicyReport {
	statePath := strings.TrimSpace(input.StatePath)
	if statePath == "" {
		statePath = state.DefaultStatePath
	}
	statePath = filepath.Clean(statePath)

	derivedRoot := deriveStatePathPolicyRootFromStatePath(statePath)
	stateRoot := strings.TrimSpace(input.StateRoot)
	stateRootSource := "explicit"
	if stateRoot == "" {
		stateRoot = derivedRoot
		stateRootSource = "derived_from_state_path"
	} else {
		stateRoot = filepath.Clean(stateRoot)
	}

	report := statePathPolicyReport{
		SchemaVersion:                  statePathPolicyReportSchema,
		Command:                        "state-path-policy-dev",
		CreatedAt:                      time.Now().UTC().Format(time.RFC3339),
		StatePath:                      statePath,
		StateRoot:                      stateRoot,
		StateRootSource:                stateRootSource,
		DerivedRootFromState:           derivedRoot,
		CanonicalPreferredRoot:         ".carbonstack-comms",
		CanonicalRootPolicy:            "preferred_policy_anchor_not_brittle_chokepoint",
		SidecarDir:                     filepath.Clean(strings.TrimSpace(input.SidecarDir)),
		CypherDBPath:                   strings.TrimSpace(input.CypherDBPath),
		ValidatorTempRoot:              strings.TrimSpace(input.ValidatorTempRoot),
		EvidenceRoot:                   strings.TrimSpace(input.EvidenceRoot),
		OutputPath:                     strings.TrimSpace(input.OutputPath),
		Classification:                 "path_policy_classified",
		Action:                         "allow",
		ExplicitStateCompatibility:     true,
		CanonicalRootBrittleChokepoint: false,
		DerivedSiblingRootsSupported:   true,
		SidecarClassifiedOnly:          true,
		CypherClassifiedOnly:           true,
		CleanupImplemented:             false,
		StateRelocationPerformed:       false,
		MigrationPerformed:             false,
		RepairPerformed:                false,
		NoSilentMigration:              true,
		NoSilentRepair:                 true,
		TrustOrCandidateMutation:       false,
		VerifiedIdentityClaimed:        false,
		CypherMLSReconciled:            false,
		VaultClaimed:                   false,
		BackupRestoreClaimed:           false,
		DeploymentClaimed:              false,
		FullRuntimeDevPromoted:         false,
		GateDStarted:                   false,
	}

	if report.SidecarDir == "" || report.SidecarDir == "." {
		report.SidecarDir = defaultOpenMLSSidecarDir
	}

	report.StateRootRelationship = classifyStateRootRelationship(stateRoot, derivedRoot)
	if report.StateRootRelationship == "explicit_root_differs_from_state_directory" {
		report.Classification = "explicit_state_root_override_classified"
		report.Action = "classify"
		report.Notes = append(report.Notes, "explicit --state-root differs from the directory beside --state; C3 classifies this rather than refusing to avoid brittle inspection")
	}

	add := func(item statePathPolicyItem) {
		report.Items = append(report.Items, inspectStatePathPolicyItem(item, stateRoot, derivedRoot))
	}

	add(statePathPolicyItem{
		ID:                  "comms.state_file",
		Path:                statePath,
		PathKind:            "json_file",
		AuthorityDomain:     "comms_owned",
		Owner:               "carbonstack-comms/internal/state",
		Classification:      "local_comms_state_file",
		RootRelation:        "state_path",
		Action:              "allow",
		MutationPolicy:      "not_mutated_by_c3",
		CleanupPolicy:       "do_not_delete_as_generated_artifact",
		CompatibilityPolicy: "C2 classifies schema compatibility separately",
	})

	add(statePathPolicyItem{
		ID:                  "comms.state_root",
		Path:                stateRoot,
		PathKind:            "directory",
		AuthorityDomain:     "comms_owned",
		Owner:               "carbonstack-comms",
		Classification:      "comms_state_root_policy_anchor",
		RootRelation:        report.StateRootRelationship,
		Action:              actionForStateRootRelationship(report.StateRootRelationship),
		MutationPolicy:      "not_mutated_by_c3",
		CleanupPolicy:       "do_not_delete_as_generated_artifact",
		CompatibilityPolicy: "explicit --state compatibility preserved",
		Notes: []string{
			"Canonical root is preferred policy, not mandatory layout enforcement.",
		},
	})

	for _, child := range []struct {
		id             string
		name           string
		classification string
		owner          string
		pathKind       string
	}{
		{"comms.trust_records", "trust.json", "trust_store_path", "carbonstack-comms/internal/trust", "json_file"},
		{"comms.trust_events", "trust-events.jsonl", "trust_history_path", "carbonstack-comms/internal/trust", "jsonl_file"},
		{"comms.identity_candidates", "identity-candidates.json", "identity_candidate_store_path", "carbonstack-comms/internal/trust", "json_file"},
		{"comms.keypackage_receipt_root", "keypackage-receipts", "keypackage_receipt_root", "openmls-relay-keypackage-consume-dev", "directory"},
		{"comms.welcome_receipt_root", "welcome-receipts", "welcome_receipt_root", "openmls-relay-welcome-consume-dev", "directory"},
		{"comms.workflow_report_root", "workflow-reports", "workflow_report_root", "workflow-relay-onboarding-dev", "directory"},
	} {
		add(statePathPolicyItem{
			ID:                  child.id,
			Path:                filepath.Join(stateRoot, child.name),
			PathKind:            child.pathKind,
			AuthorityDomain:     "comms_owned",
			Owner:               child.owner,
			Classification:      child.classification,
			RootRelation:        "under_comms_state_root",
			Action:              "allow",
			MutationPolicy:      "not_mutated_by_c3",
			CleanupPolicy:       "do_not_delete_as_generated_artifact",
			CompatibilityPolicy: "C2/C4/C5 decide runtime enforcement depth",
		})
	}

	add(statePathPolicyItem{
		ID:                  "sidecar.project_dir",
		Path:                report.SidecarDir,
		PathKind:            "directory",
		AuthorityDomain:     "sidecar_owned",
		Owner:               "openmls-sidecar",
		Classification:      "sidecar_project_boundary",
		RootRelation:        "external_authority",
		Action:              "classify",
		MutationPolicy:      "classify_only_no_rewrite",
		CleanupPolicy:       "do not clean except explicit known generated roots",
		CompatibilityPolicy: "sidecar owns cryptographic state compatibility",
	})

	add(statePathPolicyItem{
		ID:                  "sidecar.generated_state_root",
		Path:                filepath.Join(report.SidecarDir, ".carbonstack-openmls-sidecar-state"),
		PathKind:            "directory",
		AuthorityDomain:     "sidecar_owned",
		Owner:               "openmls-sidecar",
		Classification:      "sidecar_generated_state_root",
		RootRelation:        "external_authority",
		Action:              "classify",
		MutationPolicy:      "classify_only_no_rewrite",
		CleanupPolicy:       "known generated root; clean only through explicit clean-generated tooling",
		CompatibilityPolicy: "sidecar owns cryptographic state compatibility",
	})

	if report.CypherDBPath != "" {
		add(statePathPolicyItem{
			ID:                  "cypher.database",
			Path:                filepath.Clean(report.CypherDBPath),
			PathKind:            "sqlite_file",
			AuthorityDomain:     "cypher_owned",
			Owner:               "carbonstack-cypher",
			Classification:      "cypher_server_database",
			RootRelation:        "external_authority",
			Action:              "classify",
			MutationPolicy:      "classify_only_no_schema_migration",
			CleanupPolicy:       "do_not_delete_as_generated_artifact",
			CompatibilityPolicy: "Cypher migrations own DB compatibility",
		})
	}

	if report.ValidatorTempRoot != "" {
		add(statePathPolicyItem{
			ID:                  "validator.temp_root",
			Path:                filepath.Clean(report.ValidatorTempRoot),
			PathKind:            "directory",
			AuthorityDomain:     "validator_generated",
			Owner:               "tools/carbonstack-validate",
			Classification:      "validator_temp_root",
			RootRelation:        "generated_evidence",
			Action:              "classify",
			MutationPolicy:      "generated_by_validation_only",
			CleanupPolicy:       "explicit clean-generated scope only",
			CompatibilityPolicy: "not runtime state authority",
		})
	}

	if report.EvidenceRoot != "" {
		add(statePathPolicyItem{
			ID:                  "evidence.root",
			Path:                filepath.Clean(report.EvidenceRoot),
			PathKind:            "directory",
			AuthorityDomain:     "evidence_generated",
			Owner:               "operator_evidence_workflow",
			Classification:      "external_evidence_root",
			RootRelation:        "evidence_only",
			Action:              "classify",
			MutationPolicy:      "not_runtime_state",
			CleanupPolicy:       "operator controlled",
			CompatibilityPolicy: "not runtime compatibility authority",
		})
	}

	sort.SliceStable(report.Items, func(i, j int) bool { return report.Items[i].ID < report.Items[j].ID })
	report.Summary = summarizeStatePathPolicy(report.Items)

	if report.Summary.RefuseItems > 0 {
		report.Action = "refuse"
		report.Classification = "unsafe_path_policy_refused"
	}
	return report
}

func deriveStatePathPolicyRootFromStatePath(statePath string) string {
	dir := filepath.Dir(strings.TrimSpace(statePath))
	if dir == "." || dir == "" {
		return ".carbonstack-comms"
	}
	return filepath.Clean(dir)
}

func classifyStateRootRelationship(stateRoot, derivedRoot string) string {
	if sameCleanPath(stateRoot, derivedRoot) {
		return "derived_from_state_path"
	}
	if filepath.Base(stateRoot) == ".carbonstack-comms" {
		return "explicit_canonical_preferred_root"
	}
	return "explicit_root_differs_from_state_directory"
}

func actionForStateRootRelationship(rel string) string {
	switch rel {
	case "derived_from_state_path", "explicit_canonical_preferred_root":
		return "allow"
	default:
		return "classify"
	}
}

func sameCleanPath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

func inspectStatePathPolicyItem(item statePathPolicyItem, stateRoot, derivedRoot string) statePathPolicyItem {
	item.ID = normalizeStatePathPolicyField(item.ID, "unknown")
	item.PathKind = normalizeStatePathPolicyField(item.PathKind, "unknown")
	item.AuthorityDomain = normalizeStatePathPolicyField(item.AuthorityDomain, "unknown")
	item.Owner = normalizeStatePathPolicyField(item.Owner, "unknown")
	item.Classification = normalizeStatePathPolicyField(item.Classification, "unknown")
	item.RootRelation = normalizeStatePathPolicyField(item.RootRelation, "unknown")
	item.Action = normalizeStatePathPolicyField(item.Action, "classify")
	item.MutationPolicy = normalizeStatePathPolicyField(item.MutationPolicy, "unknown")
	item.CleanupPolicy = normalizeStatePathPolicyField(item.CleanupPolicy, "unknown")
	item.CompatibilityPolicy = normalizeStatePathPolicyField(item.CompatibilityPolicy, "unknown")

	if item.Path != "" {
		item.Path = filepath.Clean(item.Path)
		if reason := unsafePathPolicyReason(item.Path); reason != "" {
			item.Action = "refuse"
			item.UnsafeReason = reason
			item.Notes = append(item.Notes, "unsafe path policy case refused by C3")
		}
		if info, err := os.Stat(item.Path); err == nil {
			item.Exists = true
			item.IsDir = info.IsDir()
		}
	}

	if item.AuthorityDomain != "comms_owned" && item.Action == "allow" {
		item.Action = "classify"
	}
	return item
}

func unsafePathPolicyReason(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "empty_path"
	}
	clean := filepath.Clean(path)
	if clean == "." {
		return "current_directory_path"
	}
	parts := strings.Split(clean, string(os.PathSeparator))
	for _, part := range parts {
		if part == ".." {
			return "parent_traversal"
		}
	}
	if strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "parent_traversal"
	}
	return ""
}

func summarizeStatePathPolicy(items []statePathPolicyItem) statePathPolicySummary {
	summary := statePathPolicySummary{
		TotalItems:            len(items),
		AuthorityDomainCounts: map[string]int{},
		ClassificationCounts:  map[string]int{},
		ActionCounts:          map[string]int{},
	}
	for _, item := range items {
		if item.Exists {
			summary.ExistingItems++
		}
		switch item.Action {
		case "allow":
			summary.AllowItems++
		case "refuse":
			summary.RefuseItems++
		default:
			summary.ClassifyItems++
		}
		summary.AuthorityDomainCounts[item.AuthorityDomain]++
		summary.ClassificationCounts[item.Classification]++
		summary.ActionCounts[item.Action]++
	}
	return summary
}

func normalizeStatePathPolicyField(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func writeStatePathPolicyReportAtomic(path string, report statePathPolicyReport) error {
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

func printStatePathPolicyReport(report statePathPolicyReport) {
	fmt.Println("state path policy dev")
	fmt.Println("command: state-path-policy-dev")
	fmt.Printf("schema_version: %s\n", report.SchemaVersion)
	fmt.Printf("state_path: %s\n", report.StatePath)
	fmt.Printf("state_root: %s\n", report.StateRoot)
	fmt.Printf("state_root_source: %s\n", report.StateRootSource)
	fmt.Printf("derived_root_from_state: %s\n", report.DerivedRootFromState)
	fmt.Printf("canonical_preferred_root: %s\n", report.CanonicalPreferredRoot)
	fmt.Printf("state_root_relationship: %s\n", report.StateRootRelationship)
	fmt.Printf("classification: %s\n", report.Classification)
	fmt.Printf("action: %s\n", report.Action)
	if report.OutputPath != "" {
		fmt.Printf("output_path: %s\n", report.OutputPath)
	}
	fmt.Printf("total_items: %d\n", report.Summary.TotalItems)
	fmt.Printf("allow_items: %d\n", report.Summary.AllowItems)
	fmt.Printf("classify_items: %d\n", report.Summary.ClassifyItems)
	fmt.Printf("refuse_items: %d\n", report.Summary.RefuseItems)
	for _, item := range report.Items {
		fmt.Printf("item: %s authority=%s class=%s action=%s relation=%s path=%s unsafe=%s\n", item.ID, item.AuthorityDomain, item.Classification, item.Action, item.RootRelation, item.Path, item.UnsafeReason)
	}
	fmt.Printf("explicit_state_compatibility: %t\n", report.ExplicitStateCompatibility)
	fmt.Printf("canonical_root_brittle_chokepoint: %t\n", report.CanonicalRootBrittleChokepoint)
	fmt.Printf("derived_sibling_roots_supported: %t\n", report.DerivedSiblingRootsSupported)
	fmt.Printf("sidecar_classified_only: %t\n", report.SidecarClassifiedOnly)
	fmt.Printf("cypher_classified_only: %t\n", report.CypherClassifiedOnly)
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
	fmt.Println("warning: dev/pre-alpha path policy only; no migration, repair, relocation, cleanup, trust promotion, verified identity, vault, backup/restore, deployment, full-runtime-dev, or Gate D claim")
}
