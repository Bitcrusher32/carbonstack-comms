package app

import (
	"crypto/sha256"
	"encoding/hex"
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

const stateSubstrateInventorySchema = "carbonstack-state-substrate-inventory/v0"

type stateSubstrateInventoryInput struct {
	StatePath    string
	StateRoot    string
	SidecarDir   string
	CypherDBPath string
	EvidenceRoot string
	OutputPath   string
}

type stateSubstrateInventoryReport struct {
	SchemaVersion              string                         `json:"schema_version"`
	Command                    string                         `json:"command"`
	CreatedAt                  string                         `json:"created_at"`
	StatePath                  string                         `json:"state_path"`
	StateRoot                  string                         `json:"state_root"`
	StateRootSource            string                         `json:"state_root_source"`
	SidecarDir                 string                         `json:"sidecar_dir"`
	CypherDBPath               string                         `json:"cypher_db_path,omitempty"`
	EvidenceRoot               string                         `json:"evidence_root,omitempty"`
	OutputPath                 string                         `json:"output_path,omitempty"`
	Items                      []stateSubstrateInventoryItem  `json:"items"`
	Summary                    stateSubstrateInventorySummary `json:"summary"`
	CanonicalCommsRootPolicy   string                         `json:"canonical_comms_root_policy"`
	ExplicitStateCompatibility bool                           `json:"explicit_state_compatibility"`
	DeepReconFriendly          bool                           `json:"deep_recon_friendly"`
	NoSilentRepair             bool                           `json:"no_silent_repair"`
	NoSilentMigration          bool                           `json:"no_silent_migration"`
	NoTrustOrCandidateMutation bool                           `json:"no_trust_or_candidate_mutation"`
	VerifiedIdentityClaimed    bool                           `json:"verified_identity_claimed"`
	CypherMLSReconciled        bool                           `json:"cypher_mls_reconciled"`
	VaultClaimed               bool                           `json:"vault_claimed"`
	BackupRestoreClaimed       bool                           `json:"backup_restore_claimed"`
	DeploymentClaimed          bool                           `json:"deployment_claimed"`
	FullRuntimeDevPromoted     bool                           `json:"full_runtime_dev_promoted"`
	GateDStarted               bool                           `json:"gate_d_started"`
}

type stateSubstrateInventoryItem struct {
	ID                  string   `json:"id"`
	AuthorityDomain     string   `json:"authority_domain"`
	Path                string   `json:"path,omitempty"`
	PathKind            string   `json:"path_kind"`
	Expected            bool     `json:"expected"`
	Exists              bool     `json:"exists"`
	IsDir               bool     `json:"is_dir"`
	Classification      string   `json:"classification"`
	StateClass          string   `json:"state_class"`
	Sensitivity         string   `json:"sensitivity"`
	Owner               string   `json:"owner"`
	WriterPolicy        string   `json:"writer_policy"`
	MutationPolicy      string   `json:"mutation_policy"`
	CleanupPolicy       string   `json:"cleanup_policy"`
	CompatibilityPolicy string   `json:"compatibility_policy"`
	SchemaVersion       string   `json:"schema_version,omitempty"`
	SchemaStatus        string   `json:"schema_status"`
	SupportedSchema     bool     `json:"supported_schema"`
	Notes               []string `json:"notes,omitempty"`
}

type stateSubstrateInventorySummary struct {
	TotalItems              int            `json:"total_items"`
	ExistingItems           int            `json:"existing_items"`
	MissingExpectedItems    int            `json:"missing_expected_items"`
	UnsupportedSchemaItems  int            `json:"unsupported_schema_items"`
	LegacyUnversionedItems  int            `json:"legacy_unversioned_items"`
	CommsOwnedItems         int            `json:"comms_owned_items"`
	SidecarOwnedItems       int            `json:"sidecar_owned_items"`
	CypherOwnedItems        int            `json:"cypher_owned_items"`
	ValidatorGeneratedItems int            `json:"validator_generated_items"`
	EvidenceGeneratedItems  int            `json:"evidence_generated_items"`
	ClassificationCounts    map[string]int `json:"classification_counts"`
	AuthorityDomainCounts   map[string]int `json:"authority_domain_counts"`
	SchemaStatusCounts      map[string]int `json:"schema_status_counts"`
}

func cmdStateSubstrateInventoryDev(args []string) error {
	fs := flag.NewFlagSet("state-substrate-inventory-dev", flag.ContinueOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local Comms state path; remains supported and does not require canonical-root migration")
	stateRoot := fs.String("state-root", "", "optional canonical Comms-owned state root override; default derives beside --state")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory to classify as sidecar-owned state")
	cypherDBPath := fs.String("cypher-db", "", "optional Cypher DB path to classify as Cypher-owned server state")
	evidenceRoot := fs.String("evidence-root", "", "optional evidence root to classify as generated evidence, not runtime state")
	outputPath := fs.String("output", "", "optional path for machine-readable inventory report; writing this report is generated evidence only")
	if err := fs.Parse(args); err != nil {
		return err
	}

	input := stateSubstrateInventoryInput{
		StatePath:    strings.TrimSpace(*statePath),
		StateRoot:    strings.TrimSpace(*stateRoot),
		SidecarDir:   strings.TrimSpace(*sidecarDir),
		CypherDBPath: strings.TrimSpace(*cypherDBPath),
		EvidenceRoot: strings.TrimSpace(*evidenceRoot),
		OutputPath:   strings.TrimSpace(*outputPath),
	}

	report, err := evaluateStateSubstrateInventory(input)
	if err != nil {
		return err
	}

	if report.OutputPath != "" {
		if err := writeStateSubstrateInventoryReportAtomic(report.OutputPath, report); err != nil {
			return err
		}
	}

	printStateSubstrateInventoryReport(report)
	return nil
}

func evaluateStateSubstrateInventory(input stateSubstrateInventoryInput) (stateSubstrateInventoryReport, error) {
	statePath := strings.TrimSpace(input.StatePath)
	if statePath == "" {
		statePath = state.DefaultStatePath
	}

	stateRoot := strings.TrimSpace(input.StateRoot)
	stateRootSource := "explicit"
	if stateRoot == "" {
		stateRoot = deriveStateSubstrateRootFromStatePath(statePath)
		stateRootSource = "derived_from_state_path"
	}

	report := stateSubstrateInventoryReport{
		SchemaVersion:              stateSubstrateInventorySchema,
		Command:                    "state-substrate-inventory-dev",
		CreatedAt:                  time.Now().UTC().Format(time.RFC3339),
		StatePath:                  statePath,
		StateRoot:                  stateRoot,
		StateRootSource:            stateRootSource,
		SidecarDir:                 strings.TrimSpace(input.SidecarDir),
		CypherDBPath:               strings.TrimSpace(input.CypherDBPath),
		EvidenceRoot:               strings.TrimSpace(input.EvidenceRoot),
		OutputPath:                 strings.TrimSpace(input.OutputPath),
		CanonicalCommsRootPolicy:   "policy_anchor_not_brittle_chokepoint",
		ExplicitStateCompatibility: true,
		DeepReconFriendly:          true,
		NoSilentRepair:             true,
		NoSilentMigration:          true,
		NoTrustOrCandidateMutation: true,
		VerifiedIdentityClaimed:    false,
		CypherMLSReconciled:        false,
		VaultClaimed:               false,
		BackupRestoreClaimed:       false,
		DeploymentClaimed:          false,
		FullRuntimeDevPromoted:     false,
		GateDStarted:               false,
	}

	add := func(item stateSubstrateInventoryItem) {
		report.Items = append(report.Items, inspectStateSubstrateItem(item))
	}

	add(stateSubstrateInventoryItem{
		ID:                  "comms.state_root",
		AuthorityDomain:     "comms_owned",
		Path:                stateRoot,
		PathKind:            "directory",
		Expected:            true,
		Classification:      "canonical_comms_owned_root",
		StateClass:          "state_root",
		Sensitivity:         "mixed_local_state",
		Owner:               "carbonstack-comms",
		WriterPolicy:        "multiple_comms_commands_derive_or_use_children",
		MutationPolicy:      "policy_anchor_only",
		CleanupPolicy:       "do_not_delete_as_generated_artifact",
		CompatibilityPolicy: "explicit_state_compatibility_preserved",
		Notes: []string{
			"Canonical root is a documented policy anchor, not a brittle mandatory chokepoint.",
			"Explicit --state remains supported.",
		},
	})

	add(stateSubstrateInventoryItem{
		ID:                  "comms.state_file",
		AuthorityDomain:     "comms_owned",
		Path:                statePath,
		PathKind:            "json_file",
		Expected:            true,
		Classification:      "local_comms_state",
		StateClass:          "ready_device_state",
		Sensitivity:         "local_account_device_server_metadata",
		Owner:               "carbonstack-comms/internal/state",
		WriterPolicy:        "state.Save and init/register-device flows",
		MutationPolicy:      "state_mutation_surface",
		CleanupPolicy:       "do_not_delete_as_generated_artifact",
		CompatibilityPolicy: "C2 must decide schema/version compatibility posture",
		Notes: []string{
			"Current state file may be legacy/unversioned; classify before enforcing migration.",
		},
	})

	add(stateSubstrateInventoryItem{
		ID:                  "comms.trust_records",
		AuthorityDomain:     "comms_owned",
		Path:                filepath.Join(stateRoot, "trust.json"),
		PathKind:            "json_file",
		Expected:            false,
		Classification:      "trust_state",
		StateClass:          "trust_candidate_state",
		Sensitivity:         "trust_metadata",
		Owner:               "carbonstack-comms/internal/trust",
		WriterPolicy:        "trust commands only",
		MutationPolicy:      "do_not_mutate_in_gate_c1",
		CleanupPolicy:       "do_not_delete_as_generated_artifact",
		CompatibilityPolicy: "C2/C-later must classify before enforcement",
		Notes: []string{
			"Gate C1 inventories trust state but does not promote or verify identity.",
		},
	})

	add(stateSubstrateInventoryItem{
		ID:                  "comms.trust_events",
		AuthorityDomain:     "comms_owned",
		Path:                filepath.Join(stateRoot, "trust-events.jsonl"),
		PathKind:            "jsonl_file",
		Expected:            false,
		Classification:      "trust_event_history",
		StateClass:          "trust_candidate_state",
		Sensitivity:         "trust_metadata",
		Owner:               "carbonstack-comms/internal/trust",
		WriterPolicy:        "trust lifecycle commands",
		MutationPolicy:      "do_not_mutate_in_gate_c1",
		CleanupPolicy:       "do_not_delete_as_generated_artifact",
		CompatibilityPolicy: "jsonl compatibility deferred",
	})

	add(stateSubstrateInventoryItem{
		ID:                  "comms.identity_candidates",
		AuthorityDomain:     "comms_owned",
		Path:                filepath.Join(stateRoot, "identity-candidates.json"),
		PathKind:            "json_file",
		Expected:            false,
		Classification:      "identity_candidate_state",
		StateClass:          "trust_candidate_state",
		Sensitivity:         "candidate_identity_metadata",
		Owner:               "carbonstack-comms/internal/trust",
		WriterPolicy:        "candidate review commands",
		MutationPolicy:      "do_not_mutate_in_gate_c1",
		CleanupPolicy:       "do_not_delete_as_generated_artifact",
		CompatibilityPolicy: "C2/C-later must classify before enforcement",
		Notes: []string{
			"Known identity_candidate_review.go self-assignment warning remains classified, not silently normalized.",
		},
	})

	add(stateSubstrateInventoryItem{
		ID:                  "comms.keypackage_receipt_root",
		AuthorityDomain:     "comms_owned",
		Path:                filepath.Join(stateRoot, "keypackage-receipts"),
		PathKind:            "directory",
		Expected:            false,
		Classification:      "keypackage_receipt_root",
		StateClass:          "onboarding_receipt_state",
		Sensitivity:         "local_onboarding_artifact_metadata",
		Owner:               "openmls-relay-keypackage-consume-dev",
		WriterPolicy:        "receipt writer with ACK-after-persist discipline",
		MutationPolicy:      "do_not_mutate_in_gate_c1",
		CleanupPolicy:       "do_not_delete_as_generated_artifact",
		CompatibilityPolicy: "C2 should enforce supported receipt schema",
	})

	add(stateSubstrateInventoryItem{
		ID:                  "comms.welcome_receipt_root",
		AuthorityDomain:     "comms_owned",
		Path:                filepath.Join(stateRoot, "welcome-receipts"),
		PathKind:            "directory",
		Expected:            false,
		Classification:      "welcome_receipt_root",
		StateClass:          "onboarding_receipt_state",
		Sensitivity:         "local_onboarding_artifact_metadata",
		Owner:               "openmls-relay-welcome-consume-dev",
		WriterPolicy:        "receipt writer with ACK-after-join discipline",
		MutationPolicy:      "do_not_mutate_in_gate_c1",
		CleanupPolicy:       "do_not_delete_as_generated_artifact",
		CompatibilityPolicy: "C2 should enforce supported receipt schema",
	})

	add(stateSubstrateInventoryItem{
		ID:                  "comms.workflow_report_root",
		AuthorityDomain:     "comms_owned",
		Path:                filepath.Join(stateRoot, "workflow-reports"),
		PathKind:            "directory",
		Expected:            false,
		Classification:      "workflow_report_root",
		StateClass:          "workflow_evidence_state",
		Sensitivity:         "local_workflow_metadata",
		Owner:               "workflow-relay-onboarding-dev",
		WriterPolicy:        "durable workflow report writer",
		MutationPolicy:      "do_not_mutate_in_gate_c1",
		CleanupPolicy:       "do_not_delete_as_generated_artifact",
		CompatibilityPolicy: "C2 should enforce supported workflow report schema",
	})

	sidecarDir := strings.TrimSpace(input.SidecarDir)
	if sidecarDir == "" {
		sidecarDir = defaultOpenMLSSidecarDir
		report.SidecarDir = sidecarDir
	}
	add(stateSubstrateInventoryItem{
		ID:                  "sidecar.project_dir",
		AuthorityDomain:     "sidecar_owned",
		Path:                sidecarDir,
		PathKind:            "directory",
		Expected:            true,
		Classification:      "sidecar_project_boundary",
		StateClass:          "cryptographic_runtime_boundary",
		Sensitivity:         "sidecar_source_and_generated_state_boundary",
		Owner:               "openmls-sidecar",
		WriterPolicy:        "sidecar commands own provider/conversation internals",
		MutationPolicy:      "classify_only_in_gate_c1",
		CleanupPolicy:       "do not clean except known generated roots through validator clean-generated",
		CompatibilityPolicy: "Gate C Comms substrate references but does not rewrite sidecar cryptographic internals",
	})

	add(stateSubstrateInventoryItem{
		ID:                  "sidecar.generated_state_root",
		AuthorityDomain:     "sidecar_owned",
		Path:                filepath.Join(sidecarDir, ".carbonstack-openmls-sidecar-state"),
		PathKind:            "directory",
		Expected:            false,
		Classification:      "sidecar_generated_state_root",
		StateClass:          "cryptographic_runtime_state",
		Sensitivity:         "cryptographic_group_provider_state",
		Owner:               "openmls-sidecar",
		WriterPolicy:        "sidecar commands",
		MutationPolicy:      "classify_only_in_gate_c1",
		CleanupPolicy:       "known generated root; validator may clean only when explicitly requested",
		CompatibilityPolicy: "sidecar owns cryptographic compatibility",
	})

	if report.CypherDBPath != "" {
		add(stateSubstrateInventoryItem{
			ID:                  "cypher.database",
			AuthorityDomain:     "cypher_owned",
			Path:                report.CypherDBPath,
			PathKind:            "sqlite_file",
			Expected:            false,
			Classification:      "cypher_server_database",
			StateClass:          "server_routing_delivery_state",
			Sensitivity:         "relay_server_metadata",
			Owner:               "carbonstack-cypher",
			WriterPolicy:        "Cypher server and migrations",
			MutationPolicy:      "classify_only_in_gate_c1",
			CleanupPolicy:       "do_not_delete_as_generated_artifact",
			CompatibilityPolicy: "Cypher migrations own DB compatibility",
		})
	} else {
		add(stateSubstrateInventoryItem{
			ID:                  "cypher.database",
			AuthorityDomain:     "cypher_owned",
			PathKind:            "sqlite_file",
			Expected:            false,
			Classification:      "cypher_server_database_not_configured",
			StateClass:          "server_routing_delivery_state",
			Sensitivity:         "relay_server_metadata",
			Owner:               "carbonstack-cypher",
			WriterPolicy:        "Cypher server and migrations",
			MutationPolicy:      "not_applicable",
			CleanupPolicy:       "not_applicable",
			CompatibilityPolicy: "classification placeholder only",
			Notes: []string{
				"Use --cypher-db to classify a concrete Cypher DB path.",
			},
		})
	}

	if report.EvidenceRoot != "" {
		add(stateSubstrateInventoryItem{
			ID:                  "evidence.root",
			AuthorityDomain:     "evidence_generated",
			Path:                report.EvidenceRoot,
			PathKind:            "directory",
			Expected:            false,
			Classification:      "external_evidence_root",
			StateClass:          "evidence_output",
			Sensitivity:         "operator_evidence_logs",
			Owner:               "operator_validation_workflow",
			WriterPolicy:        "scripts and validation evidence",
			MutationPolicy:      "not_runtime_state",
			CleanupPolicy:       "operator controlled",
			CompatibilityPolicy: "not_runtime_compatibility_authority",
		})
	}

	report.Items = append(report.Items, scanStateSubstrateKnownJSON(report.StateRoot)...)
	sort.SliceStable(report.Items, func(i, j int) bool { return report.Items[i].ID < report.Items[j].ID })
	report.Summary = summarizeStateSubstrateInventory(report.Items)
	return report, nil
}

func deriveStateSubstrateRootFromStatePath(statePath string) string {
	dir := filepath.Dir(strings.TrimSpace(statePath))
	if dir == "." || dir == "" {
		return ".carbonstack-comms"
	}
	return dir
}

func inspectStateSubstrateItem(item stateSubstrateInventoryItem) stateSubstrateInventoryItem {
	item.AuthorityDomain = normalizeStateSubstrateField(item.AuthorityDomain, "unknown")
	item.PathKind = normalizeStateSubstrateField(item.PathKind, "unknown")
	item.Classification = normalizeStateSubstrateField(item.Classification, "unknown")
	item.StateClass = normalizeStateSubstrateField(item.StateClass, "unknown")
	item.Sensitivity = normalizeStateSubstrateField(item.Sensitivity, "unknown")
	item.Owner = normalizeStateSubstrateField(item.Owner, "unknown")
	item.WriterPolicy = normalizeStateSubstrateField(item.WriterPolicy, "unknown")
	item.MutationPolicy = normalizeStateSubstrateField(item.MutationPolicy, "unknown")
	item.CleanupPolicy = normalizeStateSubstrateField(item.CleanupPolicy, "unknown")
	item.CompatibilityPolicy = normalizeStateSubstrateField(item.CompatibilityPolicy, "unknown")
	item.SchemaStatus = "not_json"

	if item.Path == "" {
		item.Exists = false
		if item.SchemaStatus == "" {
			item.SchemaStatus = "not_applicable"
		}
		return item
	}

	info, err := os.Stat(item.Path)
	if err != nil {
		item.Exists = false
		if item.Expected {
			item.Notes = append(item.Notes, "expected path is missing")
		}
		return item
	}
	item.Exists = true
	item.IsDir = info.IsDir()

	if item.PathKind == "json_file" && !item.IsDir {
		schema, status := inspectJSONSchemaVersion(item.Path)
		item.SchemaVersion = schema
		item.SchemaStatus = status
		item.SupportedSchema = isSupportedStateSubstrateSchema(schema)
		if status == "missing_schema_version" {
			item.SupportedSchema = false
		}
	} else if item.PathKind == "jsonl_file" {
		item.SchemaStatus = "jsonl_unversioned_or_event_stream"
	} else {
		item.SchemaStatus = "not_json"
	}

	if item.SchemaStatus == "missing_schema_version" && item.Classification != "local_comms_state" {
		item.Notes = append(item.Notes, "unversioned JSON should be classified before C2 enforcement")
	}
	if item.SchemaStatus == "unsupported_schema_version" {
		item.Notes = append(item.Notes, "unsupported schema must refuse in safety-sensitive C2+ readers")
	}
	return item
}

func inspectJSONSchemaVersion(path string) (string, string) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", "unreadable_json"
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", "invalid_json"
	}
	value, ok := raw["schema_version"]
	if !ok {
		return "", "missing_schema_version"
	}
	s, ok := value.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", "invalid_schema_version"
	}
	s = strings.TrimSpace(s)
	if isSupportedStateSubstrateSchema(s) {
		return s, "supported_schema_version"
	}
	return s, "unsupported_schema_version"
}

func isSupportedStateSubstrateSchema(schema string) bool {
	switch schema {
	case stateSubstrateInventorySchema,
		"carbonstack-keypackage-consume-receipt/v0",
		"carbonstack-welcome-consume-receipt/v0",
		"carbonstack-workflow-relay-onboarding-report/v0",
		"carbonstack-cypher-mls-mismatch-report/v0":
		return true
	default:
		return false
	}
}

func scanStateSubstrateKnownJSON(stateRoot string) []stateSubstrateInventoryItem {
	var out []stateSubstrateInventoryItem

	scan := func(rootDir, fileName, idPrefix, classification, owner, compatibility string) {
		if rootDir == "" {
			return
		}
		info, err := os.Stat(rootDir)
		if err != nil || !info.IsDir() {
			return
		}
		_ = filepath.WalkDir(rootDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if d.Name() != fileName {
				return nil
			}
			rel, _ := filepath.Rel(rootDir, path)
			id := idPrefix + "." + safeStateSubstrateID(rel)
			out = append(out, inspectStateSubstrateItem(stateSubstrateInventoryItem{
				ID:                  id,
				AuthorityDomain:     "comms_owned",
				Path:                path,
				PathKind:            "json_file",
				Expected:            false,
				Classification:      classification,
				StateClass:          "discovered_comms_owned_json_state",
				Sensitivity:         "local_state_metadata",
				Owner:               owner,
				WriterPolicy:        owner,
				MutationPolicy:      "do_not_mutate_in_gate_c1",
				CleanupPolicy:       "do_not_delete_as_generated_artifact",
				CompatibilityPolicy: compatibility,
				Notes: []string{
					"Discovered under Comms-owned derived root.",
				},
			}))
			return nil
		})
	}

	scan(filepath.Join(stateRoot, "keypackage-receipts"), "receipt.json", "discovered.keypackage_receipt", "keypackage_receipt_manifest", "openmls-relay-keypackage-consume-dev", "C2 should refuse unsupported receipt schemas")
	scan(filepath.Join(stateRoot, "welcome-receipts"), "receipt.json", "discovered.welcome_receipt", "welcome_receipt_manifest", "openmls-relay-welcome-consume-dev", "C2 should refuse unsupported receipt schemas")
	scan(filepath.Join(stateRoot, "workflow-reports"), "workflow-report.json", "discovered.workflow_report", "workflow_report_manifest", "workflow-relay-onboarding-dev", "C2 should refuse unsupported workflow report schemas")

	return out
}

func summarizeStateSubstrateInventory(items []stateSubstrateInventoryItem) stateSubstrateInventorySummary {
	summary := stateSubstrateInventorySummary{
		TotalItems:            len(items),
		ClassificationCounts:  map[string]int{},
		AuthorityDomainCounts: map[string]int{},
		SchemaStatusCounts:    map[string]int{},
	}
	for _, item := range items {
		if item.Exists {
			summary.ExistingItems++
		}
		if item.Expected && !item.Exists {
			summary.MissingExpectedItems++
		}
		if item.SchemaStatus == "unsupported_schema_version" {
			summary.UnsupportedSchemaItems++
		}
		if item.SchemaStatus == "missing_schema_version" {
			summary.LegacyUnversionedItems++
		}
		switch item.AuthorityDomain {
		case "comms_owned":
			summary.CommsOwnedItems++
		case "sidecar_owned":
			summary.SidecarOwnedItems++
		case "cypher_owned":
			summary.CypherOwnedItems++
		case "validator_generated":
			summary.ValidatorGeneratedItems++
		case "evidence_generated":
			summary.EvidenceGeneratedItems++
		}
		summary.ClassificationCounts[item.Classification]++
		summary.AuthorityDomainCounts[item.AuthorityDomain]++
		summary.SchemaStatusCounts[item.SchemaStatus]++
	}
	return summary
}

func normalizeStateSubstrateField(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func safeStateSubstrateID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "empty"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	cleaned := strings.Trim(b.String(), "._-")
	if cleaned == "" {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])[:16]
	}
	return cleaned
}

func writeStateSubstrateInventoryReportAtomic(path string, report stateSubstrateInventoryReport) error {
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

func printStateSubstrateInventoryReport(report stateSubstrateInventoryReport) {
	fmt.Println("state substrate inventory dev")
	fmt.Println("command: state-substrate-inventory-dev")
	fmt.Printf("schema_version: %s\n", report.SchemaVersion)
	fmt.Printf("state_path: %s\n", report.StatePath)
	fmt.Printf("state_root: %s\n", report.StateRoot)
	fmt.Printf("state_root_source: %s\n", report.StateRootSource)
	fmt.Printf("sidecar_dir: %s\n", report.SidecarDir)
	if report.CypherDBPath != "" {
		fmt.Printf("cypher_db_path: %s\n", report.CypherDBPath)
	}
	if report.EvidenceRoot != "" {
		fmt.Printf("evidence_root: %s\n", report.EvidenceRoot)
	}
	if report.OutputPath != "" {
		fmt.Printf("output_path: %s\n", report.OutputPath)
	}
	fmt.Printf("total_items: %d\n", report.Summary.TotalItems)
	fmt.Printf("existing_items: %d\n", report.Summary.ExistingItems)
	fmt.Printf("missing_expected_items: %d\n", report.Summary.MissingExpectedItems)
	fmt.Printf("legacy_unversioned_items: %d\n", report.Summary.LegacyUnversionedItems)
	fmt.Printf("unsupported_schema_items: %d\n", report.Summary.UnsupportedSchemaItems)
	for _, item := range report.Items {
		fmt.Printf("item: %s authority=%s class=%s exists=%t schema_status=%s path=%s\n", item.ID, item.AuthorityDomain, item.Classification, item.Exists, item.SchemaStatus, item.Path)
	}
	fmt.Printf("canonical_comms_root_policy: %s\n", report.CanonicalCommsRootPolicy)
	fmt.Printf("explicit_state_compatibility: %t\n", report.ExplicitStateCompatibility)
	fmt.Printf("deep_recon_friendly: %t\n", report.DeepReconFriendly)
	fmt.Printf("no_silent_repair: %t\n", report.NoSilentRepair)
	fmt.Printf("no_silent_migration: %t\n", report.NoSilentMigration)
	fmt.Printf("no_trust_or_candidate_mutation: %t\n", report.NoTrustOrCandidateMutation)
	fmt.Printf("verified_identity_claimed: %t\n", report.VerifiedIdentityClaimed)
	fmt.Printf("cypher_mls_reconciled: %t\n", report.CypherMLSReconciled)
	fmt.Printf("vault_claimed: %t\n", report.VaultClaimed)
	fmt.Printf("backup_restore_claimed: %t\n", report.BackupRestoreClaimed)
	fmt.Printf("deployment_claimed: %t\n", report.DeploymentClaimed)
	fmt.Printf("full_runtime_dev_promoted: %t\n", report.FullRuntimeDevPromoted)
	fmt.Printf("gate_d_started: %t\n", report.GateDStarted)
	fmt.Println("warning: dev/pre-alpha inventory and authority-map only; does not migrate, repair, delete, trust-promote, verify identity, create a vault, restore backup, deploy, or start Gate D")
}
