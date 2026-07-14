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

const stateSchemaCompatibilityReportSchema = "carbonstack-state-schema-compatibility-report/v0"

type stateSchemaCompatibilityInput struct {
	Kind                 string
	Path                 string
	OutputPath           string
	AllowRefusalExitZero bool
}

type stateSchemaCompatibilityReport struct {
	SchemaVersion            string   `json:"schema_version"`
	Command                  string   `json:"command"`
	CreatedAt                string   `json:"created_at"`
	Kind                     string   `json:"kind"`
	Path                     string   `json:"path"`
	OutputPath               string   `json:"output_path,omitempty"`
	PathExists               bool     `json:"path_exists"`
	IsDir                    bool     `json:"is_dir"`
	JSONReadable             bool     `json:"json_readable"`
	DeclaredSchemaVersion    string   `json:"declared_schema_version,omitempty"`
	SchemaStatus             string   `json:"schema_status"`
	Classification           string   `json:"classification"`
	Action                   string   `json:"action"`
	SupportedSchema          bool     `json:"supported_schema"`
	SafetySensitive          bool     `json:"safety_sensitive"`
	LegacyClassifiedOnly     bool     `json:"legacy_classified_only"`
	MutationPerformed        bool     `json:"mutation_performed"`
	MigrationPerformed       bool     `json:"migration_performed"`
	RepairPerformed          bool     `json:"repair_performed"`
	NoSilentMigration        bool     `json:"no_silent_migration"`
	NoSilentRepair           bool     `json:"no_silent_repair"`
	TrustOrCandidateMutation bool     `json:"trust_or_candidate_state_mutated"`
	VerifiedIdentityClaimed  bool     `json:"verified_identity_claimed"`
	VaultClaimed             bool     `json:"vault_claimed"`
	BackupRestoreClaimed     bool     `json:"backup_restore_claimed"`
	DeploymentClaimed        bool     `json:"deployment_claimed"`
	FullRuntimeDevPromoted   bool     `json:"full_runtime_dev_promoted"`
	GateDStarted             bool     `json:"gate_d_started"`
	SupportedSchemas         []string `json:"supported_schemas"`
	Notes                    []string `json:"notes,omitempty"`
}

type stateSchemaCompatibilityKind struct {
	Kind            string
	SafetySensitive bool
	Supported       []string
	LegacyClassify  bool
	Description     string
}

func cmdStateSchemaCompatDev(args []string) error {
	fs := flag.NewFlagSet("state-schema-compat-dev", flag.ContinueOnError)
	kind := fs.String("kind", "", "schema kind: keypackage-receipt, welcome-receipt, workflow-report, state-substrate-inventory, cypher-mls-mismatch-report, comms-state")
	path := fs.String("path", "", "JSON file path to inspect")
	outputPath := fs.String("output", "", "optional machine-readable compatibility report path; generated evidence only")
	allowRefusalExitZero := fs.Bool("allow-refusal-exit-zero", false, "print refusal but exit zero for validation/profiling")
	if err := fs.Parse(args); err != nil {
		return err
	}

	report := evaluateStateSchemaCompatibility(stateSchemaCompatibilityInput{
		Kind:                 *kind,
		Path:                 *path,
		OutputPath:           *outputPath,
		AllowRefusalExitZero: *allowRefusalExitZero,
	})

	if report.OutputPath != "" {
		if err := writeStateSchemaCompatibilityReportAtomic(report.OutputPath, report); err != nil {
			return err
		}
	}

	printStateSchemaCompatibilityReport(report)

	if report.Action == "refuse" && !*allowRefusalExitZero {
		return fmt.Errorf("state_schema_compatibility_refused: kind=%s classification=%s schema_status=%s path=%s", report.Kind, report.Classification, report.SchemaStatus, report.Path)
	}
	return nil
}

func evaluateStateSchemaCompatibility(input stateSchemaCompatibilityInput) stateSchemaCompatibilityReport {
	kind := strings.TrimSpace(input.Kind)
	path := strings.TrimSpace(input.Path)
	spec, ok := stateSchemaCompatibilityKinds()[kind]

	report := stateSchemaCompatibilityReport{
		SchemaVersion:            stateSchemaCompatibilityReportSchema,
		Command:                  "state-schema-compat-dev",
		CreatedAt:                time.Now().UTC().Format(time.RFC3339),
		Kind:                     kind,
		Path:                     path,
		OutputPath:               strings.TrimSpace(input.OutputPath),
		SchemaStatus:             "not_checked",
		Classification:           "unknown",
		Action:                   "refuse",
		MutationPerformed:        false,
		MigrationPerformed:       false,
		RepairPerformed:          false,
		NoSilentMigration:        true,
		NoSilentRepair:           true,
		TrustOrCandidateMutation: false,
		VerifiedIdentityClaimed:  false,
		VaultClaimed:             false,
		BackupRestoreClaimed:     false,
		DeploymentClaimed:        false,
		FullRuntimeDevPromoted:   false,
		GateDStarted:             false,
	}

	if !ok {
		report.SchemaStatus = "unknown_kind"
		report.Classification = "unsupported_kind"
		report.Notes = append(report.Notes, "unsupported schema kind")
		return report
	}
	report.SafetySensitive = spec.SafetySensitive
	report.LegacyClassifiedOnly = spec.LegacyClassify
	report.SupportedSchemas = append([]string{}, spec.Supported...)
	sort.Strings(report.SupportedSchemas)

	if path == "" {
		report.SchemaStatus = "missing_path_argument"
		report.Classification = "missing_path_argument"
		return report
	}

	info, err := os.Stat(path)
	if err != nil {
		report.PathExists = false
		report.SchemaStatus = "path_missing"
		report.Classification = "missing_state_artifact"
		report.Notes = append(report.Notes, "missing path is refused for compatibility checks")
		return report
	}
	report.PathExists = true
	report.IsDir = info.IsDir()
	if info.IsDir() {
		report.SchemaStatus = "path_is_directory"
		report.Classification = "not_json_file"
		return report
	}

	body, err := os.ReadFile(path)
	if err != nil {
		report.SchemaStatus = "unreadable_json"
		report.Classification = "unreadable_json"
		return report
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		report.JSONReadable = false
		report.SchemaStatus = "invalid_json"
		report.Classification = "invalid_json"
		return report
	}
	report.JSONReadable = true

	value, hasSchema := raw["schema_version"]
	if !hasSchema {
		if spec.LegacyClassify {
			report.SchemaStatus = "missing_schema_version"
			report.Classification = "legacy_unversioned_classified"
			report.Action = "classify"
			report.SupportedSchema = false
			report.Notes = append(report.Notes, "legacy/unversioned artifact classified without migration")
			return report
		}
		report.SchemaStatus = "missing_schema_version"
		report.Classification = "missing_schema_refused"
		report.Notes = append(report.Notes, "safety-sensitive artifact has no schema_version")
		return report
	}

	schema, ok := value.(string)
	if !ok || strings.TrimSpace(schema) == "" {
		report.SchemaStatus = "invalid_schema_version"
		report.Classification = "invalid_schema_refused"
		return report
	}
	schema = strings.TrimSpace(schema)
	report.DeclaredSchemaVersion = schema

	if containsStateSchema(spec.Supported, schema) {
		report.SchemaStatus = "supported_schema_version"
		report.Classification = "compatible"
		report.Action = "allow"
		report.SupportedSchema = true
		return report
	}

	report.SchemaStatus = "unsupported_schema_version"
	report.Classification = "unsupported_schema_refused"
	report.SupportedSchema = false
	report.Notes = append(report.Notes, "unsupported schema is refused; C2 performs no migration")
	return report
}

func stateSchemaCompatibilityKinds() map[string]stateSchemaCompatibilityKind {
	return map[string]stateSchemaCompatibilityKind{
		"state-substrate-inventory": {
			Kind:            "state-substrate-inventory",
			SafetySensitive: true,
			Supported:       []string{"carbonstack-state-substrate-inventory/v0"},
			Description:     "Gate C1 inventory report",
		},
		"keypackage-receipt": {
			Kind:            "keypackage-receipt",
			SafetySensitive: true,
			Supported:       []string{"carbonstack-keypackage-consume-receipt/v0"},
			Description:     "B5d KeyPackage consume receipt manifest",
		},
		"welcome-receipt": {
			Kind:            "welcome-receipt",
			SafetySensitive: true,
			Supported:       []string{"carbonstack-welcome-consume-receipt/v0"},
			Description:     "B6 Welcome consume receipt manifest",
		},
		"workflow-report": {
			Kind:            "workflow-report",
			SafetySensitive: true,
			Supported:       []string{"carbonstack-workflow-relay-onboarding-report/v0"},
			Description:     "B8 workflow report",
		},
		"cypher-mls-mismatch-report": {
			Kind:            "cypher-mls-mismatch-report",
			SafetySensitive: true,
			Supported:       []string{"carbonstack-cypher-mls-mismatch-report/v0"},
			Description:     "B7 mismatch report",
		},
		"comms-state": {
			Kind:            "comms-state",
			SafetySensitive: true,
			Supported:       []string{},
			LegacyClassify:  true,
			Description:     "local Comms state; currently classified before strict migration/refusal enforcement",
		},
	}
}

func containsStateSchema(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func writeStateSchemaCompatibilityReportAtomic(path string, report stateSchemaCompatibilityReport) error {
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

func printStateSchemaCompatibilityReport(report stateSchemaCompatibilityReport) {
	fmt.Println("state schema compatibility dev")
	fmt.Println("command: state-schema-compat-dev")
	fmt.Printf("schema_version: %s\n", report.SchemaVersion)
	fmt.Printf("kind: %s\n", report.Kind)
	fmt.Printf("path: %s\n", report.Path)
	if report.OutputPath != "" {
		fmt.Printf("output_path: %s\n", report.OutputPath)
	}
	fmt.Printf("path_exists: %t\n", report.PathExists)
	fmt.Printf("json_readable: %t\n", report.JSONReadable)
	fmt.Printf("declared_schema_version: %s\n", report.DeclaredSchemaVersion)
	fmt.Printf("schema_status: %s\n", report.SchemaStatus)
	fmt.Printf("classification: %s\n", report.Classification)
	fmt.Printf("action: %s\n", report.Action)
	fmt.Printf("supported_schema: %t\n", report.SupportedSchema)
	fmt.Printf("safety_sensitive: %t\n", report.SafetySensitive)
	fmt.Printf("legacy_classified_only: %t\n", report.LegacyClassifiedOnly)
	fmt.Printf("mutation_performed: %t\n", report.MutationPerformed)
	fmt.Printf("migration_performed: %t\n", report.MigrationPerformed)
	fmt.Printf("repair_performed: %t\n", report.RepairPerformed)
	fmt.Printf("no_silent_migration: %t\n", report.NoSilentMigration)
	fmt.Printf("no_silent_repair: %t\n", report.NoSilentRepair)
	fmt.Printf("trust_or_candidate_state_mutated: %t\n", report.TrustOrCandidateMutation)
	fmt.Printf("verified_identity_claimed: %t\n", report.VerifiedIdentityClaimed)
	fmt.Printf("vault_claimed: %t\n", report.VaultClaimed)
	fmt.Printf("backup_restore_claimed: %t\n", report.BackupRestoreClaimed)
	fmt.Printf("deployment_claimed: %t\n", report.DeploymentClaimed)
	fmt.Printf("full_runtime_dev_promoted: %t\n", report.FullRuntimeDevPromoted)
	fmt.Printf("gate_d_started: %t\n", report.GateDStarted)
	fmt.Println("warning: dev/pre-alpha schema compatibility check only; no migration, repair, trust promotion, verified identity, vault, backup/restore, deployment, full-runtime-dev, or Gate D claim")
}
