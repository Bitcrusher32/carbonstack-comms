package state

import (
	"errors"
	"sort"
	"strings"
	"time"
)

const GateDStateRecoveryModelSchema = "carbonstack-state-recovery-vault-backup-model/v0"

const (
	GateDClassificationExistsCurrentCode       = "exists_current_code"
	GateDClassificationModelOnly               = "model_only"
	GateDClassificationAdapterOnly             = "adapter_or_classification_only"
	GateDClassificationSafeNonSecretDryRun     = "safe_non_secret_dry_run_candidate"
	GateDClassificationBlockedSecretBearing    = "blocked_secret_bearing"
	GateDClassificationFutureVaultRequired     = "future_vault_required"
	GateDClassificationExplicitlyDeferred      = "explicitly_deferred"
	GateDClassificationUnknownRequiresContract = "unknown_requires_contract"
)

type GateDStateDomainInput struct {
	RepoOrComponent              string
	StateDomain                  string
	StatePathOrLocator           string
	StateRoot                    string
	SecretBearing                bool
	FutureVaultRequired          bool
	ReferencesTrustCandidate     bool
	ReferencesChangedLineage     bool
	ReferencesDemotionRevocation bool
	ExistingCode                 bool
	ModelOnly                    bool
	AdapterOnly                  bool
}

type GateDStateDomainClassification struct {
	RepoOrComponent                      string   `json:"repo_or_component"`
	StateDomain                          string   `json:"state_domain"`
	StatePathOrLocator                   string   `json:"state_path_or_locator"`
	StateRoot                            string   `json:"state_root"`
	SecretBearing                        bool     `json:"secret_bearing"`
	FutureVaultRequired                  bool     `json:"future_vault_required"`
	BackupManifestClassification         string   `json:"backup_manifest_classification"`
	RestoreClassification                string   `json:"restore_classification"`
	MigrationCompatibilityClassification string   `json:"migration_compatibility_classification"`
	RollbackMetadataClassification       string   `json:"rollback_metadata_classification"`
	TrustCandidateStateReference         string   `json:"trust_candidate_state_reference"`
	ChangedLineageWarningReference       string   `json:"changed_lineage_warning_reference"`
	DemotionOrRevocationReference        string   `json:"demotion_or_revocation_reference"`
	RefusalOrWarning                     string   `json:"refusal_or_warning"`
	Nonclaims                            []string `json:"nonclaims"`
	EvidencePaths                        []string `json:"evidence_paths"`
}

type GateDStateRecoveryReport struct {
	SchemaVersion  string                           `json:"schema_version"`
	ReportID       string                           `json:"report_id"`
	CreatedAt      string                           `json:"created_at"`
	StateInventory []GateDStateDomainClassification `json:"state_inventory"`
	StateRoots     []string                         `json:"state_roots"`
	Nonclaims      []string                         `json:"nonclaims"`
}

func BuildGateDStateRecoveryReport(reportID string, inputs []GateDStateDomainInput, createdAt time.Time) (GateDStateRecoveryReport, error) {
	reportID = strings.TrimSpace(reportID)
	if reportID == "" {
		return GateDStateRecoveryReport{}, errors.New("report ID is required")
	}
	if len(inputs) == 0 {
		return GateDStateRecoveryReport{}, errors.New("at least one state domain is required")
	}

	inventory := make([]GateDStateDomainClassification, 0, len(inputs))
	rootSet := map[string]bool{}
	for _, input := range inputs {
		classification := ClassifyGateDStateDomain(input)
		inventory = append(inventory, classification)
		if classification.StateRoot != "" {
			rootSet[classification.StateRoot] = true
		}
	}

	var roots []string
	for root := range rootSet {
		roots = append(roots, root)
	}
	sort.Strings(roots)

	return GateDStateRecoveryReport{
		SchemaVersion:  GateDStateRecoveryModelSchema,
		ReportID:       reportID,
		CreatedAt:      createdAt.UTC().Format(time.RFC3339),
		StateInventory: inventory,
		StateRoots:     roots,
		Nonclaims:      GateDStateRecoveryNonclaims(),
	}, nil
}

func ClassifyGateDStateDomain(input GateDStateDomainInput) GateDStateDomainClassification {
	stateRoot := strings.TrimSpace(input.StateRoot)
	domain := strings.TrimSpace(input.StateDomain)
	component := strings.TrimSpace(input.RepoOrComponent)
	locator := strings.TrimSpace(input.StatePathOrLocator)

	backup := GateDClassificationSafeNonSecretDryRun
	restore := GateDClassificationSafeNonSecretDryRun
	migration := GateDClassificationSafeNonSecretDryRun
	rollback := GateDClassificationSafeNonSecretDryRun
	refusal := "classify only; no repair, migration, trust import, secret restore, or destructive cleanup"

	if input.SecretBearing {
		backup = GateDClassificationBlockedSecretBearing
		restore = GateDClassificationBlockedSecretBearing
		migration = GateDClassificationExplicitlyDeferred
		rollback = GateDClassificationUnknownRequiresContract
		refusal = "blocked: secret-bearing state requires future vault pipeline and cannot be restored by Gate D dry-run"
	} else if input.FutureVaultRequired {
		backup = GateDClassificationFutureVaultRequired
		restore = GateDClassificationFutureVaultRequired
		migration = GateDClassificationExplicitlyDeferred
		rollback = GateDClassificationUnknownRequiresContract
		refusal = "future-vault-required: inventory only until secure vault pipeline exists"
	} else if input.AdapterOnly || input.ModelOnly {
		backup = GateDClassificationAdapterOnly
		restore = GateDClassificationAdapterOnly
		migration = GateDClassificationAdapterOnly
		rollback = GateDClassificationAdapterOnly
		refusal = "adapter/model only: classify and report without state mutation"
	} else if input.ExistingCode {
		backup = GateDClassificationExistsCurrentCode
		restore = GateDClassificationSafeNonSecretDryRun
		migration = GateDClassificationSafeNonSecretDryRun
		rollback = GateDClassificationSafeNonSecretDryRun
	}

	trustReference := "not_applicable"
	if input.ReferencesTrustCandidate {
		trustReference = "referenced_inventory_only_not_backup_target"
	}
	changedReference := "not_applicable"
	if input.ReferencesChangedLineage {
		changedReference = "referenced_warning_only_not_repair_target"
	}
	demotionReference := "not_applicable"
	if input.ReferencesDemotionRevocation {
		demotionReference = "referenced_event_only_not_restore_authority"
	}

	return GateDStateDomainClassification{
		RepoOrComponent:                      component,
		StateDomain:                          domain,
		StatePathOrLocator:                   locator,
		StateRoot:                            stateRoot,
		SecretBearing:                        input.SecretBearing,
		FutureVaultRequired:                  input.FutureVaultRequired,
		BackupManifestClassification:         backup,
		RestoreClassification:                restore,
		MigrationCompatibilityClassification: migration,
		RollbackMetadataClassification:       rollback,
		TrustCandidateStateReference:         trustReference,
		ChangedLineageWarningReference:       changedReference,
		DemotionOrRevocationReference:        demotionReference,
		RefusalOrWarning:                     refusal,
		Nonclaims:                            GateDStateRecoveryNonclaims(),
	}
}

func GateDStateRecoveryNonclaims() []string {
	return []string{
		"not production vault",
		"not encryption-at-rest",
		"not secure key storage",
		"not production backup/restore",
		"not migration safety",
		"not secret-bearing backup restore",
		"not hardware-backed storage",
		"not automatic migration",
		"not silent repair",
		"not silent signer provider or group regeneration",
		"not silent trust import",
		"not destructive cleanup",
		"not verified identity",
		"not trust promotion",
	}
}

func GateDStateRecoveryClaims() map[string]bool {
	return map[string]bool{
		"production_vault":                          false,
		"encryption_at_rest":                        false,
		"secure_key_storage":                        false,
		"production_backup_restore":                 false,
		"migration_safety":                          false,
		"secret_bearing_backup_restore":             false,
		"hardware_backed_storage":                   false,
		"automatic_migration":                       false,
		"silent_repair":                             false,
		"silent_signer_provider_group_regeneration": false,
		"silent_trust_import":                       false,
		"destructive_cleanup":                       false,
	}
}

func GateDRestoreWouldImportTrust(input GateDStateDomainInput) bool {
	return input.ReferencesTrustCandidate && !input.SecretBearing
}
