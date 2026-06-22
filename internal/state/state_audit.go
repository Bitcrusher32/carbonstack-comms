package state

import (
	"os"
	"strings"
)

const (
	DefaultSidecarStateRoot  = "internal/protocol/mls/openmls-sidecar/.carbonstack-openmls-sidecar-state"
	DefaultSidecarTargetRoot = "internal/protocol/mls/openmls-sidecar/target"
	DefaultCypherDBPath      = "../carbonstack-cypher/cypher.db"

	StateAuditSchemaVersion = "carbonstack-comms-state-audit/v0"
)

type StateAuditOptions struct {
	StatePath         string
	SidecarStateRoot  string
	SidecarTargetRoot string
	CypherDBPath      string
}

type StateAuditReport struct {
	SchemaVersion             string             `json:"schema_version"`
	Command                   string             `json:"command"`
	StateBoundaryModelVersion string             `json:"state_boundary_model_version"`
	StateBoundaryRole         string             `json:"state_boundary_role"`
	ProtoSubstrate            bool               `json:"proto_substrate"`
	PQTagsReservedNotImpl     bool               `json:"pq_tags_reserved_not_implemented"`
	MutationAllowed           bool               `json:"mutation_allowed"`
	RawSecretContentsPrinted  bool               `json:"raw_secret_contents_printed"`
	DomainsTotal              int                `json:"domains_total"`
	DomainsPresent            int                `json:"domains_present"`
	DomainsAbsent             int                `json:"domains_absent"`
	Domains                   []StateAuditDomain `json:"domains"`
	Warning                   string             `json:"warning"`
}

type StateAuditDomain struct {
	Domain              string `json:"domain"`
	Path                string `json:"path"`
	Present             bool   `json:"present"`
	Kind                string `json:"kind"`
	SizeBytes           int64  `json:"size_bytes"`
	Classification      string `json:"classification"`
	AuthorityClass      string `json:"authority_class"`
	SensitivityClass    string `json:"sensitivity_class"`
	NoSilentRule        string `json:"no_silent_rule"`
	BoundaryWarning     string `json:"boundary_warning"`
	CypherInventoryOnly bool   `json:"cypher_inventory_only"`
	VaultClass          string `json:"vault_class"`
	SecretBearing       string `json:"secret_bearing"`
	FutureVaultRequired bool   `json:"future_vault_required"`
	SafeToPrintContents bool   `json:"safe_to_print_contents"`
	SafeToDelete        string `json:"safe_to_delete"`
	MutationAllowed     bool   `json:"mutation_allowed"`
	Note                string `json:"note"`
}

func DefaultStateAuditOptions() StateAuditOptions {
	return StateAuditOptions{
		StatePath:         DefaultStatePath,
		SidecarStateRoot:  DefaultSidecarStateRoot,
		SidecarTargetRoot: DefaultSidecarTargetRoot,
		CypherDBPath:      DefaultCypherDBPath,
	}
}

func BuildStateAuditReport(opts StateAuditOptions) StateAuditReport {
	domains := AuditStateDomains(opts)

	present := 0
	for _, domain := range domains {
		if domain.Present {
			present++
		}
	}
	for i := range domains {
		enrichStateAuditDomain(&domains[i])
	}

	return StateAuditReport{
		SchemaVersion:             StateAuditSchemaVersion,
		Command:                   "state-audit-dev",
		StateBoundaryModelVersion: "v0.6.29-state-boundary-v0",
		StateBoundaryRole:         "proto_substrate_inventory_check",
		ProtoSubstrate:            true,
		PQTagsReservedNotImpl:     true,
		MutationAllowed:           false,
		RawSecretContentsPrinted:  false,
		DomainsTotal:              len(domains),
		DomainsPresent:            present,
		DomainsAbsent:             len(domains) - present,
		Domains:                   domains,
		Warning:                   "dev/pre-alpha state-domain inventory; not vault encryption, recovery, deletion, or production key storage",
	}
}

func AuditStateDomains(opts StateAuditOptions) []StateAuditDomain {
	adapter := NewLocalPathVaultAdapter(opts)
	resolutions := adapter.ListDomains()

	domains := make([]StateAuditDomain, 0, len(resolutions))
	for _, resolution := range resolutions {
		domains = append(domains, auditPath(StateAuditDomain{
			Domain:              string(resolution.Domain.ID),
			Path:                resolution.Path,
			Classification:      resolution.Domain.Classification,
			VaultClass:          string(resolution.Domain.VaultClass),
			SecretBearing:       resolution.Domain.SecretBearing,
			FutureVaultRequired: resolution.Domain.FutureVaultRequired,
			SafeToPrintContents: resolution.Domain.SafeToPrintContents,
			SafeToDelete:        resolution.Domain.SafeToDelete,
			MutationAllowed:     resolution.Domain.MutationAllowed,
			Note:                resolution.Domain.Note,
		}))
	}

	return domains
}

func normalizeStateAuditOptions(opts StateAuditOptions) StateAuditOptions {
	defaults := DefaultStateAuditOptions()

	if strings.TrimSpace(opts.StatePath) == "" {
		opts.StatePath = defaults.StatePath
	}
	if strings.TrimSpace(opts.SidecarStateRoot) == "" {
		opts.SidecarStateRoot = defaults.SidecarStateRoot
	}
	if strings.TrimSpace(opts.SidecarTargetRoot) == "" {
		opts.SidecarTargetRoot = defaults.SidecarTargetRoot
	}
	if strings.TrimSpace(opts.CypherDBPath) == "" {
		opts.CypherDBPath = defaults.CypherDBPath
	}

	return opts
}

func auditPath(domain StateAuditDomain) StateAuditDomain {
	info, err := os.Stat(domain.Path)
	if err != nil {
		domain.Present = false
		domain.Kind = "absent"
		domain.SizeBytes = 0
		return domain
	}

	domain.Present = true
	domain.SizeBytes = info.Size()

	switch {
	case info.IsDir():
		domain.Kind = "directory"
	case info.Mode().IsRegular():
		domain.Kind = "file"
	default:
		domain.Kind = "other"
	}

	return domain
}
func enrichStateAuditDomain(domain *StateAuditDomain) {
	domain.AuthorityClass = stateAuditAuthorityClass(domain)
	domain.SensitivityClass = stateAuditSensitivityClass(domain)
	domain.NoSilentRule = stateAuditNoSilentRule(domain)
	domain.BoundaryWarning = stateAuditBoundaryWarning(domain)
	domain.CypherInventoryOnly = string(domain.Domain) == string(StateDomainLocalCypherDB)
}

func stateAuditAuthorityClass(domain *StateAuditDomain) string {
	switch string(domain.Domain) {
	case string(StateDomainCommsState):
		return "runtime_authority"
	case string(StateDomainTrustStore), string(StateDomainCandidateStore):
		return "safety_sensitive_future_runtime_authority"
	case string(StateDomainTrustHistory):
		return "metadata_evidence"
	case string(StateDomainSidecarGeneratedState):
		return "dev_runtime_authority_container"
	case string(StateDomainSidecarBuildOutput):
		return "generated_disposable"
	case string(StateDomainLocalCypherDB):
		return "server_side_coordination_authority_inventory_only"
	default:
		return "unclassified"
	}
}

func stateAuditSensitivityClass(domain *StateAuditDomain) string {
	switch string(domain.Domain) {
	case string(StateDomainCommsState):
		return "safety_sensitive_possibly_privacy_sensitive"
	case string(StateDomainTrustStore), string(StateDomainCandidateStore):
		return "safety_sensitive_privacy_sensitive"
	case string(StateDomainTrustHistory):
		return "safety_sensitive_metadata_evidence"
	case string(StateDomainSidecarGeneratedState):
		return "secret_bearing_safety_sensitive_dev_scope"
	case string(StateDomainSidecarBuildOutput):
		return "generated_build_output"
	case string(StateDomainLocalCypherDB):
		return "privacy_sensitive_safety_sensitive_maybe_secret_bearing"
	default:
		return "unclassified"
	}
}

func stateAuditNoSilentRule(domain *StateAuditDomain) string {
	switch string(domain.Domain) {
	case string(StateDomainCommsState):
		return "no_silent_replacement_import_or_restore"
	case string(StateDomainTrustStore):
		return "no_silent_trust_promotion"
	case string(StateDomainTrustHistory):
		return "no_silent_deletion_or_rewrite"
	case string(StateDomainCandidateStore):
		return "no_silent_verified_import"
	case string(StateDomainSidecarGeneratedState):
		return "no_silent_runtime_authority_regeneration"
	case string(StateDomainSidecarBuildOutput):
		return "generated_cleanup_only_when_explicitly_scoped"
	case string(StateDomainLocalCypherDB):
		return "inventory_only_no_silent_routing_membership_ack_mutation"
	default:
		return "unclassified"
	}
}

func stateAuditBoundaryWarning(domain *StateAuditDomain) string {
	switch string(domain.Domain) {
	case string(StateDomainCommsState):
		return "state_boundary_inventory_only_not_backup_restore"
	case string(StateDomainTrustStore):
		return "trust_state_inventory_only_not_verification"
	case string(StateDomainTrustHistory):
		return "trust_history_evidence_inventory_only_not_secure_audit_log"
	case string(StateDomainCandidateStore):
		return "candidate_state_inventory_only_not_verified_identity"
	case string(StateDomainSidecarGeneratedState):
		return "dev_generated_state_not_production_vault"
	case string(StateDomainSidecarBuildOutput):
		return "generated_build_output_not_release_material"
	case string(StateDomainLocalCypherDB):
		return "cypher_inventory_only_not_comms_vault_not_restore"
	default:
		return "state_boundary_inventory_only"
	}
}
