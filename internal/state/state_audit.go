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
	SchemaVersion            string             `json:"schema_version"`
	Command                  string             `json:"command"`
	MutationAllowed          bool               `json:"mutation_allowed"`
	RawSecretContentsPrinted bool               `json:"raw_secret_contents_printed"`
	DomainsTotal             int                `json:"domains_total"`
	DomainsPresent           int                `json:"domains_present"`
	DomainsAbsent            int                `json:"domains_absent"`
	Domains                  []StateAuditDomain `json:"domains"`
	Warning                  string             `json:"warning"`
}

type StateAuditDomain struct {
	Domain              string `json:"domain"`
	Path                string `json:"path"`
	Present             bool   `json:"present"`
	Kind                string `json:"kind"`
	SizeBytes           int64  `json:"size_bytes"`
	Classification      string `json:"classification"`
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

	return StateAuditReport{
		SchemaVersion:            StateAuditSchemaVersion,
		Command:                  "state-audit-dev",
		MutationAllowed:          false,
		RawSecretContentsPrinted: false,
		DomainsTotal:             len(domains),
		DomainsPresent:           present,
		DomainsAbsent:            len(domains) - present,
		Domains:                  domains,
		Warning:                  "dev/pre-alpha state-domain inventory; not vault encryption, recovery, deletion, or production key storage",
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
