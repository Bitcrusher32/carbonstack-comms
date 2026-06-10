package state

import (
	"os"
	"path/filepath"
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
	opts = normalizeStateAuditOptions(opts)

	stateDir := filepath.Dir(opts.StatePath)
	if stateDir == "." || strings.TrimSpace(stateDir) == "" {
		stateDir = "."
	}

	return []StateAuditDomain{
		auditPath(StateAuditDomain{
			Domain:              "comms_state",
			Path:                opts.StatePath,
			Classification:      "local-app-state",
			SecretBearing:       "maybe",
			FutureVaultRequired: true,
			SafeToPrintContents: false,
			SafeToDelete:        "no",
			MutationAllowed:     false,
			Note:                "contains local Comms account/device/server configuration; do not print raw contents in audits",
		}),
		auditPath(StateAuditDomain{
			Domain:              "trust_store",
			Path:                filepath.Join(stateDir, "trust.json"),
			Classification:      "local-trust-state",
			SecretBearing:       "maybe",
			FutureVaultRequired: true,
			SafeToPrintContents: false,
			SafeToDelete:        "no",
			MutationAllowed:     false,
			Note:                "client-owned trust state; provider observation, Relay Space routing, and OpenMLS membership must not silently mutate it",
		}),
		auditPath(StateAuditDomain{
			Domain:              "trust_history",
			Path:                filepath.Join(stateDir, "trust-events.jsonl"),
			Classification:      "append-only-trust-history",
			SecretBearing:       "maybe",
			FutureVaultRequired: true,
			SafeToPrintContents: false,
			SafeToDelete:        "no",
			MutationAllowed:     false,
			Note:                "append-only local trust/history evidence; important for recovery and mismatch review",
		}),
		auditPath(StateAuditDomain{
			Domain:              "candidate_store",
			Path:                filepath.Join(stateDir, "identity-candidates.json"),
			Classification:      "local-trust-adjacent-candidate-state",
			SecretBearing:       "maybe",
			FutureVaultRequired: true,
			SafeToPrintContents: false,
			SafeToDelete:        "no",
			MutationAllowed:     false,
			Note:                "unverified/candidate identity material; never equivalent to verified trust",
		}),
		auditPath(StateAuditDomain{
			Domain:              "sidecar_generated_state",
			Path:                opts.SidecarStateRoot,
			Classification:      "generated-dev-provider-state",
			SecretBearing:       "yes",
			FutureVaultRequired: true,
			SafeToPrintContents: false,
			SafeToDelete:        "only explicit generated-state cleanup, never unknown operator state",
			MutationAllowed:     false,
			Note:                "dev-local OpenMLS signer/provider/group state; not production vault storage",
		}),
		auditPath(StateAuditDomain{
			Domain:              "sidecar_build_output",
			Path:                opts.SidecarTargetRoot,
			Classification:      "generated-build-output",
			SecretBearing:       "no",
			FutureVaultRequired: false,
			SafeToPrintContents: false,
			SafeToDelete:        "yes if generated by local build",
			MutationAllowed:     false,
			Note:                "Rust/Cargo build output; excluded from release material",
		}),
		auditPath(StateAuditDomain{
			Domain:              "local_cypher_db",
			Path:                opts.CypherDBPath,
			Classification:      "server-relay-local-db",
			SecretBearing:       "maybe",
			FutureVaultRequired: false,
			SafeToPrintContents: false,
			SafeToDelete:        "only explicit local operator cleanup",
			MutationAllowed:     false,
			Note:                "local Cypher SQLite database may contain relay metadata/envelopes; not Comms vault state and not release material",
		}),
	}
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
