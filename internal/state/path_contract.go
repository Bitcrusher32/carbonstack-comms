package state

const StatePathContractSchemaVersion = "carbonstack-comms-state-path-contract/v0"

type StatePathContract struct {
	SchemaVersion string                        `json:"schema_version"`
	StatePath     string                        `json:"state_path"`
	Domains       []StatePathContractDomain     `json:"domains"`
	Capabilities  StatePathContractCapabilities `json:"capabilities"`
	Warning       string                        `json:"warning"`
}

type StatePathContractDomain struct {
	ID                  string `json:"id"`
	Path                string `json:"path"`
	Classification      string `json:"classification"`
	VaultClass          string `json:"vault_class"`
	SecretBearing       string `json:"secret_bearing"`
	FutureVaultRequired bool   `json:"future_vault_required"`
	SafeToPrintContents bool   `json:"safe_to_print_contents"`
	SafeToDelete        string `json:"safe_to_delete"`
	MutationAllowed     bool   `json:"mutation_allowed"`
	Note                string `json:"note"`
}

type StatePathContractCapabilities struct {
	EncryptionEnabled     bool `json:"encryption_enabled"`
	CanReadSecretContents bool `json:"can_read_secret_contents"`
	CanWriteSecretContent bool `json:"can_write_secret_contents"`
	CanDeleteDomains      bool `json:"can_delete_domains"`
}

func BuildStatePathContract(opts StateAuditOptions) StatePathContract {
	opts = normalizeStateAuditOptions(opts)
	adapter := NewLocalPathVaultAdapter(opts)

	resolutions := adapter.ListDomains()
	domains := make([]StatePathContractDomain, 0, len(resolutions))
	for _, resolution := range resolutions {
		domains = append(domains, StatePathContractDomain{
			ID:                  string(resolution.Domain.ID),
			Path:                resolution.Path,
			Classification:      resolution.Domain.Classification,
			VaultClass:          string(resolution.Domain.VaultClass),
			SecretBearing:       resolution.Domain.SecretBearing,
			FutureVaultRequired: resolution.Domain.FutureVaultRequired,
			SafeToPrintContents: resolution.Domain.SafeToPrintContents,
			SafeToDelete:        resolution.Domain.SafeToDelete,
			MutationAllowed:     resolution.Domain.MutationAllowed,
			Note:                resolution.Domain.Note,
		})
	}

	return StatePathContract{
		SchemaVersion: StatePathContractSchemaVersion,
		StatePath:     opts.StatePath,
		Domains:       domains,
		Capabilities: StatePathContractCapabilities{
			EncryptionEnabled:     adapter.EncryptionEnabled(),
			CanReadSecretContents: adapter.CanReadSecretContents(),
			CanWriteSecretContent: adapter.CanWriteSecretContents(),
			CanDeleteDomains:      adapter.CanDeleteDomains(),
		},
		Warning: "non-encrypting path contract only; not vault encryption, recovery, deletion, or production key storage",
	}
}

func ResolveStateDomainPath(opts StateAuditOptions, domainID StateDomainID) (string, error) {
	adapter := NewLocalPathVaultAdapter(opts)

	resolution, err := adapter.Resolve(domainID)
	if err != nil {
		return "", err
	}

	return resolution.Path, nil
}
