package state

import "fmt"

type VaultAdapter interface {
	ListDomains() []StateDomainResolution
	Resolve(domainID StateDomainID) (StateDomainResolution, error)
	EncryptionEnabled() bool
	CanReadSecretContents() bool
	CanWriteSecretContents() bool
	CanDeleteDomains() bool
}

type LocalPathVaultAdapter struct {
	domains []StateDomainResolution
}

func NewLocalPathVaultAdapter(opts StateAuditOptions) LocalPathVaultAdapter {
	return LocalPathVaultAdapter{
		domains: ResolveDefaultStateDomains(opts),
	}
}

func (a LocalPathVaultAdapter) ListDomains() []StateDomainResolution {
	out := make([]StateDomainResolution, len(a.domains))
	copy(out, a.domains)
	return out
}

func (a LocalPathVaultAdapter) Resolve(domainID StateDomainID) (StateDomainResolution, error) {
	for _, domain := range a.domains {
		if domain.Domain.ID == domainID {
			return domain, nil
		}
	}

	return StateDomainResolution{}, fmt.Errorf("unknown state domain %q", domainID)
}

func (a LocalPathVaultAdapter) EncryptionEnabled() bool {
	return false
}

func (a LocalPathVaultAdapter) CanReadSecretContents() bool {
	return false
}

func (a LocalPathVaultAdapter) CanWriteSecretContents() bool {
	return false
}

func (a LocalPathVaultAdapter) CanDeleteDomains() bool {
	return false
}
