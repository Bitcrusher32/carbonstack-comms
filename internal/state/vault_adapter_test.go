package state

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalPathVaultAdapterResolvesDomainsWithoutSecretCapabilities(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	adapter := NewLocalPathVaultAdapter(StateAuditOptions{
		StatePath: statePath,
	})

	if adapter.EncryptionEnabled() {
		t.Fatal("local path vault adapter must not claim encryption")
	}
	if adapter.CanReadSecretContents() {
		t.Fatal("local path vault adapter must not read secret contents")
	}
	if adapter.CanWriteSecretContents() {
		t.Fatal("local path vault adapter must not write secret contents")
	}
	if adapter.CanDeleteDomains() {
		t.Fatal("local path vault adapter must not delete domains")
	}

	domains := adapter.ListDomains()
	if len(domains) == 0 {
		t.Fatal("expected adapter domains")
	}

	resolved, err := adapter.Resolve(StateDomainTrustStore)
	if err != nil {
		t.Fatalf("resolve trust_store: %v", err)
	}
	if resolved.Path != filepath.Join(filepath.Dir(statePath), "trust.json") {
		t.Fatalf("trust_store path = %q", resolved.Path)
	}
	if !resolved.Domain.FutureVaultRequired {
		t.Fatal("trust_store should require future vault")
	}
}

func TestLocalPathVaultAdapterRejectsUnknownDomain(t *testing.T) {
	adapter := NewLocalPathVaultAdapter(StateAuditOptions{})

	_, err := adapter.Resolve(StateDomainID("missing_domain"))
	if err == nil || !strings.Contains(err.Error(), "unknown state domain") {
		t.Fatalf("expected unknown state domain error, got %v", err)
	}
}

func TestLocalPathVaultAdapterListDomainsReturnsCopy(t *testing.T) {
	adapter := NewLocalPathVaultAdapter(StateAuditOptions{})

	first := adapter.ListDomains()
	if len(first) == 0 {
		t.Fatal("expected domains")
	}

	first[0].Path = "mutated"

	second := adapter.ListDomains()
	if second[0].Path == "mutated" {
		t.Fatal("ListDomains exposed mutable internal slice")
	}
}
