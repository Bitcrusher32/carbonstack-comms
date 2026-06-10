package state

import (
	"path/filepath"
	"testing"
)

func TestResolveDefaultStateDomainsStableOrderAndPaths(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, ".carbonstack-comms", "state.json")
	sidecarRoot := filepath.Join(dir, "sidecar-state")
	sidecarTarget := filepath.Join(dir, "target")
	cypherDB := filepath.Join(dir, "cypher.db")

	domains := ResolveDefaultStateDomains(StateAuditOptions{
		StatePath:         statePath,
		SidecarStateRoot:  sidecarRoot,
		SidecarTargetRoot: sidecarTarget,
		CypherDBPath:      cypherDB,
	})

	wantOrder := []StateDomainID{
		StateDomainCommsState,
		StateDomainTrustStore,
		StateDomainTrustHistory,
		StateDomainCandidateStore,
		StateDomainSidecarGeneratedState,
		StateDomainSidecarBuildOutput,
		StateDomainLocalCypherDB,
	}

	if len(domains) != len(wantOrder) {
		t.Fatalf("len(domains) = %d, want %d", len(domains), len(wantOrder))
	}

	for i, want := range wantOrder {
		if domains[i].Domain.ID != want {
			t.Fatalf("domain[%d] = %q, want %q", i, domains[i].Domain.ID, want)
		}
		if domains[i].Domain.MutationAllowed {
			t.Fatalf("domain %s unexpectedly allows mutation", domains[i].Domain.ID)
		}
		if domains[i].Domain.SafeToPrintContents {
			t.Fatalf("domain %s unexpectedly allows raw content printing", domains[i].Domain.ID)
		}
	}

	byID := map[StateDomainID]StateDomainResolution{}
	for _, domain := range domains {
		byID[domain.Domain.ID] = domain
	}

	if byID[StateDomainCommsState].Path != statePath {
		t.Fatalf("comms_state path = %q", byID[StateDomainCommsState].Path)
	}
	if byID[StateDomainTrustStore].Path != filepath.Join(filepath.Dir(statePath), "trust.json") {
		t.Fatalf("trust_store path = %q", byID[StateDomainTrustStore].Path)
	}
	if byID[StateDomainTrustHistory].Path != filepath.Join(filepath.Dir(statePath), "trust-events.jsonl") {
		t.Fatalf("trust_history path = %q", byID[StateDomainTrustHistory].Path)
	}
	if byID[StateDomainCandidateStore].Path != filepath.Join(filepath.Dir(statePath), "identity-candidates.json") {
		t.Fatalf("candidate_store path = %q", byID[StateDomainCandidateStore].Path)
	}
	if byID[StateDomainSidecarGeneratedState].Domain.VaultClass != VaultClassGeneratedSecretState {
		t.Fatalf("sidecar_generated_state vault class = %q", byID[StateDomainSidecarGeneratedState].Domain.VaultClass)
	}
	if byID[StateDomainSidecarBuildOutput].Domain.FutureVaultRequired {
		t.Fatal("sidecar_build_output should not require future vault")
	}
	if byID[StateDomainLocalCypherDB].Domain.VaultClass != VaultClassServerRelayLocalState {
		t.Fatalf("local_cypher_db vault class = %q", byID[StateDomainLocalCypherDB].Domain.VaultClass)
	}
}
