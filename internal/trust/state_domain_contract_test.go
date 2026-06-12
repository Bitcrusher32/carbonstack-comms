package trust

import (
	"path/filepath"
	"testing"

	statepkg "git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func TestStateDomainContractMatchesTrustPathDerivation(t *testing.T) {
	statePath := filepath.Join("state-dir", "state.json")
	opts := statepkg.StateAuditOptions{StatePath: statePath}
	trustPaths := PathsForStatePath(statePath)

	trustStorePath, err := statepkg.ResolveStateDomainPath(opts, statepkg.StateDomainTrustStore)
	if err != nil {
		t.Fatalf("resolve trust store: %v", err)
	}
	if trustStorePath != trustPaths.TrustPath {
		t.Fatalf("trust store path = %q, want %q", trustStorePath, trustPaths.TrustPath)
	}

	trustHistoryPath, err := statepkg.ResolveStateDomainPath(opts, statepkg.StateDomainTrustHistory)
	if err != nil {
		t.Fatalf("resolve trust history: %v", err)
	}
	if trustHistoryPath != trustPaths.EventsPath {
		t.Fatalf("trust history path = %q, want %q", trustHistoryPath, trustPaths.EventsPath)
	}

	candidatePath, err := statepkg.ResolveStateDomainPath(opts, statepkg.StateDomainCandidateStore)
	if err != nil {
		t.Fatalf("resolve candidate store: %v", err)
	}
	if candidatePath != IdentityCandidatesPathForStatePath(statePath) {
		t.Fatalf("candidate path = %q, want %q", candidatePath, IdentityCandidatesPathForStatePath(statePath))
	}
}
