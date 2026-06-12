package app

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/trust"
)

func TestResolveCommandStatePathsMatchesLegacyTrustDerivation(t *testing.T) {
	statePath := filepath.Join("state-dir", "state.json")

	paths, err := resolveCommandStatePaths(statePath)
	if err != nil {
		t.Fatalf("resolve command state paths: %v", err)
	}

	legacyTrustPaths := trust.PathsForStatePath(statePath)
	if paths.StatePath != statePath {
		t.Fatalf("state path = %q, want %q", paths.StatePath, statePath)
	}
	if paths.TrustPaths.TrustPath != legacyTrustPaths.TrustPath {
		t.Fatalf("trust path = %q, want %q", paths.TrustPaths.TrustPath, legacyTrustPaths.TrustPath)
	}
	if paths.TrustPaths.EventsPath != legacyTrustPaths.EventsPath {
		t.Fatalf("events path = %q, want %q", paths.TrustPaths.EventsPath, legacyTrustPaths.EventsPath)
	}
	if paths.CandidatePath != trust.IdentityCandidatesPathForStatePath(statePath) {
		t.Fatalf("candidate path = %q, want %q", paths.CandidatePath, trust.IdentityCandidatesPathForStatePath(statePath))
	}
}

func TestResolveCommandStatePathsDoesNotCreateFiles(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, ".carbonstack-comms", "state.json")

	_, err := resolveCommandStatePaths(statePath)
	if err != nil {
		t.Fatalf("resolve command state paths: %v", err)
	}

	for _, path := range []string{
		statePath,
		filepath.Join(filepath.Dir(statePath), "trust.json"),
		filepath.Join(filepath.Dir(statePath), "trust-events.jsonl"),
		filepath.Join(filepath.Dir(statePath), "identity-candidates.json"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("resolveCommandStatePaths should not create %s, stat err=%v", path, err)
		}
	}
}
