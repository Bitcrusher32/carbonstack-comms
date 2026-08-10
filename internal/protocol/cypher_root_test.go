package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resolveTestCypherRoot resolves the sibling carbonstack-cypher checkout used by
// protocol integration tests.
//
// Resolution order:
//  1. CARBONSTACK_CYPHER_ROOT, when explicitly set;
//  2. sibling checkout next to the carbonstack-comms repo.
//
// This is test-only harness stability. It is not a production runtime dependency,
// service-discovery feature, public-ingress feature, container feature, or
// deployment readiness claim.
func resolveTestCypherRoot(t testing.TB, commsRoot string) string {
	t.Helper()

	if override := strings.TrimSpace(os.Getenv("CARBONSTACK_CYPHER_ROOT")); override != "" {
		return requireTestCypherRoot(t, override, "CARBONSTACK_CYPHER_ROOT")
	}

	sibling := filepath.Join(filepath.Dir(commsRoot), "carbonstack-cypher")
	return requireTestCypherRoot(t, sibling, "sibling checkout")
}

func requireTestCypherRoot(t testing.TB, root, source string) string {
	t.Helper()

	cleanRoot := filepath.Clean(root)
	mainPath := filepath.Join(cleanRoot, "cmd", "cypher", "main.go")
	if info, err := os.Stat(mainPath); err != nil || info.IsDir() {
		if err == nil {
			t.Fatalf("invalid carbonstack-cypher root from %s: %s is a directory", source, mainPath)
		}
		t.Fatalf("invalid carbonstack-cypher root from %s: missing %s: %v", source, mainPath, err)
	}
	return cleanRoot
}
