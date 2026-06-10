package app

import (
	"flag"
	"fmt"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func cmdStateAuditDev(args []string) error {
	defaults := state.DefaultStateAuditOptions()

	fs := flag.NewFlagSet("state-audit-dev", flag.ExitOnError)
	statePath := fs.String("state", defaults.StatePath, "Comms state.json path")
	sidecarStateRoot := fs.String("sidecar-state-root", defaults.SidecarStateRoot, "OpenMLS sidecar generated state root")
	sidecarTargetRoot := fs.String("sidecar-target-root", defaults.SidecarTargetRoot, "OpenMLS sidecar Rust/Cargo build output root")
	cypherDBPath := fs.String("cypher-db", defaults.CypherDBPath, "local Cypher SQLite DB path to classify without reading contents")

	if err := fs.Parse(args); err != nil {
		return err
	}

	domains := state.AuditStateDomains(state.StateAuditOptions{
		StatePath:         *statePath,
		SidecarStateRoot:  *sidecarStateRoot,
		SidecarTargetRoot: *sidecarTargetRoot,
		CypherDBPath:      *cypherDBPath,
	})

	fmt.Println("state audit dev")
	fmt.Println("command: state-audit-dev")
	fmt.Println("mutation_allowed: false")
	fmt.Println("raw_secret_contents_printed: false")
	fmt.Println("warning: dev/pre-alpha state-domain inventory; not vault encryption, recovery, deletion, or production key storage")

	for _, domain := range domains {
		fmt.Println()
		fmt.Printf("domain: %s\n", domain.Domain)
		fmt.Printf("path: %s\n", domain.Path)
		fmt.Printf("present: %t\n", domain.Present)
		fmt.Printf("kind: %s\n", domain.Kind)
		fmt.Printf("size_bytes: %d\n", domain.SizeBytes)
		fmt.Printf("classification: %s\n", domain.Classification)
		fmt.Printf("secret_bearing: %s\n", domain.SecretBearing)
		fmt.Printf("future_vault_required: %t\n", domain.FutureVaultRequired)
		fmt.Printf("safe_to_print_contents: %t\n", domain.SafeToPrintContents)
		fmt.Printf("safe_to_delete: %s\n", domain.SafeToDelete)
		fmt.Printf("mutation_allowed: %t\n", domain.MutationAllowed)
		fmt.Printf("note: %s\n", domain.Note)
	}

	fmt.Println()
	fmt.Printf("domains_total: %d\n", len(domains))
	fmt.Println("status: inspected")
	return nil
}
