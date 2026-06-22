package app

import (
	"encoding/json"
	"errors"
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
	format := fs.String("format", "text", "output format: text or json")

	if err := fs.Parse(args); err != nil {
		return err
	}

	report := state.BuildStateAuditReport(state.StateAuditOptions{
		StatePath:         *statePath,
		SidecarStateRoot:  *sidecarStateRoot,
		SidecarTargetRoot: *sidecarTargetRoot,
		CypherDBPath:      *cypherDBPath,
	})

	switch *format {
	case "text":
		printStateAuditText(report)
		return nil
	case "json":
		encoder := json.NewEncoder(stdoutWriter{})
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	default:
		return errors.New("--format must be text or json")
	}
}

func printStateAuditText(report state.StateAuditReport) {
	fmt.Println("state audit dev")
	fmt.Printf("schema_version: %s\n", report.SchemaVersion)
	fmt.Printf("command: %s\n", report.Command)
	fmt.Printf("state_boundary_model_version: %s\n", report.StateBoundaryModelVersion)
	fmt.Printf("state_boundary_role: %s\n", report.StateBoundaryRole)
	fmt.Printf("proto_substrate: %t\n", report.ProtoSubstrate)
	fmt.Printf("pq_tags_reserved_not_implemented: %t\n", report.PQTagsReservedNotImpl)
	fmt.Printf("mutation_allowed: %t\n", report.MutationAllowed)
	fmt.Printf("raw_secret_contents_printed: %t\n", report.RawSecretContentsPrinted)
	fmt.Printf("warning: %s\n", report.Warning)

	for _, domain := range report.Domains {
		fmt.Println()
		fmt.Printf("domain: %s\n", domain.Domain)
		fmt.Printf("path: %s\n", domain.Path)
		fmt.Printf("present: %t\n", domain.Present)
		fmt.Printf("kind: %s\n", domain.Kind)
		fmt.Printf("size_bytes: %d\n", domain.SizeBytes)
		fmt.Printf("classification: %s\n", domain.Classification)
		fmt.Printf("authority_class: %s\n", domain.AuthorityClass)
		fmt.Printf("sensitivity_class: %s\n", domain.SensitivityClass)
		fmt.Printf("no_silent_rule: %s\n", domain.NoSilentRule)
		fmt.Printf("boundary_warning: %s\n", domain.BoundaryWarning)
		fmt.Printf("cypher_inventory_only: %t\n", domain.CypherInventoryOnly)
		fmt.Printf("vault_class: %s\n", domain.VaultClass)
		fmt.Printf("secret_bearing: %s\n", domain.SecretBearing)
		fmt.Printf("future_vault_required: %t\n", domain.FutureVaultRequired)
		fmt.Printf("safe_to_print_contents: %t\n", domain.SafeToPrintContents)
		fmt.Printf("safe_to_delete: %s\n", domain.SafeToDelete)
		fmt.Printf("mutation_allowed: %t\n", domain.MutationAllowed)
		fmt.Printf("note: %s\n", domain.Note)
	}

	fmt.Println()
	fmt.Printf("domains_total: %d\n", report.DomainsTotal)
	fmt.Printf("domains_present: %d\n", report.DomainsPresent)
	fmt.Printf("domains_absent: %d\n", report.DomainsAbsent)
	fmt.Println("status: inspected")
}

type stdoutWriter struct{}

func (stdoutWriter) Write(p []byte) (int, error) {
	return fmt.Print(string(p))
}
