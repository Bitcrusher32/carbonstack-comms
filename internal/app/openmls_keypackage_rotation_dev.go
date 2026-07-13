package app

import (
	"errors"
	"flag"
	"fmt"
)

func cmdOpenMLSKeyPackageGenerateDev(args []string) error {
	fs := flag.NewFlagSet("openmls-keypackage-generate-dev", flag.ContinueOnError)
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	deviceLabel := fs.String("sidecar-device-label", "", "local OpenMLS sidecar device label")
	requestID := fs.String("request-id", "", "device-local KeyPackage generation idempotency key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *deviceLabel == "" || *requestID == "" {
		return errors.New("--sidecar-device-label and --request-id are required")
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"keypackage-generate",
		"--device-label",
		*deviceLabel,
		"--request-id",
		*requestID,
	)
	if err != nil {
		return err
	}

	fmt.Println("openmls dev KeyPackage generation")
	fmt.Println("command: openmls-keypackage-generate-dev")
	fmt.Println("status: generated")
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	bootstrapPrintOptionalString("device_label", envelope.Data)
	bootstrapPrintOptionalString("generation_id", envelope.Data)
	bootstrapPrintOptionalString("request_id", envelope.Data)
	bootstrapPrintOptionalString("key_package_ref", envelope.Data)
	bootstrapPrintOptionalString("artifact_path", envelope.Data)
	bootstrapPrintOptionalString("artifact_sha256", envelope.Data)
	bootstrapPrintOptionalString("manifest_path", envelope.Data)
	bootstrapPrintOptionalString("current_generation_id", envelope.Data)
	bootstrapPrintOptionalInteger("sequence", envelope.Data)
	bootstrapPrintOptionalInteger("generation_count", envelope.Data)
	bootstrapPrintOptionalBool("idempotent_replay", envelope.Data)
	bootstrapPrintOptionalBool("recovered_from_manifest", envelope.Data)
	fmt.Println("warning: dev-local KeyPackage generation only; no Relay publication, consume, Welcome, or trust mutation")
	return nil
}

func cmdOpenMLSKeyPackageInventoryDev(args []string) error {
	fs := flag.NewFlagSet("openmls-keypackage-inventory-dev", flag.ContinueOnError)
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	deviceLabel := fs.String("sidecar-device-label", "", "local OpenMLS sidecar device label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *deviceLabel == "" {
		return errors.New("--sidecar-device-label is required")
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"keypackage-inventory",
		"--device-label",
		*deviceLabel,
	)
	if err != nil {
		return err
	}

	fmt.Println("openmls dev KeyPackage inventory")
	fmt.Println("command: openmls-keypackage-inventory-dev")
	fmt.Println("status: inspected")
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	bootstrapPrintOptionalString("device_label", envelope.Data)
	bootstrapPrintOptionalString("current_generation_id", envelope.Data)
	bootstrapPrintOptionalInteger("next_sequence", envelope.Data)
	bootstrapPrintOptionalInteger("generation_count", envelope.Data)
	bootstrapPrintOptionalInteger("active_count", envelope.Data)
	bootstrapPrintOptionalInteger("retired_count", envelope.Data)
	bootstrapPrintOptionalBool("local_state_mutated", envelope.Data)
	fmt.Println("warning: read-only dev inventory; no Relay publication or implicit repair")
	return nil
}

func cmdOpenMLSKeyPackageRetireDev(args []string) error {
	fs := flag.NewFlagSet("openmls-keypackage-retire-dev", flag.ContinueOnError)
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	deviceLabel := fs.String("sidecar-device-label", "", "local OpenMLS sidecar device label")
	generationID := fs.String("generation-id", "", "non-current KeyPackage generation to retire")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *deviceLabel == "" || *generationID == "" {
		return errors.New("--sidecar-device-label and --generation-id are required")
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"keypackage-retire",
		"--device-label",
		*deviceLabel,
		"--generation-id",
		*generationID,
	)
	if err != nil {
		return err
	}

	fmt.Println("openmls dev KeyPackage retirement")
	fmt.Println("command: openmls-keypackage-retire-dev")
	fmt.Println("status: retired")
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	bootstrapPrintOptionalString("device_label", envelope.Data)
	bootstrapPrintOptionalString("generation_id", envelope.Data)
	bootstrapPrintOptionalString("status", envelope.Data)
	bootstrapPrintOptionalInteger("retired_at_unix", envelope.Data)
	bootstrapPrintOptionalBool("idempotent_replay", envelope.Data)
	bootstrapPrintOptionalBool("artifact_retained", envelope.Data)
	bootstrapPrintOptionalBool("provider_storage_retained", envelope.Data)
	fmt.Println("warning: retirement is metadata-only; artifacts and private provider state are retained")
	return nil
}
