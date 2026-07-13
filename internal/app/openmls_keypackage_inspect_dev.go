package app

import (
	"errors"
	"flag"
	"fmt"
	"math"
)

func cmdOpenMLSKeyPackageInspectDev(args []string) error {
	fs := flag.NewFlagSet("openmls-keypackage-inspect-dev", flag.ContinueOnError)
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "local OpenMLS sidecar device label used for ownership evidence")
	keyPackagePath := fs.String("keypackage", "", "serialized OpenMLS KeyPackage artifact path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *sidecarDeviceLabel == "" || *keyPackagePath == "" {
		return errors.New("--sidecar-device-label and --keypackage are required")
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"keypackage-inspect",
		"--device-label",
		*sidecarDeviceLabel,
		"--keypackage",
		*keyPackagePath,
	)
	if err != nil {
		return err
	}

	deviceLabel := bootstrapStringField(envelope.Data, "device_label")
	if deviceLabel == "" {
		deviceLabel = *sidecarDeviceLabel
	}
	inspectedPath := bootstrapStringField(envelope.Data, "keypackage_path")
	if inspectedPath == "" {
		inspectedPath = *keyPackagePath
	}

	fmt.Println("openmls dev KeyPackage inspection")
	fmt.Println("command: openmls-keypackage-inspect-dev")
	fmt.Println("status: inspected")
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	fmt.Printf("sidecar_device_label: %s\n", deviceLabel)
	fmt.Printf("keypackage_path: %s\n", inspectedPath)
	bootstrapPrintOptionalString("key_package_ref", envelope.Data)
	bootstrapPrintOptionalString("key_package_artifact_sha256", envelope.Data)
	bootstrapPrintOptionalInteger("key_package_artifact_size_bytes", envelope.Data)
	bootstrapPrintOptionalInteger("lifetime_not_before_unix", envelope.Data)
	bootstrapPrintOptionalInteger("lifetime_not_after_unix", envelope.Data)
	bootstrapPrintOptionalInteger("inspected_at_unix", envelope.Data)
	bootstrapPrintOptionalBool("valid_at_inspection_time", envelope.Data)
	bootstrapPrintOptionalBool("openmls_validation_passed", envelope.Data)
	bootstrapPrintOptionalBool("owner_match", envelope.Data)
	bootstrapPrintOptionalString("owner_evidence", envelope.Data)
	bootstrapPrintOptionalString("identity_binding", envelope.Data)
	bootstrapPrintOptionalBool("local_state_mutated", envelope.Data)
	fmt.Println("warning: read-only dev KeyPackage inspection; local sidecar ownership evidence is not account, device, Relay Space, human identity, or trust verification")
	return nil
}

func bootstrapPrintOptionalInteger(key string, data map[string]any) {
	if data == nil {
		return
	}
	value, ok := data[key]
	if !ok {
		return
	}

	switch number := value.(type) {
	case float64:
		if math.Trunc(number) == number {
			fmt.Printf("%s: %.0f\n", key, number)
		}
	case int:
		fmt.Printf("%s: %d\n", key, number)
	case int64:
		fmt.Printf("%s: %d\n", key, number)
	case uint64:
		fmt.Printf("%s: %d\n", key, number)
	case jsonNumberLike:
		fmt.Printf("%s: %s\n", key, number.String())
	}
}

type jsonNumberLike interface {
	String() string
}
