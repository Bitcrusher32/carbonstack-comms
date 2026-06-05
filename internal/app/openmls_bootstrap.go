package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"path/filepath"
)

type openMLSSidecarBootstrapEnvelope struct {
	OK      bool                         `json:"ok"`
	Command string                       `json:"command"`
	Data    map[string]any               `json:"data"`
	Error   *openMLSSidecarErrorEnvelope `json:"error"`
}

var runOpenMLSBootstrapSidecarForCommand = runOpenMLSBootstrapSidecar

func cmdOpenMLSIdentityCreateDev(args []string) error {
	fs := flag.NewFlagSet("openmls-identity-create-dev", flag.ExitOnError)
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sidecarDeviceLabel == "" {
		return errors.New("--sidecar-device-label is required")
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"identity-create",
		"--device-label", *sidecarDeviceLabel,
	)
	if err != nil {
		return err
	}

	deviceLabel := bootstrapStringField(envelope.Data, "device_label")
	if deviceLabel == "" {
		deviceLabel = *sidecarDeviceLabel
	}

	fmt.Println("openmls dev bootstrap")
	fmt.Println("command: openmls-identity-create-dev")
	fmt.Println("status: created")
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	fmt.Printf("sidecar_device_label: %s\n", deviceLabel)
	fmt.Println("warning: dev/pre-alpha OpenMLS bootstrap path; not production identity UX")

	return nil
}

func cmdOpenMLSIdentityStatusDev(args []string) error {
	fs := flag.NewFlagSet("openmls-identity-status-dev", flag.ExitOnError)
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sidecarDeviceLabel == "" {
		return errors.New("--sidecar-device-label is required")
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"identity-status",
		"--device-label", *sidecarDeviceLabel,
	)
	if err != nil {
		return err
	}

	deviceLabel := bootstrapStringField(envelope.Data, "device_label")
	if deviceLabel == "" {
		deviceLabel = *sidecarDeviceLabel
	}

	fmt.Println("openmls dev bootstrap")
	fmt.Println("command: openmls-identity-status-dev")
	fmt.Println("status: loaded")
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	fmt.Printf("sidecar_device_label: %s\n", deviceLabel)
	if value, ok := bootstrapBoolField(envelope.Data, "identity_exists"); ok {
		fmt.Printf("identity_exists: %t\n", value)
	}
	fmt.Println("warning: dev/pre-alpha OpenMLS bootstrap path; not production identity UX")

	return nil
}

func cmdOpenMLSBundleExportDev(args []string) error {
	fs := flag.NewFlagSet("openmls-bundle-export-dev", flag.ExitOnError)
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	writeArtifact := fs.Bool("write-artifact", false, "write OpenMLS KeyPackage artifact")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sidecarDeviceLabel == "" {
		return errors.New("--sidecar-device-label is required")
	}

	sidecarArgs := []string{"--device-label", *sidecarDeviceLabel}
	if *writeArtifact {
		sidecarArgs = append(sidecarArgs, "--write-artifact")
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"public-bundle-export",
		sidecarArgs...,
	)
	if err != nil {
		return err
	}

	deviceLabel := bootstrapStringField(envelope.Data, "device_label")
	if deviceLabel == "" {
		deviceLabel = *sidecarDeviceLabel
	}

	keyPackageHint := bootstrapStringField(envelope.Data, "key_package_artifact_path_hint")
	keyPackagePath := bootstrapPathFromHint(*sidecarDir, keyPackageHint)

	fmt.Println("openmls dev bootstrap")
	fmt.Println("command: openmls-bundle-export-dev")
	fmt.Println("status: exported")
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	fmt.Printf("sidecar_device_label: %s\n", deviceLabel)
	if keyPackageHint != "" {
		fmt.Printf("key_package_artifact_path_hint: %s\n", keyPackageHint)
	}
	if keyPackagePath != "" {
		fmt.Printf("key_package_artifact_path: %s\n", keyPackagePath)
	}
	fmt.Println("warning: dev/pre-alpha OpenMLS bootstrap path; not production identity UX")

	return nil
}

func cmdOpenMLSConversationCreateDev(args []string) error {
	fs := flag.NewFlagSet("openmls-conversation-create-dev", flag.ExitOnError)
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS sidecar conversation label")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sidecarDeviceLabel == "" || *conversationLabel == "" {
		return errors.New("--sidecar-device-label and --conversation are required")
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"conversation-create",
		"--device-label", *sidecarDeviceLabel,
		"--conversation-label", *conversationLabel,
	)
	if err != nil {
		return err
	}

	deviceLabel := bootstrapStringField(envelope.Data, "device_label")
	if deviceLabel == "" {
		deviceLabel = *sidecarDeviceLabel
	}
	conversation := bootstrapStringField(envelope.Data, "conversation_label")
	if conversation == "" {
		conversation = *conversationLabel
	}

	fmt.Println("openmls dev bootstrap")
	fmt.Println("command: openmls-conversation-create-dev")
	fmt.Println("status: created")
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	fmt.Printf("sidecar_device_label: %s\n", deviceLabel)
	fmt.Printf("sidecar_conversation_label: %s\n", conversation)
	bootstrapPrintOptionalString("conversation_state_path_hint", envelope.Data)
	bootstrapPrintOptionalString("conversation_summary_path_hint", envelope.Data)
	bootstrapPrintOptionalString("provider_storage_path_hint", envelope.Data)
	fmt.Println("warning: dev/pre-alpha OpenMLS bootstrap path; not production conversation UX")

	return nil
}

func cmdOpenMLSConversationLoadCheckDev(args []string) error {
	fs := flag.NewFlagSet("openmls-conversation-load-check-dev", flag.ExitOnError)
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS sidecar conversation label")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sidecarDeviceLabel == "" || *conversationLabel == "" {
		return errors.New("--sidecar-device-label and --conversation are required")
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"conversation-load-check",
		"--device-label", *sidecarDeviceLabel,
		"--conversation-label", *conversationLabel,
	)
	if err != nil {
		return err
	}

	deviceLabel := bootstrapStringField(envelope.Data, "device_label")
	if deviceLabel == "" {
		deviceLabel = *sidecarDeviceLabel
	}
	conversation := bootstrapStringField(envelope.Data, "conversation_label")
	if conversation == "" {
		conversation = *conversationLabel
	}

	fmt.Println("openmls dev bootstrap")
	fmt.Println("command: openmls-conversation-load-check-dev")
	fmt.Println("status: loaded")
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	fmt.Printf("sidecar_device_label: %s\n", deviceLabel)
	fmt.Printf("sidecar_conversation_label: %s\n", conversation)
	if value, ok := bootstrapBoolField(envelope.Data, "group_reloadable"); ok {
		fmt.Printf("group_reloadable: %t\n", value)
	}
	fmt.Println("warning: dev/pre-alpha OpenMLS bootstrap path; not production conversation UX")

	return nil
}

func runOpenMLSBootstrapSidecar(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
	cmdArgs := append([]string{"run", "--quiet", "--", sidecarCommand}, args...)
	cmd := exec.Command("cargo", cmdArgs...)
	cmd.Dir = sidecarDir

	output, execErr := cmd.CombinedOutput()

	var envelope openMLSSidecarBootstrapEnvelope
	if err := json.Unmarshal(output, &envelope); err != nil {
		if execErr != nil {
			return envelope, fmt.Errorf("run OpenMLS sidecar %s: %w: %s", sidecarCommand, execErr, string(output))
		}
		return envelope, fmt.Errorf("parse OpenMLS sidecar %s JSON: %w: %s", sidecarCommand, err, string(output))
	}

	if !envelope.OK {
		if envelope.Error != nil {
			return envelope, fmt.Errorf("OpenMLS sidecar %s failed: %s: %s", sidecarCommand, envelope.Error.Code, envelope.Error.Message)
		}
		return envelope, fmt.Errorf("OpenMLS sidecar %s failed", sidecarCommand)
	}

	if execErr != nil {
		return envelope, fmt.Errorf("run OpenMLS sidecar %s: %w", sidecarCommand, execErr)
	}

	if envelope.Command == "" {
		envelope.Command = sidecarCommand
	}

	return envelope, nil
}

func bootstrapStringField(data map[string]any, key string) string {
	if data == nil {
		return ""
	}
	value, ok := data[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return text
}

func bootstrapBoolField(data map[string]any, key string) (bool, bool) {
	if data == nil {
		return false, false
	}
	value, ok := data[key]
	if !ok {
		return false, false
	}
	b, ok := value.(bool)
	return b, ok
}

func bootstrapPrintOptionalString(key string, data map[string]any) {
	value := bootstrapStringField(data, key)
	if value != "" {
		fmt.Printf("%s: %s\n", key, value)
	}
}

func bootstrapPathFromHint(sidecarDir string, hint string) string {
	if hint == "" {
		return ""
	}
	if filepath.IsAbs(hint) {
		return filepath.Clean(hint)
	}
	return filepath.Clean(filepath.Join(sidecarDir, hint))
}
