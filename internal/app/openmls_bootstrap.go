package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os/exec"
	"path/filepath"

	"os"
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
		loadCheckSummaryPath, loadCheckProviderPath := openMLSConversationLoadCheckMetadataPaths(*sidecarDir, *sidecarDeviceLabel, *conversationLabel)
		loadCheckSummaryPresent := openMLSConversationLoadCheckRegularFileExists(loadCheckSummaryPath)
		loadCheckProviderPresent := openMLSConversationLoadCheckRegularFileExists(loadCheckProviderPath)
		if !loadCheckSummaryPresent {
			fmt.Println("openmls dev bootstrap")
			fmt.Println("command: openmls-conversation-load-check-dev")
			fmt.Println("status: metadata_missing")
			fmt.Println("sidecar_command: conversation-load-check")
			fmt.Printf("sidecar_device_label: %s\n", *sidecarDeviceLabel)
			fmt.Printf("sidecar_conversation_label: %s\n", *conversationLabel)
			fmt.Println("group_reloadable: false")
			fmt.Println("provider_reloadable: not_evaluated_by_load_check")
			fmt.Printf("summary_metadata_present: %t\n", loadCheckSummaryPresent)
			fmt.Printf("provider_storage_present: %t\n", loadCheckProviderPresent)
			fmt.Printf("summary_metadata_path: %s\n", loadCheckSummaryPath)
			fmt.Printf("provider_storage_path: %s\n", loadCheckProviderPath)
			fmt.Println("summary_metadata_warning: conversation-summary metadata is missing; conversation-load-check-dev is stricter than message-open and cannot confirm reloadability without summary metadata")
			fmt.Println("warning: dev/pre-alpha OpenMLS bootstrap path; not production conversation UX")
		}
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
		loadCheckSummaryPath, loadCheckProviderPath := openMLSConversationLoadCheckMetadataPaths(*sidecarDir, *sidecarDeviceLabel, *conversationLabel)
		fmt.Printf("provider_reloadable: %t\n", value)
		fmt.Println("summary_metadata_present: true")
		fmt.Println("provider_storage_present: true")
		fmt.Printf("summary_metadata_path: %s\n", loadCheckSummaryPath)
		fmt.Printf("provider_storage_path: %s\n", loadCheckProviderPath)
		fmt.Println("summary_metadata_warning: none")
	}
	fmt.Println("warning: dev/pre-alpha OpenMLS bootstrap path; not production conversation UX")

	return nil
}

func cmdOpenMLSConversationAddMemberDev(args []string) error {
	fs := flag.NewFlagSet("openmls-conversation-add-member-dev", flag.ExitOnError)
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS sidecar conversation label")
	memberKeyPackage := fs.String("member-keypackage", "", "OpenMLS member KeyPackage artifact path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sidecarDeviceLabel == "" || *conversationLabel == "" || *memberKeyPackage == "" {
		return errors.New("--sidecar-device-label, --conversation, and --member-keypackage are required")
	}

	memberKeyPackageAbs, err := filepath.Abs(*memberKeyPackage)
	if err != nil {
		return fmt.Errorf("resolve --member-keypackage: %w", err)
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"conversation-add-member",
		"--device-label", *sidecarDeviceLabel,
		"--conversation-label", *conversationLabel,
		"--member-keypackage", memberKeyPackageAbs,
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

	welcomeHint := bootstrapStringField(envelope.Data, "welcome_artifact_path_hint")
	welcomePath := bootstrapPathFromHint(*sidecarDir, welcomeHint)
	welcomeManifestHint := bootstrapStringField(envelope.Data, "welcome_manifest_path_hint")
	welcomeManifestPath := bootstrapPathFromHint(*sidecarDir, welcomeManifestHint)

	fmt.Println("openmls dev bootstrap")
	fmt.Println("command: openmls-conversation-add-member-dev")
	fmt.Println("status: welcome_created")
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	fmt.Printf("sidecar_device_label: %s\n", deviceLabel)
	fmt.Printf("sidecar_conversation_label: %s\n", conversation)
	bootstrapPrintOptionalString("member_keypackage_path_hint", envelope.Data)
	if welcomeHint != "" {
		fmt.Printf("welcome_artifact_path_hint: %s\n", welcomeHint)
	}
	if welcomePath != "" {
		fmt.Printf("welcome_artifact_path: %s\n", welcomePath)
	}
	if welcomeManifestHint != "" {
		fmt.Printf("welcome_manifest_path_hint: %s\n", welcomeManifestHint)
	}
	if welcomeManifestPath != "" {
		fmt.Printf("welcome_manifest_path: %s\n", welcomeManifestPath)
	}
	bootstrapPrintOptionalString("welcome_artifact_sha256", envelope.Data)
	bootstrapPrintOptionalNumber("welcome_artifact_size_bytes", envelope.Data)
	bootstrapPrintOptionalBool("member_added", envelope.Data)
	bootstrapPrintOptionalBool("welcome_artifact_written", envelope.Data)
	bootstrapPrintOptionalBool("group_reloadable", envelope.Data)
	bootstrapPrintOptionalNumber("member_count_before", envelope.Data)
	bootstrapPrintOptionalNumber("member_count_after", envelope.Data)
	bootstrapPrintOptionalString("epoch_before", envelope.Data)
	bootstrapPrintOptionalString("epoch_after", envelope.Data)
	fmt.Println("warning: dev/pre-alpha OpenMLS bootstrap path; not production membership UX")

	return nil
}

func cmdOpenMLSConversationJoinDev(args []string) error {
	fs := flag.NewFlagSet("openmls-conversation-join-dev", flag.ExitOnError)
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS sidecar conversation label")
	welcome := fs.String("welcome", "", "OpenMLS Welcome artifact path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sidecarDeviceLabel == "" || *conversationLabel == "" || *welcome == "" {
		return errors.New("--sidecar-device-label, --conversation, and --welcome are required")
	}

	welcomeAbs, err := filepath.Abs(*welcome)
	if err != nil {
		return fmt.Errorf("resolve --welcome: %w", err)
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"conversation-join",
		"--device-label", *sidecarDeviceLabel,
		"--conversation-label", *conversationLabel,
		"--welcome", welcomeAbs,
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
	fmt.Println("command: openmls-conversation-join-dev")
	fmt.Println("status: joined")
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	fmt.Printf("sidecar_device_label: %s\n", deviceLabel)
	fmt.Printf("sidecar_conversation_label: %s\n", conversation)
	bootstrapPrintOptionalString("welcome_artifact_path_hint", envelope.Data)
	bootstrapPrintOptionalBool("joined", envelope.Data)
	bootstrapPrintOptionalBool("group_reloadable", envelope.Data)
	bootstrapPrintOptionalNumber("member_count", envelope.Data)
	bootstrapPrintOptionalString("epoch", envelope.Data)
	bootstrapPrintOptionalString("join_summary_path_hint", envelope.Data)
	bootstrapPrintOptionalString("conversation_state_path_hint", envelope.Data)
	bootstrapPrintOptionalString("conversation_summary_path_hint", envelope.Data)
	bootstrapPrintOptionalString("provider_storage_path_hint", envelope.Data)
	fmt.Println("warning: dev/pre-alpha OpenMLS bootstrap path; not production membership UX")

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

func bootstrapPrintOptionalBool(key string, data map[string]any) {
	value, ok := bootstrapBoolField(data, key)
	if ok {
		fmt.Printf("%s: %t\n", key, value)
	}
}

func bootstrapPrintOptionalNumber(key string, data map[string]any) {
	if data == nil {
		return
	}
	value, ok := data[key]
	if !ok {
		return
	}
	switch number := value.(type) {
	case float64:
		if number == float64(int64(number)) {
			fmt.Printf("%s: %d\n", key, int64(number))
			return
		}
		fmt.Printf("%s: %v\n", key, number)
	case int:
		fmt.Printf("%s: %d\n", key, number)
	case int64:
		fmt.Printf("%s: %d\n", key, number)
	default:
		fmt.Printf("%s: %v\n", key, value)
	}
}

func openMLSConversationLoadCheckMetadataPaths(sidecarDir string, sidecarDeviceLabel string, conversation string) (string, string) {
	conversationDir := filepath.Join(sidecarDir, ".carbonstack-openmls-sidecar-state", "dev", "devices", sidecarDeviceLabel, "conversations", conversation)
	return filepath.Join(conversationDir, "conversation-summary.json"), filepath.Join(conversationDir, "provider-storage.json")
}

func openMLSConversationLoadCheckRegularFileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	return !info.IsDir()
}
