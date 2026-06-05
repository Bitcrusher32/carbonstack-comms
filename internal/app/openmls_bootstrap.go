package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os/exec"
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
