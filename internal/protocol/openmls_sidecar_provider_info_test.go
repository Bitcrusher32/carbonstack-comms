package protocol

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

const openMLSSidecarDir = "mls/research/openmls-sidecar"

type openMLSSidecarProviderInfo struct {
	Provider                string   `json:"provider"`
	Implementation          string   `json:"implementation"`
	Mode                    string   `json:"mode"`
	Phase                   string   `json:"phase"`
	Capabilities            []string `json:"capabilities"`
	Unsupported             []string `json:"unsupported"`
	SecurityLevel           string   `json:"security_level"`
	PrivateMaterialIncluded bool     `json:"private_material_included"`
	Warnings                []string `json:"warnings"`
}

func TestOpenMLSSidecarProviderInfoCommand(t *testing.T) {
	sidecarDir := filepath.Clean(openMLSSidecarDir)

	cmd := exec.Command("cargo", "run", "--quiet", "--", "provider-info")
	cmd.Dir = sidecarDir

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("run OpenMLS sidecar provider-info: %v", err)
	}

	var info openMLSSidecarProviderInfo
	if err := json.Unmarshal(output, &info); err != nil {
		t.Fatalf("parse provider-info JSON: %v\noutput:\n%s", err, string(output))
	}

	if info.Provider != "openmls" {
		t.Fatalf("provider = %q, want openmls", info.Provider)
	}

	if info.Implementation != "carbonstack-openmls-sidecar" {
		t.Fatalf("implementation = %q, want carbonstack-openmls-sidecar", info.Implementation)
	}

	if info.Mode != "experimental-sidecar" {
		t.Fatalf("mode = %q, want experimental-sidecar", info.Mode)
	}

	if info.Phase != "phase2d-provider-info" {
		t.Fatalf("phase = %q, want phase2d-provider-info", info.Phase)
	}

	if info.PrivateMaterialIncluded {
		t.Fatal("provider-info must not include private material")
	}

	assertStringPresent(t, info.Capabilities, "provider-info")

	unsupported := []string{
		"identity-create",
		"public-bundle-export",
		"conversation-create",
		"conversation-add-member",
		"conversation-join",
		"message-protect",
		"message-open",
		"state-checkpoint",
		"state-load-check",
	}

	for _, command := range unsupported {
		assertStringPresent(t, info.Unsupported, command)
	}

	if len(info.Warnings) == 0 {
		t.Fatal("expected provider-info warnings")
	}
}

func assertStringPresent(t *testing.T, values []string, want string) {
	t.Helper()

	for _, value := range values {
		if value == want {
			return
		}
	}

	t.Fatalf("expected %q in %#v", want, values)
}
