package app

import (
	"strings"
	"testing"
)

func TestOpenMLSKeyPackageGenerateDevInvokesSidecar(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	t.Cleanup(func() { runOpenMLSBootstrapSidecarForCommand = old })

	var gotCommand string
	var gotArgs []string
	runOpenMLSBootstrapSidecarForCommand = func(
		sidecarDir string,
		sidecarCommand string,
		args ...string,
	) (openMLSSidecarBootstrapEnvelope, error) {
		gotCommand = sidecarCommand
		gotArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "keypackage-generate",
			Data: map[string]any{
				"device_label":            "alice",
				"generation_id":           "kp-000002",
				"sequence":                float64(2),
				"request_id":              "rotate-2",
				"key_package_ref":         "sha256:ref",
				"artifact_path":           "keypackages/kp-000002/keypackage.bin",
				"manifest_path":           "keypackages/kp-000002/manifest.json",
				"current_generation_id":   "kp-000002",
				"generation_count":        float64(2),
				"idempotent_replay":       false,
				"recovered_from_manifest": false,
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSKeyPackageGenerateDev([]string{
			"--sidecar-dir", "sidecar-test",
			"--sidecar-device-label", "alice",
			"--request-id", "rotate-2",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotCommand != "keypackage-generate" {
		t.Fatalf("command = %q", gotCommand)
	}
	wantArgs := []string{"--device-label", "alice", "--request-id", "rotate-2"}
	if strings.Join(gotArgs, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Fatalf("args = %#v", gotArgs)
	}
	for _, marker := range []string{
		"command: openmls-keypackage-generate-dev",
		"generation_id: kp-000002",
		"request_id: rotate-2",
		"idempotent_replay: false",
	} {
		if !strings.Contains(out, marker) {
			t.Fatalf("output missing %q:\n%s", marker, out)
		}
	}
}

func TestOpenMLSKeyPackageInventoryDevInvokesSidecar(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	t.Cleanup(func() { runOpenMLSBootstrapSidecarForCommand = old })

	runOpenMLSBootstrapSidecarForCommand = func(
		sidecarDir string,
		sidecarCommand string,
		args ...string,
	) (openMLSSidecarBootstrapEnvelope, error) {
		if sidecarCommand != "keypackage-inventory" {
			t.Fatalf("command = %q", sidecarCommand)
		}
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "keypackage-inventory",
			Data: map[string]any{
				"device_label":          "alice",
				"current_generation_id": "kp-000003",
				"generation_count":      float64(3),
				"active_count":          float64(2),
				"retired_count":         float64(1),
				"local_state_mutated":   false,
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSKeyPackageInventoryDev([]string{
			"--sidecar-device-label", "alice",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"command: openmls-keypackage-inventory-dev",
		"generation_count: 3",
		"retired_count: 1",
		"local_state_mutated: false",
	} {
		if !strings.Contains(out, marker) {
			t.Fatalf("output missing %q:\n%s", marker, out)
		}
	}
}

func TestOpenMLSKeyPackageRetireDevInvokesSidecar(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	t.Cleanup(func() { runOpenMLSBootstrapSidecarForCommand = old })

	runOpenMLSBootstrapSidecarForCommand = func(
		sidecarDir string,
		sidecarCommand string,
		args ...string,
	) (openMLSSidecarBootstrapEnvelope, error) {
		if sidecarCommand != "keypackage-retire" {
			t.Fatalf("command = %q", sidecarCommand)
		}
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "keypackage-retire",
			Data: map[string]any{
				"device_label":              "alice",
				"generation_id":             "kp-000001",
				"status":                    "retired",
				"idempotent_replay":         true,
				"artifact_retained":         true,
				"provider_storage_retained": true,
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSKeyPackageRetireDev([]string{
			"--sidecar-device-label", "alice",
			"--generation-id", "kp-000001",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"command: openmls-keypackage-retire-dev",
		"generation_id: kp-000001",
		"idempotent_replay: true",
		"artifact_retained: true",
	} {
		if !strings.Contains(out, marker) {
			t.Fatalf("output missing %q:\n%s", marker, out)
		}
	}
}

func TestOpenMLSKeyPackageLifecycleDevRequiresArguments(t *testing.T) {
	if err := cmdOpenMLSKeyPackageGenerateDev([]string{"--sidecar-device-label", "alice"}); err == nil {
		t.Fatal("generate should require request id")
	}
	if err := cmdOpenMLSKeyPackageInventoryDev(nil); err == nil {
		t.Fatal("inventory should require device label")
	}
	if err := cmdOpenMLSKeyPackageRetireDev([]string{"--sidecar-device-label", "alice"}); err == nil {
		t.Fatal("retire should require generation id")
	}
}

func TestOpenMLSKeyPackageInspectDevPassesGenerationManifest(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	t.Cleanup(func() { runOpenMLSBootstrapSidecarForCommand = old })

	var gotArgs []string
	runOpenMLSBootstrapSidecarForCommand = func(
		sidecarDir string,
		sidecarCommand string,
		args ...string,
	) (openMLSSidecarBootstrapEnvelope, error) {
		gotArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "keypackage-inspect",
			Data: map[string]any{
				"device_label":             "alice",
				"keypackage_path":          "keypackage.bin",
				"generation_manifest_path": "manifest.json",
				"owner_match":              true,
				"local_state_mutated":      false,
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSKeyPackageInspectDev([]string{
			"--sidecar-device-label", "alice",
			"--keypackage", "keypackage.bin",
			"--generation-manifest", "manifest.json",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--device-label", "alice",
		"--keypackage", "keypackage.bin",
		"--generation-manifest", "manifest.json",
	}
	if strings.Join(gotArgs, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("args = %#v want %#v", gotArgs, want)
	}
	if !strings.Contains(out, "generation_manifest_path: manifest.json") {
		t.Fatalf("output missing manifest path:\n%s", out)
	}
}
