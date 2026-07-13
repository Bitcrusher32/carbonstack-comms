package app

import (
	"errors"
	"strings"
	"testing"
)

func TestOpenMLSKeyPackageInspectDevRequiresArguments(t *testing.T) {
	err := cmdOpenMLSKeyPackageInspectDev([]string{
		"--sidecar-device-label",
		"alice",
	})
	if err == nil || !strings.Contains(
		err.Error(),
		"--sidecar-device-label and --keypackage are required",
	) {
		t.Fatalf("expected required argument error, got %v", err)
	}
}

func TestOpenMLSKeyPackageInspectDevPrintsStableReadOnlyOutput(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	t.Cleanup(func() {
		runOpenMLSBootstrapSidecarForCommand = old
	})

	var gotDir string
	var gotCommand string
	var gotArgs []string

	runOpenMLSBootstrapSidecarForCommand = func(
		sidecarDir string,
		sidecarCommand string,
		args ...string,
	) (openMLSSidecarBootstrapEnvelope, error) {
		gotDir = sidecarDir
		gotCommand = sidecarCommand
		gotArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "keypackage-inspect",
			Data: map[string]any{
				"device_label":                    "alice-device",
				"keypackage_path":                 "alice.keypackage.bin",
				"key_package_ref":                 "sha256:keypackage-ref",
				"key_package_artifact_sha256":     "sha256:artifact",
				"key_package_artifact_size_bytes": float64(1234),
				"lifetime_not_before_unix":        float64(10),
				"lifetime_not_after_unix":         float64(20),
				"inspected_at_unix":               float64(15),
				"valid_at_inspection_time":        true,
				"openmls_validation_passed":       true,
				"owner_match":                     true,
				"owner_evidence":                  "local-sidecar-public-bundle-summary-and-manifest",
				"identity_binding":                "local-sidecar-device-label-only",
				"local_state_mutated":             false,
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSKeyPackageInspectDev([]string{
			"--sidecar-dir",
			"sidecar-test-dir",
			"--sidecar-device-label",
			"alice-device",
			"--keypackage",
			"alice.keypackage.bin",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotDir != "sidecar-test-dir" {
		t.Fatalf("sidecar dir = %q", gotDir)
	}
	if gotCommand != "keypackage-inspect" {
		t.Fatalf("sidecar command = %q", gotCommand)
	}
	wantArgs := []string{
		"--device-label",
		"alice-device",
		"--keypackage",
		"alice.keypackage.bin",
	}
	if strings.Join(gotArgs, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Fatalf("sidecar args = %#v, want %#v", gotArgs, wantArgs)
	}

	for _, marker := range []string{
		"command: openmls-keypackage-inspect-dev",
		"status: inspected",
		"sidecar_command: keypackage-inspect",
		"sidecar_device_label: alice-device",
		"key_package_ref: sha256:keypackage-ref",
		"key_package_artifact_sha256: sha256:artifact",
		"key_package_artifact_size_bytes: 1234",
		"lifetime_not_before_unix: 10",
		"lifetime_not_after_unix: 20",
		"valid_at_inspection_time: true",
		"openmls_validation_passed: true",
		"owner_match: true",
		"identity_binding: local-sidecar-device-label-only",
		"local_state_mutated: false",
	} {
		if !strings.Contains(out, marker) {
			t.Fatalf("output missing %q:\n%s", marker, out)
		}
	}
}

func TestOpenMLSKeyPackageInspectDevDoesNotPrintSuccessOnSidecarFailure(
	t *testing.T,
) {
	old := runOpenMLSBootstrapSidecarForCommand
	t.Cleanup(func() {
		runOpenMLSBootstrapSidecarForCommand = old
	})

	runOpenMLSBootstrapSidecarForCommand = func(
		sidecarDir string,
		sidecarCommand string,
		args ...string,
	) (openMLSSidecarBootstrapEnvelope, error) {
		return openMLSSidecarBootstrapEnvelope{}, errors.New(
			"keypackage_owner_mismatch",
		)
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSKeyPackageInspectDev([]string{
			"--sidecar-device-label",
			"alice-device",
			"--keypackage",
			"bob.keypackage.bin",
		})
	})
	if err == nil {
		t.Fatal("expected sidecar failure")
	}
	if strings.Contains(out, "status: inspected") {
		t.Fatalf("unexpected success output:\n%s", out)
	}
}
