package app

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestOpenMLSIdentityCreateDevRequiresDeviceLabel(t *testing.T) {
	err := cmdOpenMLSIdentityCreateDev([]string{})
	if err == nil || !strings.Contains(err.Error(), "--sidecar-device-label is required") {
		t.Fatalf("expected required sidecar device label error, got %v", err)
	}
}

func TestOpenMLSIdentityStatusDevRequiresDeviceLabel(t *testing.T) {
	err := cmdOpenMLSIdentityStatusDev([]string{})
	if err == nil || !strings.Contains(err.Error(), "--sidecar-device-label is required") {
		t.Fatalf("expected required sidecar device label error, got %v", err)
	}
}

func TestOpenMLSIdentityCreateDevInvokesSidecarAndPrintsStableOutput(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	defer func() { runOpenMLSBootstrapSidecarForCommand = old }()

	var gotDir string
	var gotCommand string
	var gotArgs []string

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		gotDir = sidecarDir
		gotCommand = sidecarCommand
		gotArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "identity-create",
			Data: map[string]any{
				"device_label": "alice-device",
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSIdentityCreateDev([]string{
			"--sidecar-dir", "sidecar-test-dir",
			"--sidecar-device-label", "alice-device",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotDir != "sidecar-test-dir" {
		t.Fatalf("unexpected sidecar dir: %q", gotDir)
	}
	if gotCommand != "identity-create" {
		t.Fatalf("unexpected sidecar command: %q", gotCommand)
	}
	wantArgs := "--device-label alice-device"
	if strings.Join(gotArgs, " ") != wantArgs {
		t.Fatalf("unexpected sidecar args: %q", strings.Join(gotArgs, " "))
	}

	for _, want := range []string{
		"openmls dev bootstrap",
		"command: openmls-identity-create-dev",
		"status: created",
		"sidecar_command: identity-create",
		"sidecar_device_label: alice-device",
		"warning: dev/pre-alpha OpenMLS bootstrap path; not production identity UX",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSIdentityStatusDevInvokesSidecarAndPrintsStableOutput(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	defer func() { runOpenMLSBootstrapSidecarForCommand = old }()

	var gotCommand string
	var gotArgs []string

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		gotCommand = sidecarCommand
		gotArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "identity-status",
			Data: map[string]any{
				"device_label":    "bob-device",
				"identity_exists": true,
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSIdentityStatusDev([]string{
			"--sidecar-device-label", "bob-device",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotCommand != "identity-status" {
		t.Fatalf("unexpected sidecar command: %q", gotCommand)
	}
	wantArgs := "--device-label bob-device"
	if strings.Join(gotArgs, " ") != wantArgs {
		t.Fatalf("unexpected sidecar args: %q", strings.Join(gotArgs, " "))
	}

	for _, want := range []string{
		"command: openmls-identity-status-dev",
		"status: loaded",
		"sidecar_command: identity-status",
		"sidecar_device_label: bob-device",
		"identity_exists: true",
		"warning: dev/pre-alpha OpenMLS bootstrap path; not production identity UX",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSIdentityCreateDevDoesNotPrintSuccessOnSidecarFailure(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	defer func() { runOpenMLSBootstrapSidecarForCommand = old }()

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		return openMLSSidecarBootstrapEnvelope{}, errors.New("sidecar exploded")
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSIdentityCreateDev([]string{
			"--sidecar-device-label", "alice-device",
		})
	})
	if err == nil {
		t.Fatal("expected sidecar error")
	}
	if strings.Contains(out, "status: created") {
		t.Fatalf("unexpected success output after sidecar failure:\n%s", out)
	}
}

func captureOpenMLSBootstrapOutput(fn func() error) (string, error) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}

	os.Stdout = w
	runErr := fn()
	closeErr := w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, copyErr := io.Copy(&buf, r)
	_ = r.Close()

	if closeErr != nil {
		return buf.String(), closeErr
	}
	if copyErr != nil {
		return buf.String(), copyErr
	}
	return buf.String(), runErr
}
