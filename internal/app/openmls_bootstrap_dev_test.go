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

func TestOpenMLSBundleExportDevRequiresDeviceLabel(t *testing.T) {
	err := cmdOpenMLSBundleExportDev([]string{})
	if err == nil || !strings.Contains(err.Error(), "--sidecar-device-label is required") {
		t.Fatalf("expected required sidecar device label error, got %v", err)
	}
}

func TestOpenMLSConversationCreateDevRequiresDeviceAndConversation(t *testing.T) {
	err := cmdOpenMLSConversationCreateDev([]string{"--sidecar-device-label", "alice-device"})
	if err == nil || !strings.Contains(err.Error(), "--sidecar-device-label and --conversation are required") {
		t.Fatalf("expected required sidecar device label and conversation error, got %v", err)
	}
}

func TestOpenMLSConversationLoadCheckDevRequiresDeviceAndConversation(t *testing.T) {
	err := cmdOpenMLSConversationLoadCheckDev([]string{"--conversation", "test-conversation"})
	if err == nil || !strings.Contains(err.Error(), "--sidecar-device-label and --conversation are required") {
		t.Fatalf("expected required sidecar device label and conversation error, got %v", err)
	}
}

func TestOpenMLSBundleExportDevInvokesSidecarAndPrintsPaths(t *testing.T) {
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
			Command: "public-bundle-export",
			Data: map[string]any{
				"device_label":                   "bob-device",
				"key_package_artifact_path_hint": ".carbonstack-openmls-sidecar-state/dev/devices/bob-device/public-bundle.keypackage.bin",
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSBundleExportDev([]string{
			"--sidecar-dir", "sidecar-test-dir",
			"--sidecar-device-label", "bob-device",
			"--write-artifact",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotDir != "sidecar-test-dir" {
		t.Fatalf("unexpected sidecar dir: %q", gotDir)
	}
	if gotCommand != "public-bundle-export" {
		t.Fatalf("unexpected sidecar command: %q", gotCommand)
	}
	wantArgs := "--device-label bob-device --write-artifact"
	if strings.Join(gotArgs, " ") != wantArgs {
		t.Fatalf("unexpected sidecar args: %q", strings.Join(gotArgs, " "))
	}

	for _, want := range []string{
		"command: openmls-bundle-export-dev",
		"status: exported",
		"sidecar_command: public-bundle-export",
		"sidecar_device_label: bob-device",
		"key_package_artifact_path_hint: .carbonstack-openmls-sidecar-state/dev/devices/bob-device/public-bundle.keypackage.bin",
		"key_package_artifact_path: sidecar-test-dir/.carbonstack-openmls-sidecar-state/dev/devices/bob-device/public-bundle.keypackage.bin",
		"warning: dev/pre-alpha OpenMLS bootstrap path; not production identity UX",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSConversationCreateDevInvokesSidecarAndPrintsStableOutput(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	defer func() { runOpenMLSBootstrapSidecarForCommand = old }()

	var gotCommand string
	var gotArgs []string

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		gotCommand = sidecarCommand
		gotArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "conversation-create",
			Data: map[string]any{
				"device_label":                   "alice-device",
				"conversation_label":             "test-conversation",
				"conversation_state_path_hint":   ".carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation",
				"conversation_summary_path_hint": ".carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation/conversation-summary.json",
				"provider_storage_path_hint":     ".carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation/provider-storage.json",
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSConversationCreateDev([]string{
			"--sidecar-device-label", "alice-device",
			"--conversation", "test-conversation",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotCommand != "conversation-create" {
		t.Fatalf("unexpected sidecar command: %q", gotCommand)
	}
	wantArgs := "--device-label alice-device --conversation-label test-conversation"
	if strings.Join(gotArgs, " ") != wantArgs {
		t.Fatalf("unexpected sidecar args: %q", strings.Join(gotArgs, " "))
	}

	for _, want := range []string{
		"command: openmls-conversation-create-dev",
		"status: created",
		"sidecar_command: conversation-create",
		"sidecar_device_label: alice-device",
		"sidecar_conversation_label: test-conversation",
		"conversation_state_path_hint: .carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation",
		"conversation_summary_path_hint: .carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation/conversation-summary.json",
		"provider_storage_path_hint: .carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation/provider-storage.json",
		"warning: dev/pre-alpha OpenMLS bootstrap path; not production conversation UX",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSConversationLoadCheckDevInvokesSidecarAndPrintsStableOutput(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	defer func() { runOpenMLSBootstrapSidecarForCommand = old }()

	var gotCommand string
	var gotArgs []string

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		gotCommand = sidecarCommand
		gotArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "conversation-load-check",
			Data: map[string]any{
				"device_label":       "alice-device",
				"conversation_label": "test-conversation",
				"group_reloadable":   true,
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSConversationLoadCheckDev([]string{
			"--sidecar-device-label", "alice-device",
			"--conversation", "test-conversation",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotCommand != "conversation-load-check" {
		t.Fatalf("unexpected sidecar command: %q", gotCommand)
	}
	wantArgs := "--device-label alice-device --conversation-label test-conversation"
	if strings.Join(gotArgs, " ") != wantArgs {
		t.Fatalf("unexpected sidecar args: %q", strings.Join(gotArgs, " "))
	}

	for _, want := range []string{
		"command: openmls-conversation-load-check-dev",
		"status: loaded",
		"sidecar_command: conversation-load-check",
		"sidecar_device_label: alice-device",
		"sidecar_conversation_label: test-conversation",
		"group_reloadable: true",
		"warning: dev/pre-alpha OpenMLS bootstrap path; not production conversation UX",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSConversationAddMemberDevRequiresDeviceConversationAndKeyPackage(t *testing.T) {
	err := cmdOpenMLSConversationAddMemberDev([]string{
		"--sidecar-device-label", "alice-device",
		"--conversation", "test-conversation",
	})
	if err == nil || !strings.Contains(err.Error(), "--sidecar-device-label, --conversation, and --member-keypackage are required") {
		t.Fatalf("expected required add-member args error, got %v", err)
	}
}

func TestOpenMLSConversationJoinDevRequiresDeviceConversationAndWelcome(t *testing.T) {
	err := cmdOpenMLSConversationJoinDev([]string{
		"--sidecar-device-label", "bob-device",
		"--conversation", "test-conversation",
	})
	if err == nil || !strings.Contains(err.Error(), "--sidecar-device-label, --conversation, and --welcome are required") {
		t.Fatalf("expected required join args error, got %v", err)
	}
}

func TestOpenMLSConversationAddMemberDevInvokesSidecarAndPrintsWelcomePaths(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	defer func() { runOpenMLSBootstrapSidecarForCommand = old }()

	var gotCommand string
	var gotArgs []string

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		gotCommand = sidecarCommand
		gotArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "conversation-add-member",
			Data: map[string]any{
				"device_label":                "alice-device",
				"conversation_label":          "test-conversation",
				"member_keypackage_path_hint": "/tmp/bob.keypackage.bin",
				"welcome_artifact_path_hint":  ".carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation/welcome.bin",
				"welcome_manifest_path_hint":  ".carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation/welcome-manifest.json",
				"welcome_artifact_sha256":     "sha256:test",
				"welcome_artifact_size_bytes": float64(879),
				"member_added":                true,
				"welcome_artifact_written":    true,
				"group_reloadable":            true,
				"member_count_before":         float64(1),
				"member_count_after":          float64(2),
				"epoch_before":                "GroupEpoch(0)",
				"epoch_after":                 "GroupEpoch(1)",
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSConversationAddMemberDev([]string{
			"--sidecar-dir", "sidecar-test-dir",
			"--sidecar-device-label", "alice-device",
			"--conversation", "test-conversation",
			"--member-keypackage", "/tmp/bob.keypackage.bin",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotCommand != "conversation-add-member" {
		t.Fatalf("unexpected sidecar command: %q", gotCommand)
	}
	if strings.Join(gotArgs[:4], " ") != "--device-label alice-device --conversation-label test-conversation" {
		t.Fatalf("unexpected leading sidecar args: %q", strings.Join(gotArgs, " "))
	}
	if gotArgs[4] != "--member-keypackage" {
		t.Fatalf("expected member-keypackage flag, got args: %q", strings.Join(gotArgs, " "))
	}

	for _, want := range []string{
		"command: openmls-conversation-add-member-dev",
		"status: welcome_created",
		"sidecar_command: conversation-add-member",
		"sidecar_device_label: alice-device",
		"sidecar_conversation_label: test-conversation",
		"member_keypackage_path_hint: /tmp/bob.keypackage.bin",
		"welcome_artifact_path_hint: .carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation/welcome.bin",
		"welcome_artifact_path: sidecar-test-dir/.carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation/welcome.bin",
		"welcome_manifest_path_hint: .carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation/welcome-manifest.json",
		"welcome_manifest_path: sidecar-test-dir/.carbonstack-openmls-sidecar-state/dev/devices/alice-device/conversations/test-conversation/welcome-manifest.json",
		"welcome_artifact_sha256: sha256:test",
		"welcome_artifact_size_bytes: 879",
		"member_added: true",
		"welcome_artifact_written: true",
		"group_reloadable: true",
		"member_count_before: 1",
		"member_count_after: 2",
		"epoch_before: GroupEpoch(0)",
		"epoch_after: GroupEpoch(1)",
		"warning: dev/pre-alpha OpenMLS bootstrap path; not production membership UX",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSConversationJoinDevInvokesSidecarAndPrintsStableOutput(t *testing.T) {
	old := runOpenMLSBootstrapSidecarForCommand
	defer func() { runOpenMLSBootstrapSidecarForCommand = old }()

	var gotCommand string
	var gotArgs []string

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		gotCommand = sidecarCommand
		gotArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "conversation-join",
			Data: map[string]any{
				"device_label":                   "bob-device",
				"conversation_label":             "test-conversation",
				"welcome_artifact_path_hint":     "/tmp/welcome.bin",
				"joined":                         true,
				"group_reloadable":               true,
				"member_count":                   float64(2),
				"epoch":                          "GroupEpoch(1)",
				"join_summary_path_hint":         ".carbonstack-openmls-sidecar-state/dev/devices/bob-device/conversations/test-conversation/join-summary.json",
				"conversation_state_path_hint":   ".carbonstack-openmls-sidecar-state/dev/devices/bob-device/conversations/test-conversation",
				"conversation_summary_path_hint": ".carbonstack-openmls-sidecar-state/dev/devices/bob-device/conversations/test-conversation/conversation-summary.json",
				"provider_storage_path_hint":     ".carbonstack-openmls-sidecar-state/dev/devices/bob-device/conversations/test-conversation/provider-storage.json",
			},
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSConversationJoinDev([]string{
			"--sidecar-device-label", "bob-device",
			"--conversation", "test-conversation",
			"--welcome", "/tmp/welcome.bin",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotCommand != "conversation-join" {
		t.Fatalf("unexpected sidecar command: %q", gotCommand)
	}
	if strings.Join(gotArgs[:4], " ") != "--device-label bob-device --conversation-label test-conversation" {
		t.Fatalf("unexpected leading sidecar args: %q", strings.Join(gotArgs, " "))
	}
	if gotArgs[4] != "--welcome" {
		t.Fatalf("expected welcome flag, got args: %q", strings.Join(gotArgs, " "))
	}

	for _, want := range []string{
		"command: openmls-conversation-join-dev",
		"status: joined",
		"sidecar_command: conversation-join",
		"sidecar_device_label: bob-device",
		"sidecar_conversation_label: test-conversation",
		"welcome_artifact_path_hint: /tmp/welcome.bin",
		"joined: true",
		"group_reloadable: true",
		"member_count: 2",
		"epoch: GroupEpoch(1)",
		"join_summary_path_hint: .carbonstack-openmls-sidecar-state/dev/devices/bob-device/conversations/test-conversation/join-summary.json",
		"conversation_state_path_hint: .carbonstack-openmls-sidecar-state/dev/devices/bob-device/conversations/test-conversation",
		"conversation_summary_path_hint: .carbonstack-openmls-sidecar-state/dev/devices/bob-device/conversations/test-conversation/conversation-summary.json",
		"provider_storage_path_hint: .carbonstack-openmls-sidecar-state/dev/devices/bob-device/conversations/test-conversation/provider-storage.json",
		"warning: dev/pre-alpha OpenMLS bootstrap path; not production membership UX",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}
