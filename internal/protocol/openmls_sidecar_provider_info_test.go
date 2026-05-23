package protocol

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

const openMLSSidecarDir = "mls/research/openmls-sidecar"

type openMLSSidecarEnvelope struct {
	OK                      bool                          `json:"ok"`
	Command                 string                        `json:"command"`
	Provider                string                        `json:"provider"`
	Implementation          string                        `json:"implementation"`
	Mode                    string                        `json:"mode"`
	Phase                   string                        `json:"phase"`
	Data                    openMLSSidecarProviderData    `json:"data"`
	Error                   *openMLSSidecarError          `json:"error,omitempty"`
	Events                  []openMLSSidecarProviderEvent `json:"events"`
	Warnings                []string                      `json:"warnings"`
	PrivateMaterialIncluded bool                          `json:"private_material_included"`
}

type openMLSSidecarProviderData struct {
	Capabilities    []string `json:"capabilities"`
	Unsupported     []string `json:"unsupported"`
	SecurityLevel   string   `json:"security_level"`
	DeviceLabel     string   `json:"device_label"`
	IdentityCreated bool     `json:"identity_created"`
	StateWritten    bool     `json:"state_written"`
}

type openMLSSidecarError struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	ProviderEvent string `json:"provider_event"`
	Severity      string `json:"severity"`
	TrustRelevant bool   `json:"trust_relevant"`
}

type openMLSSidecarProviderEvent struct {
	Event         string `json:"event"`
	Severity      string `json:"severity"`
	TrustRelevant bool   `json:"trust_relevant"`
}

func TestOpenMLSSidecarProviderInfoCommand(t *testing.T) {
	output, err := runOpenMLSSidecar("provider-info")
	if err != nil {
		t.Fatalf("run OpenMLS sidecar provider-info: %v", err)
	}

	envelope := parseSidecarEnvelope(t, output)

	if !envelope.OK {
		t.Fatal("provider-info envelope ok = false, want true")
	}

	if envelope.Command != "provider-info" {
		t.Fatalf("command = %q, want provider-info", envelope.Command)
	}

	assertProviderEnvelopeBase(t, envelope)

	if envelope.Phase != "phase2d-provider-info" {
		t.Fatalf("phase = %q, want phase2d-provider-info", envelope.Phase)
	}

	if envelope.PrivateMaterialIncluded {
		t.Fatal("provider-info must not include private material")
	}

	assertStringPresent(t, envelope.Data.Capabilities, "provider-info")
	assertStringPresent(t, envelope.Data.Capabilities, "identity-create")

	unsupported := []string{
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
		assertStringPresent(t, envelope.Data.Unsupported, command)
	}

	if stringSliceContains(envelope.Data.Unsupported, "identity-create") {
		t.Fatal("identity-create should not be listed as unsupported once command is recognized for validation")
	}

	if envelope.Data.SecurityLevel == "" {
		t.Fatal("expected security level")
	}

	if len(envelope.Warnings) == 0 {
		t.Fatal("expected provider-info warnings")
	}

	if envelope.Error != nil {
		t.Fatalf("provider-info should not include error: %#v", envelope.Error)
	}
}

func TestOpenMLSSidecarUnsupportedCommandEnvelope(t *testing.T) {
	output, err := runOpenMLSSidecar("public-bundle-export")
	assertExitCode(t, err, 2)

	envelope := parseSidecarEnvelope(t, output)

	if envelope.OK {
		t.Fatal("unsupported command envelope ok = true, want false")
	}

	if envelope.Command != "public-bundle-export" {
		t.Fatalf("command = %q, want public-bundle-export", envelope.Command)
	}

	assertProviderEnvelopeBase(t, envelope)
	assertSidecarError(t, envelope, "unsupported_command", string(ProviderEventCommandUnsupported), "warning", false)

	if envelope.PrivateMaterialIncluded {
		t.Fatal("unsupported command must not include private material")
	}

	if len(envelope.Events) == 0 {
		t.Fatal("unsupported command should include provider event")
	}
}

func TestOpenMLSSidecarIdentityCreateMissingLabel(t *testing.T) {
	output, err := runOpenMLSSidecar("identity-create")
	assertExitCode(t, err, 2)

	envelope := parseSidecarEnvelope(t, output)

	if envelope.OK {
		t.Fatal("missing-label identity-create envelope ok = true, want false")
	}

	if envelope.Command != "identity-create" {
		t.Fatalf("command = %q, want identity-create", envelope.Command)
	}

	assertProviderEnvelopeBase(t, envelope)
	assertSidecarError(t, envelope, "missing_required_argument", "provider.command.invalid", "warning", false)

	if envelope.PrivateMaterialIncluded {
		t.Fatal("missing-label identity-create must not include private material")
	}
}

func TestOpenMLSSidecarIdentityCreateInvalidLabel(t *testing.T) {
	output, err := runOpenMLSSidecar("identity-create", "--device-label", "../bad")
	assertExitCode(t, err, 2)

	envelope := parseSidecarEnvelope(t, output)

	if envelope.OK {
		t.Fatal("invalid-label identity-create envelope ok = true, want false")
	}

	if envelope.Data.DeviceLabel != "../bad" {
		t.Fatalf("device label = %q, want ../bad", envelope.Data.DeviceLabel)
	}

	assertProviderEnvelopeBase(t, envelope)
	assertSidecarError(t, envelope, "invalid_device_label", "provider.command.invalid", "warning", false)

	if envelope.PrivateMaterialIncluded {
		t.Fatal("invalid-label identity-create must not include private material")
	}
}

func TestOpenMLSSidecarIdentityCreateSafeLabelNotImplemented(t *testing.T) {
	output, err := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	assertExitCode(t, err, 3)

	envelope := parseSidecarEnvelope(t, output)

	if envelope.OK {
		t.Fatal("not-implemented identity-create envelope ok = true, want false")
	}

	if envelope.Data.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("device label = %q, want carbonstack-alice-device", envelope.Data.DeviceLabel)
	}

	if envelope.Data.IdentityCreated {
		t.Fatal("identity-create prep must not create identity material yet")
	}

	if envelope.Data.StateWritten {
		t.Fatal("identity-create prep must not write state yet")
	}

	assertProviderEnvelopeBase(t, envelope)
	assertSidecarError(t, envelope, "not_implemented", "provider.command.not_implemented", "warning", false)

	if envelope.PrivateMaterialIncluded {
		t.Fatal("not-implemented identity-create must not include private material")
	}
}

func runOpenMLSSidecar(args ...string) ([]byte, error) {
	sidecarDir := filepath.Clean(openMLSSidecarDir)

	cmdArgs := append([]string{"run", "--quiet", "--"}, args...)
	cmd := exec.Command("cargo", cmdArgs...)
	cmd.Dir = sidecarDir

	return cmd.Output()
}

func parseSidecarEnvelope(t *testing.T, output []byte) openMLSSidecarEnvelope {
	t.Helper()

	var envelope openMLSSidecarEnvelope
	if err := json.Unmarshal(output, &envelope); err != nil {
		t.Fatalf("parse sidecar JSON: %v\noutput:\n%s", err, string(output))
	}

	return envelope
}

func assertExitCode(t *testing.T, err error, want int) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected exit code %d, got nil error", want)
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("error type = %T, want *exec.ExitError", err)
	}

	if exitErr.ExitCode() != want {
		t.Fatalf("exit code = %d, want %d", exitErr.ExitCode(), want)
	}
}

func assertProviderEnvelopeBase(t *testing.T, envelope openMLSSidecarEnvelope) {
	t.Helper()

	if envelope.Provider != "openmls" {
		t.Fatalf("provider = %q, want openmls", envelope.Provider)
	}

	if envelope.Implementation != "carbonstack-openmls-sidecar" {
		t.Fatalf("implementation = %q, want carbonstack-openmls-sidecar", envelope.Implementation)
	}

	if envelope.Mode != "experimental-sidecar" {
		t.Fatalf("mode = %q, want experimental-sidecar", envelope.Mode)
	}
}

func assertSidecarError(t *testing.T, envelope openMLSSidecarEnvelope, code string, event string, severity string, trustRelevant bool) {
	t.Helper()

	if envelope.Error == nil {
		t.Fatalf("expected sidecar error %q, got nil", code)
	}

	if envelope.Error.Code != code {
		t.Fatalf("error code = %q, want %q", envelope.Error.Code, code)
	}

	if envelope.Error.ProviderEvent != event {
		t.Fatalf("provider event = %q, want %q", envelope.Error.ProviderEvent, event)
	}

	if envelope.Error.Severity != severity {
		t.Fatalf("severity = %q, want %q", envelope.Error.Severity, severity)
	}

	if envelope.Error.TrustRelevant != trustRelevant {
		t.Fatalf("trust relevant = %v, want %v", envelope.Error.TrustRelevant, trustRelevant)
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

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}

	return false
}
