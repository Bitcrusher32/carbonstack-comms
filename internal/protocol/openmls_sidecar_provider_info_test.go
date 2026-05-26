package protocol

import (
	"testing"
)

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
	assertStringPresent(t, envelope.Data.Capabilities, "identity-status")
	assertStringPresent(t, envelope.Data.Capabilities, "public-bundle-export")
	assertStringPresent(t, envelope.Data.Capabilities, "conversation-create")
	assertStringPresent(t, envelope.Data.Capabilities, "conversation-load-check")
	assertStringPresent(t, envelope.Data.Capabilities, "conversation-add-member")
	assertStringPresent(t, envelope.Data.Capabilities, "conversation-join")
	assertStringPresent(t, envelope.Data.Capabilities, "message-protect")
	assertStringPresent(t, envelope.Data.Capabilities, "message-open")
	unsupported := []string{
		"state-checkpoint",
		"state-load-check",
	}

	for _, command := range unsupported {
		assertStringPresent(t, envelope.Data.Unsupported, command)
	}

	if stringSliceContains(envelope.Data.Unsupported, "identity-create") {
		t.Fatal("identity-create should not be listed as unsupported once command is recognized")
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
	output, err := runOpenMLSSidecar("state-checkpoint")
	assertExitCode(t, err, 2)

	envelope := parseSidecarEnvelope(t, output)

	if envelope.OK {
		t.Fatal("unsupported command envelope ok = true, want false")
	}

	if envelope.Command != "state-checkpoint" {
		t.Fatalf("command = %q, want state-checkpoint", envelope.Command)
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
