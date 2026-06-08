package app

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func TestOpenMLSRelayKeyPackageSubmitDevRequiresCoreArgs(t *testing.T) {
	err := cmdOpenMLSRelayKeyPackageSubmitDev([]string{
		"--relay-space", "relay-space-1",
		"--to-device", "alice-device-id",
	})
	if err == nil || !strings.Contains(err.Error(), "--relay-space, --to-device, and --sidecar-device-label are required") {
		t.Fatalf("expected required keypackage submit args error, got %v", err)
	}
}

func TestOpenMLSRelayWelcomeSubmitDevRequiresCoreArgs(t *testing.T) {
	err := cmdOpenMLSRelayWelcomeSubmitDev([]string{
		"--relay-space", "relay-space-1",
		"--to-device", "bob-device-id",
	})
	if err == nil || !strings.Contains(err.Error(), "--relay-space, --to-device, and --welcome are required") {
		t.Fatalf("expected required welcome submit args error, got %v", err)
	}
}

func TestOpenMLSRelayKeyPackageSubmitDevExportsAndSubmitsScopedEnvelope(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldRun := runOpenMLSBootstrapSidecarForCommand
	oldSubmit := submitRelaySpaceKeyPackageEnvelopeForCommand
	defer func() {
		runOpenMLSBootstrapSidecarForCommand = oldRun
		submitRelaySpaceKeyPackageEnvelopeForCommand = oldSubmit
	}()

	var gotSidecarDir string
	var gotSidecarCommand string
	var gotSidecarArgs []string

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		gotSidecarDir = sidecarDir
		gotSidecarCommand = sidecarCommand
		gotSidecarArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "public-bundle-export",
			Data: map[string]any{
				"device_label":                   "bob-sidecar",
				"key_package_artifact_path_hint": ".carbonstack-openmls-sidecar-state/dev/devices/bob-sidecar/public-bundle.keypackage.bin",
			},
		}, nil
	}

	var gotRelaySpaceID string
	var gotSenderDeviceID string
	var gotRecipientDeviceID string
	var gotArtifactPath string
	var gotClientCreatedAt string

	submitRelaySpaceKeyPackageEnvelopeForCommand = func(c client.CypherClient, relaySpaceID string, senderDeviceID string, recipientDeviceID string, artifactPath string, clientCreatedAt string) (client.SubmitRelaySpaceEnvelopeResponse, error) {
		gotRelaySpaceID = relaySpaceID
		gotSenderDeviceID = senderDeviceID
		gotRecipientDeviceID = recipientDeviceID
		gotArtifactPath = artifactPath
		gotClientCreatedAt = clientCreatedAt
		return client.SubmitRelaySpaceEnvelopeResponse{
			EnvelopeID:       "keypackage-envelope-1",
			RelaySpaceID:     relaySpaceID,
			DeliveryState:    "queued",
			ServerReceivedAt: "2026-06-08T00:00:00Z",
			PayloadSHA256:    strings.Repeat("a", 64),
			PayloadSizeBytes: 21,
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSRelayKeyPackageSubmitDev([]string{
			"--state", statePath,
			"--relay-space", "relay-space-1",
			"--to-device", "alice-device-id",
			"--sidecar-dir", "sidecar-test-dir",
			"--sidecar-device-label", "bob-sidecar",
			"--client-created-at", "2026-06-08T00:00:00Z",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotSidecarDir != "sidecar-test-dir" {
		t.Fatalf("sidecar dir = %q", gotSidecarDir)
	}
	if gotSidecarCommand != "public-bundle-export" {
		t.Fatalf("sidecar command = %q", gotSidecarCommand)
	}
	if strings.Join(gotSidecarArgs, " ") != "--device-label bob-sidecar --write-artifact" {
		t.Fatalf("sidecar args = %q", strings.Join(gotSidecarArgs, " "))
	}

	if gotRelaySpaceID != "relay-space-1" {
		t.Fatalf("relay_space_id = %q", gotRelaySpaceID)
	}
	if gotSenderDeviceID != "local-device-id" {
		t.Fatalf("sender_device_id = %q", gotSenderDeviceID)
	}
	if gotRecipientDeviceID != "alice-device-id" {
		t.Fatalf("recipient_device_id = %q", gotRecipientDeviceID)
	}
	if gotArtifactPath != "sidecar-test-dir/.carbonstack-openmls-sidecar-state/dev/devices/bob-sidecar/public-bundle.keypackage.bin" {
		t.Fatalf("artifact path = %q", gotArtifactPath)
	}
	if gotClientCreatedAt != "2026-06-08T00:00:00Z" {
		t.Fatalf("client_created_at = %q", gotClientCreatedAt)
	}

	for _, want := range []string{
		"command: openmls-relay-keypackage-submit-dev",
		"status: sent",
		"relay_space_id: relay-space-1",
		"sender_device_id: local-device-id",
		"recipient_device_id: alice-device-id",
		"sidecar_command: public-bundle-export",
		"sidecar_device_label: bob-sidecar",
		"content_type: " + relay.ContentTypeOpenMLSKeyPackage,
		"envelope_id: keypackage-envelope-1",
		"warning: dev/pre-alpha Relay Space KeyPackage transport; not join automation or identity verification",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSRelayWelcomeSubmitDevSubmitsScopedEnvelope(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldSubmit := submitRelaySpaceWelcomeEnvelopeForCommand
	defer func() { submitRelaySpaceWelcomeEnvelopeForCommand = oldSubmit }()

	var gotRelaySpaceID string
	var gotSenderDeviceID string
	var gotRecipientDeviceID string
	var gotArtifactPath string

	submitRelaySpaceWelcomeEnvelopeForCommand = func(c client.CypherClient, relaySpaceID string, senderDeviceID string, recipientDeviceID string, artifactPath string, clientCreatedAt string) (client.SubmitRelaySpaceEnvelopeResponse, error) {
		gotRelaySpaceID = relaySpaceID
		gotSenderDeviceID = senderDeviceID
		gotRecipientDeviceID = recipientDeviceID
		gotArtifactPath = artifactPath
		return client.SubmitRelaySpaceEnvelopeResponse{
			EnvelopeID:       "welcome-envelope-1",
			RelaySpaceID:     relaySpaceID,
			DeliveryState:    "queued",
			ServerReceivedAt: "2026-06-08T00:01:00Z",
			PayloadSHA256:    strings.Repeat("b", 64),
			PayloadSizeBytes: 15,
		}, nil
	}

	welcomePath := filepath.Join(t.TempDir(), "welcome.bin")

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSRelayWelcomeSubmitDev([]string{
			"--state", statePath,
			"--relay-space", "relay-space-1",
			"--to-device", "bob-device-id",
			"--welcome", welcomePath,
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotRelaySpaceID != "relay-space-1" {
		t.Fatalf("relay_space_id = %q", gotRelaySpaceID)
	}
	if gotSenderDeviceID != "local-device-id" {
		t.Fatalf("sender_device_id = %q", gotSenderDeviceID)
	}
	if gotRecipientDeviceID != "bob-device-id" {
		t.Fatalf("recipient_device_id = %q", gotRecipientDeviceID)
	}
	if gotArtifactPath != welcomePath {
		t.Fatalf("artifact path = %q, want %q", gotArtifactPath, welcomePath)
	}

	for _, want := range []string{
		"command: openmls-relay-welcome-submit-dev",
		"status: sent",
		"relay_space_id: relay-space-1",
		"sender_device_id: local-device-id",
		"recipient_device_id: bob-device-id",
		"content_type: " + relay.ContentTypeOpenMLSWelcome,
		"envelope_id: welcome-envelope-1",
		"warning: dev/pre-alpha Relay Space Welcome transport; not join automation or identity verification",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSRelayKeyPackageInboxDevWritesWithoutAck(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	oldWrite := writeRelaySpaceKeyPackageFromEnvelopeForCommand
	defer func() {
		relaySpaceOpenMLSArtifactInboxForCommand = oldInbox
		writeRelaySpaceKeyPackageFromEnvelopeForCommand = oldWrite
	}()

	var gotRelaySpaceID string
	var gotDeviceID string
	var gotArtifactKind string
	var wroteEnvelopeID string

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
		gotRelaySpaceID = relaySpaceID
		gotDeviceID = deviceID
		gotArtifactKind = artifactKind
		return []client.RelaySpaceEnvelopeRecord{
			{
				EnvelopeID:        "keypackage-envelope-1",
				RelaySpaceID:      relaySpaceID,
				SenderDeviceID:    "bob-device-id",
				RecipientDeviceID: deviceID,
				ContentType:       relay.ContentTypeOpenMLSKeyPackage,
				ProtocolVersion:   relay.ProtocolVersionOpenMLSSidecar,
			},
		}, nil
	}

	writeRelaySpaceKeyPackageFromEnvelopeForCommand = func(outputPath string, envelope client.RelaySpaceEnvelopeRecord) error {
		wroteEnvelopeID = envelope.EnvelopeID
		return nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSRelayKeyPackageInboxDev([]string{
			"--state", statePath,
			"--relay-space", "relay-space-1",
			"--limit", "1",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotRelaySpaceID != "relay-space-1" {
		t.Fatalf("relay_space_id = %q", gotRelaySpaceID)
	}
	if gotDeviceID != "local-device-id" {
		t.Fatalf("device_id = %q", gotDeviceID)
	}
	if gotArtifactKind != relay.ArtifactKindKeyPackage {
		t.Fatalf("artifact kind = %q", gotArtifactKind)
	}
	if wroteEnvelopeID != "keypackage-envelope-1" {
		t.Fatalf("wrote envelope = %q", wroteEnvelopeID)
	}

	for _, want := range []string{
		"command: openmls-relay-keypackage-inbox-dev",
		"relay_space_id: relay-space-1",
		"device_id: local-device-id",
		"queued_keypackage_envelopes: 1",
		"ack_requested: false",
		"relay_keypackage_written",
		"envelope_id: keypackage-envelope-1",
		"acked: false",
		"warning: dev/pre-alpha Relay Space KeyPackage inbox; no add-member, ack, trust mutation, or verification",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSRelayWelcomeInboxDevWritesWithoutAck(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	oldWrite := writeRelaySpaceWelcomeFromEnvelopeForCommand
	defer func() {
		relaySpaceOpenMLSArtifactInboxForCommand = oldInbox
		writeRelaySpaceWelcomeFromEnvelopeForCommand = oldWrite
	}()

	var gotArtifactKind string
	var wroteEnvelopeID string

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
		gotArtifactKind = artifactKind
		return []client.RelaySpaceEnvelopeRecord{
			{
				EnvelopeID:        "welcome-envelope-1",
				RelaySpaceID:      relaySpaceID,
				SenderDeviceID:    "alice-device-id",
				RecipientDeviceID: deviceID,
				ContentType:       relay.ContentTypeOpenMLSWelcome,
				ProtocolVersion:   relay.ProtocolVersionOpenMLSSidecar,
			},
		}, nil
	}

	writeRelaySpaceWelcomeFromEnvelopeForCommand = func(outputPath string, envelope client.RelaySpaceEnvelopeRecord) error {
		wroteEnvelopeID = envelope.EnvelopeID
		return nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSRelayWelcomeInboxDev([]string{
			"--state", statePath,
			"--relay-space", "relay-space-1",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotArtifactKind != relay.ArtifactKindWelcome {
		t.Fatalf("artifact kind = %q", gotArtifactKind)
	}
	if wroteEnvelopeID != "welcome-envelope-1" {
		t.Fatalf("wrote envelope = %q", wroteEnvelopeID)
	}

	for _, want := range []string{
		"command: openmls-relay-welcome-inbox-dev",
		"relay_space_id: relay-space-1",
		"device_id: local-device-id",
		"queued_welcome_envelopes: 1",
		"ack_requested: false",
		"relay_welcome_written",
		"envelope_id: welcome-envelope-1",
		"acked: false",
		"warning: dev/pre-alpha Relay Space Welcome inbox; no conversation-join, ack, trust mutation, or verification",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSRelayInboxDevReportsWriteFailureWithoutAck(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	oldWrite := writeRelaySpaceWelcomeFromEnvelopeForCommand
	defer func() {
		relaySpaceOpenMLSArtifactInboxForCommand = oldInbox
		writeRelaySpaceWelcomeFromEnvelopeForCommand = oldWrite
	}()

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
		return []client.RelaySpaceEnvelopeRecord{
			{
				EnvelopeID:      "welcome-envelope-1",
				RelaySpaceID:    relaySpaceID,
				SenderDeviceID:  "alice-device-id",
				ContentType:     relay.ContentTypeOpenMLSWelcome,
				ProtocolVersion: relay.ProtocolVersionOpenMLSSidecar,
			},
		}, nil
	}

	writeRelaySpaceWelcomeFromEnvelopeForCommand = func(outputPath string, envelope client.RelaySpaceEnvelopeRecord) error {
		return errors.New("writer failed")
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSRelayWelcomeInboxDev([]string{
			"--state", statePath,
			"--relay-space", "relay-space-1",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	for _, want := range []string{
		"relay_welcome_write_failed",
		"envelope_id: welcome-envelope-1",
		"error: writer failed",
		"written_artifacts: 0",
		"write_failures: 1",
		"ack_requested: false",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func writeRelayCommandState(t *testing.T) string {
	t.Helper()

	statePath := filepath.Join(t.TempDir(), "state.json")
	err := state.Save(statePath, state.State{
		ServerURL:   "http://cypher.test",
		AccountID:   "account-1",
		DeviceID:    "local-device-id",
		DeviceLabel: "local-device",
	})
	if err != nil {
		t.Fatalf("save state: %v", err)
	}

	return statePath
}
