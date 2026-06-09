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

func TestOpenMLSRelayAddMemberDevRequiresCoreArgs(t *testing.T) {
	err := cmdOpenMLSRelayAddMemberDev([]string{
		"--relay-space", "relay-space-1",
		"--sidecar-device-label", "alice-sidecar",
	})
	if err == nil || !strings.Contains(err.Error(), "--relay-space, --sidecar-device-label, and --conversation are required") {
		t.Fatalf("expected required add-member args error, got %v", err)
	}
}

func TestOpenMLSRelayAddMemberDevWritesKeyPackageRunsSidecarAndSubmitsWelcome(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	oldWrite := writeRelaySpaceKeyPackageFromEnvelopeForCommand
	oldRun := runOpenMLSBootstrapSidecarForCommand
	oldSubmitWelcome := submitRelaySpaceWelcomeEnvelopeForCommand
	defer func() {
		relaySpaceOpenMLSArtifactInboxForCommand = oldInbox
		writeRelaySpaceKeyPackageFromEnvelopeForCommand = oldWrite
		runOpenMLSBootstrapSidecarForCommand = oldRun
		submitRelaySpaceWelcomeEnvelopeForCommand = oldSubmitWelcome
	}()

	var gotInboxRelaySpaceID string
	var gotInboxDeviceID string
	var gotInboxArtifactKind string

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
		gotInboxRelaySpaceID = relaySpaceID
		gotInboxDeviceID = deviceID
		gotInboxArtifactKind = artifactKind
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

	var wroteEnvelopeID string
	var wroteOutputPath string

	writeRelaySpaceKeyPackageFromEnvelopeForCommand = func(outputPath string, envelope client.RelaySpaceEnvelopeRecord) error {
		wroteOutputPath = outputPath
		wroteEnvelopeID = envelope.EnvelopeID
		return nil
	}

	var gotSidecarDir string
	var gotSidecarCommand string
	var gotSidecarArgs []string

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		gotSidecarDir = sidecarDir
		gotSidecarCommand = sidecarCommand
		gotSidecarArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "conversation-add-member",
			Data: map[string]any{
				"device_label":                "alice-sidecar",
				"conversation_label":          "test-conversation",
				"welcome_artifact_path_hint":  ".carbonstack-openmls-sidecar-state/dev/devices/alice-sidecar/conversations/test-conversation/welcome.bin",
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

	var gotWelcomeRelaySpaceID string
	var gotWelcomeSenderDeviceID string
	var gotWelcomeRecipientDeviceID string
	var gotWelcomeArtifactPath string
	var gotWelcomeClientCreatedAt string

	submitRelaySpaceWelcomeEnvelopeForCommand = func(c client.CypherClient, relaySpaceID string, senderDeviceID string, recipientDeviceID string, artifactPath string, clientCreatedAt string) (client.SubmitRelaySpaceEnvelopeResponse, error) {
		gotWelcomeRelaySpaceID = relaySpaceID
		gotWelcomeSenderDeviceID = senderDeviceID
		gotWelcomeRecipientDeviceID = recipientDeviceID
		gotWelcomeArtifactPath = artifactPath
		gotWelcomeClientCreatedAt = clientCreatedAt
		return client.SubmitRelaySpaceEnvelopeResponse{
			EnvelopeID:       "welcome-envelope-1",
			RelaySpaceID:     relaySpaceID,
			DeliveryState:    "queued",
			ServerReceivedAt: "2026-06-08T00:02:00Z",
			PayloadSHA256:    strings.Repeat("c", 64),
			PayloadSizeBytes: 879,
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSRelayAddMemberDev([]string{
			"--state", statePath,
			"--relay-space", "relay-space-1",
			"--sidecar-dir", "sidecar-test-dir",
			"--sidecar-device-label", "alice-sidecar",
			"--conversation", "test-conversation",
			"--client-created-at", "2026-06-08T00:02:00Z",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotInboxRelaySpaceID != "relay-space-1" {
		t.Fatalf("inbox relay_space_id = %q", gotInboxRelaySpaceID)
	}
	if gotInboxDeviceID != "local-device-id" {
		t.Fatalf("inbox device_id = %q", gotInboxDeviceID)
	}
	if gotInboxArtifactKind != relay.ArtifactKindKeyPackage {
		t.Fatalf("inbox artifact kind = %q", gotInboxArtifactKind)
	}
	if wroteEnvelopeID != "keypackage-envelope-1" {
		t.Fatalf("wrote envelope = %q", wroteEnvelopeID)
	}
	if !strings.Contains(wroteOutputPath, "public-bundle.keypackage.bin") {
		t.Fatalf("unexpected keypackage output path: %q", wroteOutputPath)
	}

	if gotSidecarDir != "sidecar-test-dir" {
		t.Fatalf("sidecar dir = %q", gotSidecarDir)
	}
	if gotSidecarCommand != "conversation-add-member" {
		t.Fatalf("sidecar command = %q", gotSidecarCommand)
	}
	if strings.Join(gotSidecarArgs[:4], " ") != "--device-label alice-sidecar --conversation-label test-conversation" {
		t.Fatalf("unexpected leading sidecar args: %q", strings.Join(gotSidecarArgs, " "))
	}
	if gotSidecarArgs[4] != "--member-keypackage" {
		t.Fatalf("expected member-keypackage flag, got args: %q", strings.Join(gotSidecarArgs, " "))
	}
	if gotSidecarArgs[5] != wroteOutputPath {
		t.Fatalf("member keypackage path = %q, want %q", gotSidecarArgs[5], wroteOutputPath)
	}

	if gotWelcomeRelaySpaceID != "relay-space-1" {
		t.Fatalf("welcome relay_space_id = %q", gotWelcomeRelaySpaceID)
	}
	if gotWelcomeSenderDeviceID != "local-device-id" {
		t.Fatalf("welcome sender_device_id = %q", gotWelcomeSenderDeviceID)
	}
	if gotWelcomeRecipientDeviceID != "bob-device-id" {
		t.Fatalf("welcome recipient_device_id = %q", gotWelcomeRecipientDeviceID)
	}
	wantWelcomePath := "sidecar-test-dir/.carbonstack-openmls-sidecar-state/dev/devices/alice-sidecar/conversations/test-conversation/welcome.bin"
	if gotWelcomeArtifactPath != wantWelcomePath {
		t.Fatalf("welcome artifact path = %q, want %q", gotWelcomeArtifactPath, wantWelcomePath)
	}
	if gotWelcomeClientCreatedAt != "2026-06-08T00:02:00Z" {
		t.Fatalf("welcome client_created_at = %q", gotWelcomeClientCreatedAt)
	}

	for _, want := range []string{
		"command: openmls-relay-add-member-dev",
		"status: welcome_created_and_sent",
		"relay_space_id: relay-space-1",
		"local_device_id: local-device-id",
		"keypackage_envelope_id: keypackage-envelope-1",
		"keypackage_from_device: bob-device-id",
		"sidecar_command: conversation-add-member",
		"sidecar_device_label: alice-sidecar",
		"sidecar_conversation_label: test-conversation",
		"welcome_recipient_device_id: bob-device-id",
		"welcome_artifact_path: " + wantWelcomePath,
		"welcome_envelope_id: welcome-envelope-1",
		"welcome_delivery_state: queued",
		"keypackage_acked: false",
		"welcome_acked: false",
		"member_added: true",
		"welcome_artifact_written: true",
		"group_reloadable: true",
		"member_count_before: 1",
		"member_count_after: 2",
		"epoch_before: GroupEpoch(0)",
		"epoch_after: GroupEpoch(1)",
		"warning: dev/pre-alpha Relay Space add-member scaffold; not join automation, identity verification, local-backbone, or production UX",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSRelayAddMemberDevAllowsWelcomeRecipientOverride(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	oldWrite := writeRelaySpaceKeyPackageFromEnvelopeForCommand
	oldRun := runOpenMLSBootstrapSidecarForCommand
	oldSubmitWelcome := submitRelaySpaceWelcomeEnvelopeForCommand
	defer func() {
		relaySpaceOpenMLSArtifactInboxForCommand = oldInbox
		writeRelaySpaceKeyPackageFromEnvelopeForCommand = oldWrite
		runOpenMLSBootstrapSidecarForCommand = oldRun
		submitRelaySpaceWelcomeEnvelopeForCommand = oldSubmitWelcome
	}()

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
		return []client.RelaySpaceEnvelopeRecord{
			{
				EnvelopeID:        "keypackage-envelope-1",
				RelaySpaceID:      relaySpaceID,
				SenderDeviceID:    "wrong-or-empty-device-id",
				RecipientDeviceID: deviceID,
				ContentType:       relay.ContentTypeOpenMLSKeyPackage,
				ProtocolVersion:   relay.ProtocolVersionOpenMLSSidecar,
			},
		}, nil
	}

	writeRelaySpaceKeyPackageFromEnvelopeForCommand = func(outputPath string, envelope client.RelaySpaceEnvelopeRecord) error {
		return nil
	}

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "conversation-add-member",
			Data: map[string]any{
				"device_label":               "alice-sidecar",
				"conversation_label":         "test-conversation",
				"welcome_artifact_path_hint": ".carbonstack-openmls-sidecar-state/dev/devices/alice-sidecar/conversations/test-conversation/welcome.bin",
			},
		}, nil
	}

	var gotWelcomeRecipientDeviceID string

	submitRelaySpaceWelcomeEnvelopeForCommand = func(c client.CypherClient, relaySpaceID string, senderDeviceID string, recipientDeviceID string, artifactPath string, clientCreatedAt string) (client.SubmitRelaySpaceEnvelopeResponse, error) {
		gotWelcomeRecipientDeviceID = recipientDeviceID
		return client.SubmitRelaySpaceEnvelopeResponse{
			EnvelopeID:    "welcome-envelope-1",
			RelaySpaceID:  relaySpaceID,
			DeliveryState: "queued",
		}, nil
	}

	_, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSRelayAddMemberDev([]string{
			"--state", statePath,
			"--relay-space", "relay-space-1",
			"--sidecar-dir", "sidecar-test-dir",
			"--sidecar-device-label", "alice-sidecar",
			"--conversation", "test-conversation",
			"--welcome-to-device", "explicit-bob-device-id",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotWelcomeRecipientDeviceID != "explicit-bob-device-id" {
		t.Fatalf("welcome recipient override = %q", gotWelcomeRecipientDeviceID)
	}
}

func TestOpenMLSRelayAddMemberDevRejectsNoKeyPackageEnvelopes(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	defer func() { relaySpaceOpenMLSArtifactInboxForCommand = oldInbox }()

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
		return nil, nil
	}

	err := cmdOpenMLSRelayAddMemberDev([]string{
		"--state", statePath,
		"--relay-space", "relay-space-1",
		"--sidecar-device-label", "alice-sidecar",
		"--conversation", "test-conversation",
	})
	if err == nil || !strings.Contains(err.Error(), "no Relay Space KeyPackage envelopes available for add-member") {
		t.Fatalf("expected no KeyPackage envelopes error, got %v", err)
	}
}

func TestOpenMLSRelayAddMemberDevRejectsMissingWelcomeHint(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	oldWrite := writeRelaySpaceKeyPackageFromEnvelopeForCommand
	oldRun := runOpenMLSBootstrapSidecarForCommand
	defer func() {
		relaySpaceOpenMLSArtifactInboxForCommand = oldInbox
		writeRelaySpaceKeyPackageFromEnvelopeForCommand = oldWrite
		runOpenMLSBootstrapSidecarForCommand = oldRun
	}()

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
		return []client.RelaySpaceEnvelopeRecord{
			{
				EnvelopeID:     "keypackage-envelope-1",
				RelaySpaceID:   relaySpaceID,
				SenderDeviceID: "bob-device-id",
				ContentType:    relay.ContentTypeOpenMLSKeyPackage,
			},
		}, nil
	}

	writeRelaySpaceKeyPackageFromEnvelopeForCommand = func(outputPath string, envelope client.RelaySpaceEnvelopeRecord) error {
		return nil
	}

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "conversation-add-member",
			Data: map[string]any{
				"device_label":       "alice-sidecar",
				"conversation_label": "test-conversation",
			},
		}, nil
	}

	err := cmdOpenMLSRelayAddMemberDev([]string{
		"--state", statePath,
		"--relay-space", "relay-space-1",
		"--sidecar-device-label", "alice-sidecar",
		"--conversation", "test-conversation",
	})
	if err == nil || !strings.Contains(err.Error(), "OpenMLS sidecar conversation-add-member did not return welcome_artifact_path_hint") {
		t.Fatalf("expected missing welcome hint error, got %v", err)
	}
}

func TestOpenMLSRelayAddMemberDevDoesNotSubmitWelcomeWhenSidecarAddMemberFails(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	oldWrite := writeRelaySpaceKeyPackageFromEnvelopeForCommand
	oldRun := runOpenMLSBootstrapSidecarForCommand
	oldSubmitWelcome := submitRelaySpaceWelcomeEnvelopeForCommand
	defer func() {
		relaySpaceOpenMLSArtifactInboxForCommand = oldInbox
		writeRelaySpaceKeyPackageFromEnvelopeForCommand = oldWrite
		runOpenMLSBootstrapSidecarForCommand = oldRun
		submitRelaySpaceWelcomeEnvelopeForCommand = oldSubmitWelcome
	}()

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
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
		if envelope.EnvelopeID != "keypackage-envelope-1" {
			t.Fatalf("wrote envelope = %q", envelope.EnvelopeID)
		}
		return nil
	}

	var gotSidecarCommand string
	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		gotSidecarCommand = sidecarCommand
		return openMLSSidecarBootstrapEnvelope{}, errors.New("sidecar add-member failed")
	}

	welcomeSubmitCalled := false
	submitRelaySpaceWelcomeEnvelopeForCommand = func(c client.CypherClient, relaySpaceID string, senderDeviceID string, recipientDeviceID string, artifactPath string, clientCreatedAt string) (client.SubmitRelaySpaceEnvelopeResponse, error) {
		welcomeSubmitCalled = true
		return client.SubmitRelaySpaceEnvelopeResponse{}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSRelayAddMemberDev([]string{
			"--state", statePath,
			"--relay-space", "relay-space-1",
			"--sidecar-dir", "sidecar-test-dir",
			"--sidecar-device-label", "alice-sidecar",
			"--conversation", "test-conversation",
		})
	})
	if err == nil || !strings.Contains(err.Error(), "sidecar add-member failed") {
		t.Fatalf("expected sidecar add-member failure, got %v", err)
	}
	if gotSidecarCommand != "conversation-add-member" {
		t.Fatalf("sidecar command = %q", gotSidecarCommand)
	}
	if welcomeSubmitCalled {
		t.Fatal("Welcome submit should not be called when sidecar add-member fails")
	}
	for _, forbidden := range []string{
		"status: welcome_created_and_sent",
		"welcome_envelope_id:",
		"welcome_delivery_state:",
		"keypackage_acked: false",
		"welcome_acked: false",
	} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("output should not contain %q after sidecar failure, got:\n%s", forbidden, out)
		}
	}
}

func TestOpenMLSRelayJoinDevRequiresCoreArgs(t *testing.T) {
	err := cmdOpenMLSRelayJoinDev([]string{
		"--relay-space", "relay-space-1",
		"--sidecar-device-label", "bob-sidecar",
	})
	if err == nil || !strings.Contains(err.Error(), "--relay-space, --sidecar-device-label, and --conversation are required") {
		t.Fatalf("expected required join args error, got %v", err)
	}
}

func TestOpenMLSRelayJoinDevWritesWelcomeRunsSidecarWithoutAckByDefault(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	oldWrite := writeRelaySpaceWelcomeFromEnvelopeForCommand
	oldRun := runOpenMLSBootstrapSidecarForCommand
	oldAck := ackRelaySpaceEnvelopeForCommand
	defer func() {
		relaySpaceOpenMLSArtifactInboxForCommand = oldInbox
		writeRelaySpaceWelcomeFromEnvelopeForCommand = oldWrite
		runOpenMLSBootstrapSidecarForCommand = oldRun
		ackRelaySpaceEnvelopeForCommand = oldAck
	}()

	var gotInboxRelaySpaceID string
	var gotInboxDeviceID string
	var gotInboxArtifactKind string

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
		gotInboxRelaySpaceID = relaySpaceID
		gotInboxDeviceID = deviceID
		gotInboxArtifactKind = artifactKind
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

	var wroteEnvelopeID string
	var wroteOutputPath string

	writeRelaySpaceWelcomeFromEnvelopeForCommand = func(outputPath string, envelope client.RelaySpaceEnvelopeRecord) error {
		wroteOutputPath = outputPath
		wroteEnvelopeID = envelope.EnvelopeID
		return nil
	}

	var gotSidecarDir string
	var gotSidecarCommand string
	var gotSidecarArgs []string

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		gotSidecarDir = sidecarDir
		gotSidecarCommand = sidecarCommand
		gotSidecarArgs = append([]string{}, args...)
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "conversation-join",
			Data: map[string]any{
				"device_label":                   "bob-sidecar",
				"conversation_label":             "test-conversation",
				"welcome_artifact_path_hint":     ".carbonstack-openmls-sidecar-state/dev/devices/bob-sidecar/conversations/test-conversation/welcome.bin",
				"joined":                         true,
				"group_reloadable":               true,
				"member_count":                   float64(2),
				"epoch":                          "GroupEpoch(1)",
				"join_summary_path_hint":         ".carbonstack-openmls-sidecar-state/dev/devices/bob-sidecar/conversations/test-conversation/join-summary.json",
				"conversation_state_path_hint":   ".carbonstack-openmls-sidecar-state/dev/devices/bob-sidecar/conversations/test-conversation/conversation.bin",
				"conversation_summary_path_hint": ".carbonstack-openmls-sidecar-state/dev/devices/bob-sidecar/conversations/test-conversation/summary.json",
				"provider_storage_path_hint":     ".carbonstack-openmls-sidecar-state/dev/devices/bob-sidecar/provider-storage",
			},
		}, nil
	}

	ackCalled := false
	ackRelaySpaceEnvelopeForCommand = func(c client.CypherClient, relaySpaceID string, envelopeID string, recipientDeviceID string) (client.AckRelaySpaceEnvelopeResponse, error) {
		ackCalled = true
		return client.AckRelaySpaceEnvelopeResponse{}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSRelayJoinDev([]string{
			"--state", statePath,
			"--relay-space", "relay-space-1",
			"--sidecar-dir", "sidecar-test-dir",
			"--sidecar-device-label", "bob-sidecar",
			"--conversation", "test-conversation",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotInboxRelaySpaceID != "relay-space-1" {
		t.Fatalf("inbox relay_space_id = %q", gotInboxRelaySpaceID)
	}
	if gotInboxDeviceID != "local-device-id" {
		t.Fatalf("inbox device_id = %q", gotInboxDeviceID)
	}
	if gotInboxArtifactKind != relay.ArtifactKindWelcome {
		t.Fatalf("inbox artifact kind = %q", gotInboxArtifactKind)
	}
	if wroteEnvelopeID != "welcome-envelope-1" {
		t.Fatalf("wrote envelope = %q", wroteEnvelopeID)
	}
	if !strings.Contains(wroteOutputPath, "welcome.bin") {
		t.Fatalf("unexpected welcome output path: %q", wroteOutputPath)
	}

	if gotSidecarDir != "sidecar-test-dir" {
		t.Fatalf("sidecar dir = %q", gotSidecarDir)
	}
	if gotSidecarCommand != "conversation-join" {
		t.Fatalf("sidecar command = %q", gotSidecarCommand)
	}
	if strings.Join(gotSidecarArgs[:4], " ") != "--device-label bob-sidecar --conversation-label test-conversation" {
		t.Fatalf("unexpected leading sidecar args: %q", strings.Join(gotSidecarArgs, " "))
	}
	if gotSidecarArgs[4] != "--welcome" {
		t.Fatalf("expected welcome flag, got args: %q", strings.Join(gotSidecarArgs, " "))
	}
	if gotSidecarArgs[5] != wroteOutputPath {
		t.Fatalf("welcome path = %q, want %q", gotSidecarArgs[5], wroteOutputPath)
	}
	if ackCalled {
		t.Fatal("ack should not be called without --ack-after-join")
	}

	for _, want := range []string{
		"command: openmls-relay-join-dev",
		"status: joined",
		"relay_space_id: relay-space-1",
		"local_device_id: local-device-id",
		"welcome_envelope_id: welcome-envelope-1",
		"welcome_from_device: alice-device-id",
		"sidecar_command: conversation-join",
		"sidecar_device_label: bob-sidecar",
		"sidecar_conversation_label: test-conversation",
		"ack_requested: false",
		"welcome_acked: false",
		"joined: true",
		"group_reloadable: true",
		"member_count: 2",
		"epoch: GroupEpoch(1)",
		"warning: dev/pre-alpha Relay Space join scaffold; not identity verification, local-backbone, or production UX",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSRelayJoinDevAcksOnlyAfterJoinSuccessWhenRequested(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	oldWrite := writeRelaySpaceWelcomeFromEnvelopeForCommand
	oldRun := runOpenMLSBootstrapSidecarForCommand
	oldAck := ackRelaySpaceEnvelopeForCommand
	defer func() {
		relaySpaceOpenMLSArtifactInboxForCommand = oldInbox
		writeRelaySpaceWelcomeFromEnvelopeForCommand = oldWrite
		runOpenMLSBootstrapSidecarForCommand = oldRun
		ackRelaySpaceEnvelopeForCommand = oldAck
	}()

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
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
		return nil
	}

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "conversation-join",
			Data: map[string]any{
				"device_label":       "bob-sidecar",
				"conversation_label": "test-conversation",
				"joined":             true,
				"group_reloadable":   true,
				"member_count":       float64(2),
				"epoch":              "GroupEpoch(1)",
			},
		}, nil
	}

	var gotAckRelaySpaceID string
	var gotAckEnvelopeID string
	var gotAckRecipientDeviceID string

	ackRelaySpaceEnvelopeForCommand = func(c client.CypherClient, relaySpaceID string, envelopeID string, recipientDeviceID string) (client.AckRelaySpaceEnvelopeResponse, error) {
		gotAckRelaySpaceID = relaySpaceID
		gotAckEnvelopeID = envelopeID
		gotAckRecipientDeviceID = recipientDeviceID
		return client.AckRelaySpaceEnvelopeResponse{
			EnvelopeID:     envelopeID,
			RelaySpaceID:   relaySpaceID,
			DeliveryState:  "acknowledged",
			AcknowledgedAt: "2026-06-08T00:03:00Z",
		}, nil
	}

	out, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSRelayJoinDev([]string{
			"--state", statePath,
			"--relay-space", "relay-space-1",
			"--sidecar-device-label", "bob-sidecar",
			"--conversation", "test-conversation",
			"--ack-after-join",
		})
	})
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if gotAckRelaySpaceID != "relay-space-1" {
		t.Fatalf("ack relay_space_id = %q", gotAckRelaySpaceID)
	}
	if gotAckEnvelopeID != "welcome-envelope-1" {
		t.Fatalf("ack envelope_id = %q", gotAckEnvelopeID)
	}
	if gotAckRecipientDeviceID != "local-device-id" {
		t.Fatalf("ack recipient_device_id = %q", gotAckRecipientDeviceID)
	}

	for _, want := range []string{
		"ack_requested: true",
		"welcome_acked: true",
		"ack_envelope_id: welcome-envelope-1",
		"ack_delivery_state: acknowledged",
		"acknowledged_at: 2026-06-08T00:03:00Z",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOpenMLSRelayJoinDevDoesNotAckWhenSidecarJoinFails(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	oldWrite := writeRelaySpaceWelcomeFromEnvelopeForCommand
	oldRun := runOpenMLSBootstrapSidecarForCommand
	oldAck := ackRelaySpaceEnvelopeForCommand
	defer func() {
		relaySpaceOpenMLSArtifactInboxForCommand = oldInbox
		writeRelaySpaceWelcomeFromEnvelopeForCommand = oldWrite
		runOpenMLSBootstrapSidecarForCommand = oldRun
		ackRelaySpaceEnvelopeForCommand = oldAck
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
		return nil
	}

	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, sidecarCommand string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		return openMLSSidecarBootstrapEnvelope{}, errors.New("sidecar join failed")
	}

	ackCalled := false
	ackRelaySpaceEnvelopeForCommand = func(c client.CypherClient, relaySpaceID string, envelopeID string, recipientDeviceID string) (client.AckRelaySpaceEnvelopeResponse, error) {
		ackCalled = true
		return client.AckRelaySpaceEnvelopeResponse{}, nil
	}

	err := cmdOpenMLSRelayJoinDev([]string{
		"--state", statePath,
		"--relay-space", "relay-space-1",
		"--sidecar-device-label", "bob-sidecar",
		"--conversation", "test-conversation",
		"--ack-after-join",
	})
	if err == nil || !strings.Contains(err.Error(), "sidecar join failed") {
		t.Fatalf("expected sidecar join failure, got %v", err)
	}
	if ackCalled {
		t.Fatal("ack should not be called when sidecar join fails")
	}
}

func TestOpenMLSRelayJoinDevDoesNotAckWhenWelcomeWriteFails(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	oldWrite := writeRelaySpaceWelcomeFromEnvelopeForCommand
	oldAck := ackRelaySpaceEnvelopeForCommand
	defer func() {
		relaySpaceOpenMLSArtifactInboxForCommand = oldInbox
		writeRelaySpaceWelcomeFromEnvelopeForCommand = oldWrite
		ackRelaySpaceEnvelopeForCommand = oldAck
	}()

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
		return []client.RelaySpaceEnvelopeRecord{
			{
				EnvelopeID:      "welcome-envelope-1",
				RelaySpaceID:    relaySpaceID,
				ContentType:     relay.ContentTypeOpenMLSWelcome,
				ProtocolVersion: relay.ProtocolVersionOpenMLSSidecar,
			},
		}, nil
	}

	writeRelaySpaceWelcomeFromEnvelopeForCommand = func(outputPath string, envelope client.RelaySpaceEnvelopeRecord) error {
		return errors.New("welcome write failed")
	}

	ackCalled := false
	ackRelaySpaceEnvelopeForCommand = func(c client.CypherClient, relaySpaceID string, envelopeID string, recipientDeviceID string) (client.AckRelaySpaceEnvelopeResponse, error) {
		ackCalled = true
		return client.AckRelaySpaceEnvelopeResponse{}, nil
	}

	err := cmdOpenMLSRelayJoinDev([]string{
		"--state", statePath,
		"--relay-space", "relay-space-1",
		"--sidecar-device-label", "bob-sidecar",
		"--conversation", "test-conversation",
		"--ack-after-join",
	})
	if err == nil || !strings.Contains(err.Error(), "write Relay Space Welcome artifact") {
		t.Fatalf("expected welcome write failure, got %v", err)
	}
	if ackCalled {
		t.Fatal("ack should not be called when Welcome write fails")
	}
}

func TestOpenMLSRelayJoinDevRejectsNoWelcomeEnvelopes(t *testing.T) {
	statePath := writeRelayCommandState(t)

	oldInbox := relaySpaceOpenMLSArtifactInboxForCommand
	defer func() { relaySpaceOpenMLSArtifactInboxForCommand = oldInbox }()

	relaySpaceOpenMLSArtifactInboxForCommand = func(c client.CypherClient, relaySpaceID string, deviceID string, artifactKind string) ([]client.RelaySpaceEnvelopeRecord, error) {
		return nil, nil
	}

	err := cmdOpenMLSRelayJoinDev([]string{
		"--state", statePath,
		"--relay-space", "relay-space-1",
		"--sidecar-device-label", "bob-sidecar",
		"--conversation", "test-conversation",
	})
	if err == nil || !strings.Contains(err.Error(), "no Relay Space Welcome envelopes available for join") {
		t.Fatalf("expected no Welcome envelopes error, got %v", err)
	}
}
