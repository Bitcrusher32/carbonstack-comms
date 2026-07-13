package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
)

func TestKeyPackagePublicationCommandSelectsInspectsAndPublishes(
	t *testing.T,
) {
	oldSidecar := runOpenMLSKeyPackagePublicationSidecarForCommand
	oldPublish := publishRelaySpaceKeyPackageForCommand
	t.Cleanup(func() {
		runOpenMLSKeyPackagePublicationSidecarForCommand = oldSidecar
		publishRelaySpaceKeyPackageForCommand = oldPublish
	})

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(
		statePath,
		[]byte(`{"server_url":"http://cypher.test","device_id":"sender-device"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	var commands []string
	runOpenMLSKeyPackagePublicationSidecarForCommand = func(
		sidecarDir string,
		command string,
		args ...string,
	) (openMLSSidecarBootstrapEnvelope, error) {
		commands = append(commands, command)
		switch command {
		case "keypackage-inventory":
			return openMLSSidecarBootstrapEnvelope{
				OK:      true,
				Command: command,
				Data: map[string]any{
					"device_label":          "alice-sidecar",
					"current_generation_id": "kp-000002",
					"generations": []any{
						map[string]any{
							"generation_id": "kp-000002",
							"request_id":    "rotate-two",
							"key_package_ref": "sha256:" +
								strings.Repeat("a", 64),
							"artifact_path": "/tmp/keypackage.bin",
							"artifact_sha256": "sha256:" +
								strings.Repeat("b", 64),
							"artifact_size_bytes":      float64(1234),
							"manifest_path":            "/tmp/manifest.json",
							"lifetime_not_before_unix": float64(10),
							"lifetime_not_after_unix":  float64(20),
							"status":                   "active",
						},
					},
				},
			}, nil
		case "keypackage-inspect":
			return openMLSSidecarBootstrapEnvelope{
				OK:      true,
				Command: command,
				Data: map[string]any{
					"key_package_ref": "sha256:" +
						strings.Repeat("a", 64),
					"key_package_artifact_sha256": "sha256:" +
						strings.Repeat("b", 64),
					"key_package_artifact_size_bytes": float64(1234),
					"lifetime_not_before_unix":        float64(10),
					"lifetime_not_after_unix":         float64(20),
					"valid_at_inspection_time":        true,
					"openmls_validation_passed":       true,
					"owner_match":                     true,
					"local_state_mutated":             false,
				},
			}, nil
		default:
			t.Fatalf("unexpected sidecar command %q", command)
			return openMLSSidecarBootstrapEnvelope{}, nil
		}
	}

	var published bool
	publishRelaySpaceKeyPackageForCommand = func(
		c client.CypherClient,
		relaySpaceID string,
		senderDeviceID string,
		recipientDeviceID string,
		keyPackageRef string,
		artifactPath string,
		clientCreatedAt string,
	) (client.PublishRelaySpaceKeyPackageResponse, error) {
		published = true
		if c.ServerURL != "http://cypher.test" ||
			relaySpaceID != "space-1" ||
			senderDeviceID != "sender-device" ||
			recipientDeviceID != "recipient-device" ||
			keyPackageRef != "sha256:"+strings.Repeat("a", 64) ||
			artifactPath != "/tmp/keypackage.bin" {
			t.Fatalf(
				"unexpected publish arguments: %#v %q %q %q %q %q",
				c,
				relaySpaceID,
				senderDeviceID,
				recipientDeviceID,
				keyPackageRef,
				artifactPath,
			)
		}
		return client.PublishRelaySpaceKeyPackageResponse{
			EnvelopeID:                "envelope-1",
			RelaySpaceID:              relaySpaceID,
			SenderDeviceID:            senderDeviceID,
			RecipientDeviceID:         recipientDeviceID,
			KeyPackageRef:             keyPackageRef,
			ContentType:               "carbonstack.mls.keypackage.v0",
			ProtocolVersion:           "carbonstack-openmls-sidecar-v0",
			DeliveryState:             "queued",
			ServerReceivedAt:          "2026-07-13T05:00:01Z",
			PayloadSHA256:             strings.Repeat("c", 64),
			PayloadSizeBytes:          1234,
			PublicationClassification: "created",
			Idempotent:                false,
		}, nil
	}

	output, err := captureOpenMLSBootstrapOutput(func() error {
		return cmdOpenMLSRelayKeyPackagePublishDev([]string{
			"--state", statePath,
			"--relay-space", "space-1",
			"--to-device", "recipient-device",
			"--sidecar-dir", "/tmp/sidecar",
			"--sidecar-device-label", "alice-sidecar",
			"--generation-id", "kp-000002",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !published ||
		strings.Join(commands, ",") !=
			"keypackage-inventory,keypackage-inspect" {
		t.Fatalf("published=%t commands=%v", published, commands)
	}
	for _, marker := range []string{
		"command: openmls-relay-keypackage-publish-dev",
		"publication_classification: created",
		"generation_id: kp-000002",
		"keypackage_acked: false",
		"welcome_submitted: false",
		"trust_or_candidate_state_mutated: false",
	} {
		if !strings.Contains(output, marker) {
			t.Fatalf("output missing %q:\n%s", marker, output)
		}
	}
}

func TestKeyPackagePublicationCommandRefusesRetiredBeforeNetwork(t *testing.T) {
	oldSidecar := runOpenMLSKeyPackagePublicationSidecarForCommand
	oldPublish := publishRelaySpaceKeyPackageForCommand
	t.Cleanup(func() {
		runOpenMLSKeyPackagePublicationSidecarForCommand = oldSidecar
		publishRelaySpaceKeyPackageForCommand = oldPublish
	})

	runOpenMLSKeyPackagePublicationSidecarForCommand = func(
		sidecarDir string,
		command string,
		args ...string,
	) (openMLSSidecarBootstrapEnvelope, error) {
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: command,
			Data: map[string]any{
				"generations": []any{
					map[string]any{
						"generation_id": "kp-000001",
						"status":        "retired",
					},
				},
			},
		}, nil
	}
	publishRelaySpaceKeyPackageForCommand = func(
		c client.CypherClient,
		relaySpaceID string,
		senderDeviceID string,
		recipientDeviceID string,
		keyPackageRef string,
		artifactPath string,
		clientCreatedAt string,
	) (client.PublishRelaySpaceKeyPackageResponse, error) {
		t.Fatal("publish must not run for retired generation")
		return client.PublishRelaySpaceKeyPackageResponse{}, nil
	}

	_, err := inspectKeyPackagePublicationGeneration(
		"/tmp/sidecar",
		"alice",
		"kp-000001",
	)
	if err == nil || !strings.Contains(err.Error(), "generation_retired") {
		t.Fatalf("error = %v", err)
	}
}

func TestKeyPackagePublicationCommandRequiresArguments(t *testing.T) {
	err := cmdOpenMLSRelayKeyPackagePublishDev(nil)
	if err == nil {
		t.Fatal("expected required argument error")
	}
}
