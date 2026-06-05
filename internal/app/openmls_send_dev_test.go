package app

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func TestOpenMLSSendDevRejectsMissingRequiredFlags(t *testing.T) {
	statePath := writeReadyState(t)

	err := Run([]string{
		"openmls-send-dev",
		"--state", statePath,
	})

	if err == nil {
		t.Fatal("expected missing required flags error")
	}
}

func TestOpenMLSSendDevDoesNotSubmitWhenProtectFails(t *testing.T) {
	statePath := writeReadyState(t)

	oldProtect := runOpenMLSMessageProtectForCommand
	oldSubmit := submitOpenMLSArtifactEnvelopeForCommand
	defer func() {
		runOpenMLSMessageProtectForCommand = oldProtect
		submitOpenMLSArtifactEnvelopeForCommand = oldSubmit
	}()

	runOpenMLSMessageProtectForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, plaintext string) (openMLSMessageProtectResult, error) {
		return openMLSMessageProtectResult{}, errors.New("protect failed")
	}

	submitCalled := false
	submitOpenMLSArtifactEnvelopeForCommand = func(c client.CypherClient, senderDeviceID string, recipientDeviceID string, artifactKind string, artifactPath string, clientCreatedAt string) (client.SubmitEnvelopeResponse, error) {
		submitCalled = true
		return client.SubmitEnvelopeResponse{}, nil
	}

	err := Run([]string{
		"openmls-send-dev",
		"--state", statePath,
		"--to-device", "recipient-device",
		"--sidecar-device-label", "carbonstack-alice-device",
		"--conversation", "carbonstack-test-conversation",
		"--message", "hello bob",
	})

	if err == nil {
		t.Fatal("expected protect failure")
	}
	if submitCalled {
		t.Fatal("submit should not be called when message-protect fails")
	}
}

func TestOpenMLSSendDevSubmitsApplicationMessageArtifact(t *testing.T) {
	statePath := writeReadyState(t)
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "application-message.bin")
	if err := os.WriteFile(artifactPath, []byte("protected OpenMLS bytes"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	oldProtect := runOpenMLSMessageProtectForCommand
	oldSubmit := submitOpenMLSArtifactEnvelopeForCommand
	defer func() {
		runOpenMLSMessageProtectForCommand = oldProtect
		submitOpenMLSArtifactEnvelopeForCommand = oldSubmit
	}()

	runOpenMLSMessageProtectForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, plaintext string) (openMLSMessageProtectResult, error) {
		if deviceLabel != "carbonstack-alice-device" {
			t.Fatalf("deviceLabel = %q", deviceLabel)
		}
		if conversationLabel != "carbonstack-test-conversation" {
			t.Fatalf("conversationLabel = %q", conversationLabel)
		}
		if messageLabel != "message-0007" {
			t.Fatalf("messageLabel = %q", messageLabel)
		}
		if plaintext != "hello bob" {
			t.Fatalf("plaintext = %q", plaintext)
		}

		return openMLSMessageProtectResult{
			DeviceLabel:             deviceLabel,
			ConversationLabel:       conversationLabel,
			MessageLabel:            messageLabel,
			MessageArtifactPathHint: artifactPath,
		}, nil
	}

	submitCalled := false
	submitOpenMLSArtifactEnvelopeForCommand = func(c client.CypherClient, senderDeviceID string, recipientDeviceID string, artifactKind string, submittedArtifactPath string, clientCreatedAt string) (client.SubmitEnvelopeResponse, error) {
		submitCalled = true

		if c.ServerURL != "http://127.0.0.1:18080" {
			t.Fatalf("server URL = %q", c.ServerURL)
		}
		if senderDeviceID != "sender-device" {
			t.Fatalf("senderDeviceID = %q", senderDeviceID)
		}
		if recipientDeviceID != "recipient-device" {
			t.Fatalf("recipientDeviceID = %q", recipientDeviceID)
		}
		if artifactKind != relay.ArtifactKindApplicationMessage {
			t.Fatalf("artifactKind = %q", artifactKind)
		}
		if submittedArtifactPath != artifactPath {
			t.Fatalf("artifactPath = %q", submittedArtifactPath)
		}
		if clientCreatedAt == "" {
			t.Fatal("clientCreatedAt should be set")
		}

		return client.SubmitEnvelopeResponse{
			EnvelopeID:       "env-openmls-1",
			DeliveryState:    "queued",
			ServerReceivedAt: "2026-06-05T00:00:00Z",
			PayloadSHA256:    "fake-sha256",
			PayloadSizeBytes: 23,
		}, nil
	}

	err := Run([]string{
		"openmls-send-dev",
		"--state", statePath,
		"--to-device", "recipient-device",
		"--sidecar-device-label", "carbonstack-alice-device",
		"--conversation", "carbonstack-test-conversation",
		"--message-label", "message-0007",
		"--message", "hello bob",
	})

	if err != nil {
		t.Fatalf("openmls-send-dev: %v", err)
	}
	if !submitCalled {
		t.Fatal("submit should be called after message-protect succeeds")
	}
}

func writeReadyState(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "state.json")
	s := state.State{
		ServerURL:       "http://127.0.0.1:18080",
		AccountID:       "account-1",
		DisplayName:     "Alice",
		DeviceID:        "sender-device",
		DeviceLabel:     "alice-device",
		ProtocolVersion: state.ProtocolVersion,
	}

	if err := state.Save(path, s); err != nil {
		t.Fatalf("save state: %v", err)
	}

	return path
}
