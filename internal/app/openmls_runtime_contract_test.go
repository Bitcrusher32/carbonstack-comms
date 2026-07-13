package app

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
)

func TestOpenMLSSendDevReturnsSubmitFailureAfterProtectSucceeds(t *testing.T) {
	statePath := writeReadyState(t)
	artifactPath := filepath.Join(t.TempDir(), "application-message.bin")

	restore := stubOpenMLSSendDevHooks(t)
	defer restore()

	runOpenMLSMessageProtectForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, plaintext string) (openMLSMessageProtectResult, error) {
		return openMLSMessageProtectResult{
			DeviceLabel:             deviceLabel,
			ConversationLabel:       conversationLabel,
			MessageLabel:            "message-submit-failure",
			MessageArtifactPathHint: artifactPath,
		}, nil
	}

	submitCalled := false
	submitOpenMLSArtifactEnvelopeForCommand = func(c client.CypherClient, senderDeviceID string, recipientDeviceID string, artifactKind string, submittedArtifactPath string, clientCreatedAt string) (client.SubmitEnvelopeResponse, error) {
		submitCalled = true

		if submittedArtifactPath != artifactPath {
			t.Fatalf("submittedArtifactPath = %q", submittedArtifactPath)
		}
		if artifactKind != relay.ArtifactKindApplicationMessage {
			t.Fatalf("artifactKind = %q", artifactKind)
		}

		return client.SubmitEnvelopeResponse{}, errors.New("submit failed")
	}

	err := Run([]string{
		"openmls-send-dev",
		"--state", statePath,
		"--to-device", "recipient-device",
		"--sidecar-device-label", "carbonstack-alice-device",
		"--conversation", "carbonstack-test-conversation",
		"--message", "hello bob",
	})

	if err == nil || !strings.Contains(err.Error(), "submit failed") {
		t.Fatalf("expected submit failure, got %v", err)
	}
	if !submitCalled {
		t.Fatal("submit should be called after message-protect succeeds")
	}
}

func TestOpenMLSSendDevRejectsEmptyMessageArtifactHintWithoutSubmit(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubOpenMLSSendDevHooks(t)
	defer restore()

	runOpenMLSMessageProtectForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, plaintext string) (openMLSMessageProtectResult, error) {
		return openMLSMessageProtectResult{
			DeviceLabel:       deviceLabel,
			ConversationLabel: conversationLabel,
			MessageLabel:      "message-empty-hint",
		}, nil
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

	if err == nil || !strings.Contains(err.Error(), "message_artifact_path_hint") {
		t.Fatalf("expected empty artifact hint error, got %v", err)
	}
	if submitCalled {
		t.Fatal("submit should not be called when message_artifact_path_hint is empty")
	}
}

func TestOpenMLSSendDevPrintsStableSuccessOutputContract(t *testing.T) {
	statePath := writeReadyState(t)
	artifactPath := filepath.Join(t.TempDir(), "application-message.bin")

	restore := stubOpenMLSSendDevHooks(t)
	defer restore()

	runOpenMLSMessageProtectForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, plaintext string) (openMLSMessageProtectResult, error) {
		return openMLSMessageProtectResult{
			DeviceLabel:             deviceLabel,
			ConversationLabel:       conversationLabel,
			MessageLabel:            "message-contract",
			MessageArtifactPathHint: artifactPath,
		}, nil
	}

	submitOpenMLSArtifactEnvelopeForCommand = func(c client.CypherClient, senderDeviceID string, recipientDeviceID string, artifactKind string, submittedArtifactPath string, clientCreatedAt string) (client.SubmitEnvelopeResponse, error) {
		return client.SubmitEnvelopeResponse{
			EnvelopeID:       "env-openmls-contract",
			DeliveryState:    "queued",
			ServerReceivedAt: "2026-06-15T00:00:00Z",
			PayloadSHA256:    "contract-sha256",
			PayloadSizeBytes: 42,
		}, nil
	}

	output, err := captureOpenMLSRuntimeOutput(func() error {
		return Run([]string{
			"openmls-send-dev",
			"--state", statePath,
			"--to-device", "recipient-device",
			"--sidecar-device-label", "carbonstack-alice-device",
			"--conversation", "carbonstack-test-conversation",
			"--message", "hello bob",
		})
	})

	if err != nil {
		t.Fatalf("openmls-send-dev: %v", err)
	}

	for _, want := range []string{
		"openmls dev envelope sent",
		"command: openmls-send-dev",
		"status: sent",
		"sender_device_id: sender-device",
		"recipient_device_id: recipient-device",
		"content_type: " + relay.ContentTypeOpenMLSApplicationMessage,
		"protocol_version: " + relay.ProtocolVersionOpenMLSSidecar,
		"envelope_id: env-openmls-contract",
		"delivery_state: queued",
		"payload_sha256: contract-sha256",
		"payload_size_bytes: 42",
		"sidecar_device_label: carbonstack-alice-device",
		"sidecar_conversation_label: carbonstack-test-conversation",
		"sidecar_message_label: message-contract",
		"warning: dev/pre-alpha OpenMLS runtime path; not production messaging UX",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("send output missing %q\n%s", want, output)
		}
	}
}

func TestOpenMLSInboxDevReportsEmptyInboxWithoutOpenOrAck(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubInboxDevHooks(t)
	defer restore()

	inboxForCommand = func(c client.CypherClient, deviceID string) (client.InboxResponse, error) {
		return client.InboxResponse{
			DeviceID:  deviceID,
			Envelopes: nil,
		}, nil
	}

	openCalled := false
	runOpenMLSMessageOpenForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, messageArtifactPath string) (openMLSMessageOpenResult, error) {
		openCalled = true
		return openMLSMessageOpenResult{}, nil
	}

	ackCalled := false
	ackEnvelopeForCommand = func(c client.CypherClient, envelopeID string, recipientDeviceID string) (client.AckEnvelopeResponse, error) {
		ackCalled = true
		return client.AckEnvelopeResponse{}, nil
	}

	output, err := captureOpenMLSRuntimeOutput(func() error {
		return Run([]string{
			"openmls-inbox-dev",
			"--state", statePath,
			"--sidecar-device-label", "carbonstack-bob-device",
			"--conversation", "carbonstack-test-conversation",
			"--ack",
		})
	})

	if err != nil {
		t.Fatalf("openmls-inbox-dev: %v", err)
	}
	if openCalled {
		t.Fatal("message-open should not be called for empty inbox")
	}
	if ackCalled {
		t.Fatal("ack should not be called for empty inbox")
	}

	for _, want := range []string{
		"queued_envelopes: 0",
		"ack_requested: true",
		"opened_envelopes: 0",
		"unsupported_envelopes: 0",
		"open_failures: 0",
		"ack_failures: 0",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("empty inbox output missing %q\n%s", want, output)
		}
	}
}

func TestOpenMLSInboxDevReportsArtifactWriteFailureWithoutOpenOrAck(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubInboxDevHooks(t)
	defer restore()

	inboxForCommand = oneOpenMLSInboxResponse

	writeOpenMLSArtifactFromEnvelopeForCommand = func(outputPath string, envelope client.EnvelopeRecord) error {
		return errors.New("artifact write failed")
	}

	openCalled := false
	runOpenMLSMessageOpenForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, messageArtifactPath string) (openMLSMessageOpenResult, error) {
		openCalled = true
		return openMLSMessageOpenResult{}, nil
	}

	ackCalled := false
	ackEnvelopeForCommand = func(c client.CypherClient, envelopeID string, recipientDeviceID string) (client.AckEnvelopeResponse, error) {
		ackCalled = true
		return client.AckEnvelopeResponse{}, nil
	}

	output, err := captureOpenMLSRuntimeOutput(func() error {
		return Run([]string{
			"openmls-inbox-dev",
			"--state", statePath,
			"--sidecar-device-label", "carbonstack-bob-device",
			"--conversation", "carbonstack-test-conversation",
			"--ack",
		})
	})

	if err != nil {
		t.Fatalf("openmls-inbox-dev should report artifact write failure without failing command: %v", err)
	}
	if openCalled {
		t.Fatal("message-open should not be called after artifact write failure")
	}
	if ackCalled {
		t.Fatal("ack should not be called after artifact write failure")
	}

	for _, want := range []string{
		"openmls_envelope_write_failed",
		"envelope_id: env-openmls-1",
		"artifact write failed",
		"opened_envelopes: 0",
		"open_failures: 1",
		"ack_failures: 0",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("artifact write failure output missing %q\n%s", want, output)
		}
	}
}

func TestOpenMLSInboxDevReportsAckFailureAfterOpenSuccess(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubInboxDevHooks(t)
	defer restore()

	inboxForCommand = oneOpenMLSInboxResponse

	runOpenMLSMessageOpenForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, messageArtifactPath string) (openMLSMessageOpenResult, error) {
		return openMLSMessageOpenResult{
			DeviceLabel:       deviceLabel,
			ConversationLabel: conversationLabel,
			MessageLabel:      messageLabel,
			PlaintextUTF8:     "hello alice",
			PlaintextLen:      len("hello alice"),
			MessageOpened:     true,
		}, nil
	}

	ackEnvelopeForCommand = func(c client.CypherClient, envelopeID string, recipientDeviceID string) (client.AckEnvelopeResponse, error) {
		return client.AckEnvelopeResponse{}, errors.New("ack failed")
	}

	output, err := captureOpenMLSRuntimeOutput(func() error {
		return Run([]string{
			"openmls-inbox-dev",
			"--state", statePath,
			"--sidecar-device-label", "carbonstack-bob-device",
			"--conversation", "carbonstack-test-conversation",
			"--message-label", "message-ack-failure",
			"--ack",
		})
	})

	if err != nil {
		t.Fatalf("openmls-inbox-dev should report ack failure without failing command: %v", err)
	}

	for _, want := range []string{
		"openmls_message_opened_but_ack_failed",
		"error: ack failed",
		"sidecar_message_label: message-ack-failure",
		"plaintext_utf8: hello alice",
		"acked: false",
		"opened_envelopes: 1",
		"ack_failures: 1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("ack failure output missing %q\n%s", want, output)
		}
	}
}

func TestOpenMLSInboxDevHonorsLimitAndGeneratedMessageLabel(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubInboxDevHooks(t)
	defer restore()

	inboxForCommand = func(c client.CypherClient, deviceID string) (client.InboxResponse, error) {
		return client.InboxResponse{
			DeviceID: deviceID,
			Envelopes: []client.EnvelopeRecord{
				openMLSApplicationEnvelope("env-openmls-1", "alice-device", deviceID, "protected OpenMLS bytes 1"),
				openMLSApplicationEnvelope("env-openmls-2", "alice-device", deviceID, "protected OpenMLS bytes 2"),
			},
		}, nil
	}

	openCount := 0
	runOpenMLSMessageOpenForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, messageArtifactPath string) (openMLSMessageOpenResult, error) {
		openCount++

		if messageLabel != "inbox-1" {
			t.Fatalf("generated messageLabel = %q", messageLabel)
		}

		return openMLSMessageOpenResult{
			DeviceLabel:       deviceLabel,
			ConversationLabel: conversationLabel,
			MessageLabel:      messageLabel,
			PlaintextUTF8:     "hello alice",
			PlaintextLen:      len("hello alice"),
			MessageOpened:     true,
		}, nil
	}

	output, err := captureOpenMLSRuntimeOutput(func() error {
		return Run([]string{
			"openmls-inbox-dev",
			"--state", statePath,
			"--sidecar-device-label", "carbonstack-bob-device",
			"--conversation", "carbonstack-test-conversation",
			"--limit", "1",
		})
	})

	if err != nil {
		t.Fatalf("openmls-inbox-dev: %v", err)
	}
	if openCount != 1 {
		t.Fatalf("message-open count = %d, want 1", openCount)
	}

	for _, want := range []string{
		"queued_envelopes: 2",
		"limit: 1",
		"envelope_id: env-openmls-1",
		"sidecar_message_label: inbox-1",
		"opened_envelopes: 1",
		"open_failures: 0",
		"ack_failures: 0",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("limit output missing %q\n%s", want, output)
		}
	}
	if strings.Contains(output, "envelope_id: env-openmls-2") {
		t.Fatalf("second envelope should not be opened with --limit 1\n%s", output)
	}
}

func stubOpenMLSSendDevHooks(t *testing.T) func() {
	t.Helper()

	oldProtect := runOpenMLSMessageProtectForCommand
	oldSubmit := submitOpenMLSArtifactEnvelopeForCommand
	oldRelaySpaceSubmit := submitRelaySpaceOpenMLSArtifactEnvelopeForMessageCommand

	return func() {
		runOpenMLSMessageProtectForCommand = oldProtect
		submitOpenMLSArtifactEnvelopeForCommand = oldSubmit
		submitRelaySpaceOpenMLSArtifactEnvelopeForMessageCommand = oldRelaySpaceSubmit
	}
}

func openMLSApplicationEnvelope(envelopeID string, senderDeviceID string, recipientDeviceID string, payload string) client.EnvelopeRecord {
	return client.EnvelopeRecord{
		EnvelopeID:        envelopeID,
		SenderDeviceID:    senderDeviceID,
		RecipientDeviceID: recipientDeviceID,
		ContentType:       relay.ContentTypeOpenMLSApplicationMessage,
		ProtocolVersion:   relay.ProtocolVersionOpenMLSSidecar,
		CiphertextB64:     relay.EncodePayloadBase64([]byte(payload)),
		PayloadSizeBytes:  int64(len(payload)),
	}
}

func captureOpenMLSRuntimeOutput(fn func() error) (string, error) {
	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		return "", err
	}

	os.Stdout = writer
	runErr := fn()

	closeErr := writer.Close()
	os.Stdout = oldStdout
	if closeErr != nil {
		return "", closeErr
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return "", err
	}
	if err := reader.Close(); err != nil {
		return "", err
	}

	return buf.String(), runErr
}
