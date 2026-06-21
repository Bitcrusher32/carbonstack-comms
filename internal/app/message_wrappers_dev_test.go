package app

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
)

func TestMessageSendDevRejectsMissingRequiredFlags(t *testing.T) {
	statePath := writeReadyState(t)

	err := Run([]string{
		"message-send-dev",
		"--state", statePath,
	})

	if err == nil || !strings.Contains(err.Error(), "--to-device, --message, --sidecar-device-label, and --conversation are required") {
		t.Fatalf("expected missing required flags error, got %v", err)
	}
}

func TestMessageSendDevSendsWithOpinionatedOutput(t *testing.T) {
	statePath := writeReadyState(t)
	artifactPath := filepath.Join(t.TempDir(), "application-message.bin")

	restore := stubOpenMLSSendDevHooks(t)
	defer restore()

	runOpenMLSMessageProtectForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, plaintext string) (openMLSMessageProtectResult, error) {
		if deviceLabel != "carbonstack-alice-device" {
			t.Fatalf("deviceLabel = %q", deviceLabel)
		}
		if conversationLabel != "carbonstack-test-conversation" {
			t.Fatalf("conversationLabel = %q", conversationLabel)
		}
		if plaintext != "hello bob" {
			t.Fatalf("plaintext = %q", plaintext)
		}
		return openMLSMessageProtectResult{
			DeviceLabel:             deviceLabel,
			ConversationLabel:       conversationLabel,
			MessageLabel:            "message-wrapper-1",
			MessageArtifactPathHint: artifactPath,
		}, nil
	}

	submitOpenMLSArtifactEnvelopeForCommand = func(c client.CypherClient, senderDeviceID string, recipientDeviceID string, artifactKind string, submittedArtifactPath string, clientCreatedAt string) (client.SubmitEnvelopeResponse, error) {
		if recipientDeviceID != "recipient-device" {
			t.Fatalf("recipientDeviceID = %q", recipientDeviceID)
		}
		if artifactKind != relay.ArtifactKindApplicationMessage {
			t.Fatalf("artifactKind = %q", artifactKind)
		}
		if submittedArtifactPath != artifactPath {
			t.Fatalf("submittedArtifactPath = %q", submittedArtifactPath)
		}
		return client.SubmitEnvelopeResponse{
			EnvelopeID:       "env-message-wrapper-1",
			DeliveryState:    "queued",
			ServerReceivedAt: "2026-06-15T00:00:00Z",
			PayloadSHA256:    "wrapper-sha256",
			PayloadSizeBytes: 88,
		}, nil
	}

	output, err := captureOpenMLSRuntimeOutput(func() error {
		return Run([]string{
			"message-send-dev",
			"--state", statePath,
			"--to-device", "recipient-device",
			"--sidecar-device-label", "carbonstack-alice-device",
			"--conversation", "carbonstack-test-conversation",
			"--message", "hello bob",
		})
	})

	if err != nil {
		t.Fatalf("message-send-dev: %v", err)
	}

	for _, want := range []string{
		"message sent",
		"command: message-send-dev",
		"implementation_path: openmls-send-dev",
		"backend: OpenMLS sidecar + Cypher application-message envelope",
		"status: sent",
		"recipient_device_id: recipient-device",
		"conversation: carbonstack-test-conversation",
		"message_label: message-wrapper-1",
		"envelope_id: env-message-wrapper-1",
		"delivery_state: queued",
		"payload_sha256: wrapper-sha256",
		"payload_size_bytes: 88",
		"warning: dev/pre-alpha OpenMLS message wrapper; not production messaging UX",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("message-send-dev output missing %q\n%s", want, output)
		}
	}
	if strings.Contains(output, "openmls dev envelope sent") {
		t.Fatalf("message-send-dev should not print low-level openmls-send-dev banner\n%s", output)
	}
}

func TestMessageSendDevReturnsSubmitFailureAfterProtectSucceeds(t *testing.T) {
	statePath := writeReadyState(t)
	artifactPath := filepath.Join(t.TempDir(), "application-message.bin")

	restore := stubOpenMLSSendDevHooks(t)
	defer restore()

	runOpenMLSMessageProtectForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, plaintext string) (openMLSMessageProtectResult, error) {
		return openMLSMessageProtectResult{
			DeviceLabel:             deviceLabel,
			ConversationLabel:       conversationLabel,
			MessageLabel:            "message-wrapper-submit-failure",
			MessageArtifactPathHint: artifactPath,
		}, nil
	}

	submitOpenMLSArtifactEnvelopeForCommand = func(c client.CypherClient, senderDeviceID string, recipientDeviceID string, artifactKind string, submittedArtifactPath string, clientCreatedAt string) (client.SubmitEnvelopeResponse, error) {
		return client.SubmitEnvelopeResponse{}, errors.New("submit failed")
	}

	err := Run([]string{
		"message-send-dev",
		"--state", statePath,
		"--to-device", "recipient-device",
		"--sidecar-device-label", "carbonstack-alice-device",
		"--conversation", "carbonstack-test-conversation",
		"--message", "hello bob",
	})

	if err == nil || !strings.Contains(err.Error(), "submit failed") {
		t.Fatalf("expected submit failure, got %v", err)
	}
}

func TestMessageInboxDevReportsEmptyInboxWithoutOpenOrAck(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubInboxDevHooks(t)
	defer restore()

	inboxForCommand = func(c client.CypherClient, deviceID string) (client.InboxResponse, error) {
		return client.InboxResponse{DeviceID: deviceID}, nil
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
			"message-inbox-dev",
			"--state", statePath,
			"--sidecar-device-label", "carbonstack-bob-device",
			"--conversation", "carbonstack-test-conversation",
			"--ack",
		})
	})

	if err != nil {
		t.Fatalf("message-inbox-dev: %v", err)
	}
	if openCalled {
		t.Fatal("message-open should not be called for empty inbox")
	}
	if ackCalled {
		t.Fatal("ack should not be called for empty inbox")
	}

	for _, want := range []string{
		"message inbox",
		"command: message-inbox-dev",
		"implementation_path: openmls-inbox-dev",
		"backend: OpenMLS sidecar + Cypher application-message envelope",
		"queued_envelopes: 0",
		"ack_requested: true",
		"message inbox summary",
		"opened_envelopes: 0",
		"unsupported_envelopes: 0",
		"open_failures: 0",
		"ack_failures: 0",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("message-inbox-dev empty output missing %q\n%s", want, output)
		}
	}
}

func TestMessageInboxDevOpensAndAcksWithOpinionatedOutput(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubInboxDevHooks(t)
	defer restore()

	inboxForCommand = oneOpenMLSInboxResponse

	runOpenMLSMessageOpenForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, messageArtifactPath string) (openMLSMessageOpenResult, error) {
		if messageLabel != "message-wrapper-inbox-1" {
			t.Fatalf("messageLabel = %q", messageLabel)
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

	ackEnvelopeForCommand = func(c client.CypherClient, envelopeID string, recipientDeviceID string) (client.AckEnvelopeResponse, error) {
		return client.AckEnvelopeResponse{
			EnvelopeID:     envelopeID,
			DeliveryState:  "acknowledged",
			AcknowledgedAt: "2026-06-15T00:00:00Z",
		}, nil
	}

	output, err := captureOpenMLSRuntimeOutput(func() error {
		return Run([]string{
			"message-inbox-dev",
			"--state", statePath,
			"--sidecar-device-label", "carbonstack-bob-device",
			"--conversation", "carbonstack-test-conversation",
			"--message-label", "message-wrapper-inbox-1",
			"--ack",
		})
	})

	if err != nil {
		t.Fatalf("message-inbox-dev: %v", err)
	}

	for _, want := range []string{
		"message opened",
		"envelope_id: env-openmls-1",
		"ack_delivery_state: acknowledged",
		"from_device: alice-device",
		"from_device_unverified: alice-device",
		"sender_identity_verified: false",
		"warning: from_device is relay envelope metadata, not verified identity",
		"conversation: carbonstack-test-conversation",
		"message_label: message-wrapper-inbox-1",
		"plaintext_utf8: hello alice",
		"acked: true",
		"opened_envelopes: 1",
		"ack_failures: 0",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("message-inbox-dev output missing %q\n%s", want, output)
		}
	}
	if strings.Contains(output, "openmls dev inbox") {
		t.Fatalf("message-inbox-dev should not print low-level openmls-inbox-dev banner\n%s", output)
	}
}

func TestMessageInboxDevReportsAckFailureAfterOpenSuccess(t *testing.T) {
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
			"message-inbox-dev",
			"--state", statePath,
			"--sidecar-device-label", "carbonstack-bob-device",
			"--conversation", "carbonstack-test-conversation",
			"--ack",
		})
	})

	if err != nil {
		t.Fatalf("message-inbox-dev should report ack failure without failing command: %v", err)
	}

	for _, want := range []string{
		"message opened",
		"ack_error: ack failed",
		"acked: false",
		"opened_envelopes: 1",
		"ack_failures: 1",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("message-inbox-dev ack failure output missing %q\n%s", want, output)
		}
	}
}

func TestMessageSendDevStrictBlocksUnknownRecipientBeforeProtectOrSubmit(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubOpenMLSSendDevHooks(t)
	defer restore()

	protectCalled := false
	submitCalled := false

	runOpenMLSMessageProtectForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, plaintext string) (openMLSMessageProtectResult, error) {
		protectCalled = true
		return openMLSMessageProtectResult{}, nil
	}
	submitOpenMLSArtifactEnvelopeForCommand = func(c client.CypherClient, senderDeviceID string, recipientDeviceID string, artifactKind string, submittedArtifactPath string, clientCreatedAt string) (client.SubmitEnvelopeResponse, error) {
		submitCalled = true
		return client.SubmitEnvelopeResponse{}, nil
	}

	err := Run([]string{
		"message-send-dev",
		"--state", statePath,
		"--to-device", "unknown-recipient-device",
		"--sidecar-device-label", "carbonstack-alice-device",
		"--conversation", "carbonstack-test-conversation",
		"--message", "hello bob",
		"--strict",
	})

	if err == nil || !strings.Contains(err.Error(), "message-send-dev blocked by trust policy") {
		t.Fatalf("expected strict trust-policy block, got %v", err)
	}
	if protectCalled {
		t.Fatal("message-protect should not be called after strict trust-policy block")
	}
	if submitCalled {
		t.Fatal("submit should not be called after strict trust-policy block")
	}
}

func TestMessageSendDevResolvesRelativeArtifactHintAgainstSidecarDir(t *testing.T) {
	statePath := writeReadyState(t)
	sidecarDir := t.TempDir()

	restore := stubOpenMLSSendDevHooks(t)
	defer restore()

	runOpenMLSMessageProtectForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, plaintext string) (openMLSMessageProtectResult, error) {
		return openMLSMessageProtectResult{
			DeviceLabel:             deviceLabel,
			ConversationLabel:       conversationLabel,
			MessageLabel:            "message-relative-artifact",
			MessageArtifactPathHint: "relative/application-message.bin",
		}, nil
	}

	submitOpenMLSArtifactEnvelopeForCommand = func(c client.CypherClient, senderDeviceID string, recipientDeviceID string, artifactKind string, submittedArtifactPath string, clientCreatedAt string) (client.SubmitEnvelopeResponse, error) {
		want := filepath.Join(sidecarDir, "relative/application-message.bin")
		if submittedArtifactPath != want {
			t.Fatalf("submittedArtifactPath = %q, want %q", submittedArtifactPath, want)
		}
		return client.SubmitEnvelopeResponse{
			EnvelopeID:       "env-relative-artifact",
			DeliveryState:    "queued",
			ServerReceivedAt: "2026-06-05T00:00:00Z",
			PayloadSHA256:    "fake-sha256",
			PayloadSizeBytes: 23,
		}, nil
	}

	err := Run([]string{
		"message-send-dev",
		"--state", statePath,
		"--to-device", "recipient-device",
		"--sidecar-dir", sidecarDir,
		"--sidecar-device-label", "carbonstack-alice-device",
		"--conversation", "carbonstack-test-conversation",
		"--message", "hello bob",
	})
	if err != nil {
		t.Fatalf("message-send-dev: %v", err)
	}
}

func TestMessageInboxDevSkipsUnsupportedEnvelopeWithoutOpenOrAck(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubInboxDevHooks(t)
	defer restore()

	inboxForCommand = func(c client.CypherClient, deviceID string) (client.InboxResponse, error) {
		return client.InboxResponse{
			DeviceID: deviceID,
			Envelopes: []client.EnvelopeRecord{{
				EnvelopeID:        "stub-envelope",
				SenderDeviceID:    "alice-device",
				RecipientDeviceID: deviceID,
				ContentType:       "carbonstack.message.text.stub.v0",
				ProtocolVersion:   "stub-v0",
			}},
		}, nil
	}

	openCalled := false
	ackCalled := false

	runOpenMLSMessageOpenForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, messageArtifactPath string) (openMLSMessageOpenResult, error) {
		openCalled = true
		return openMLSMessageOpenResult{}, nil
	}
	ackEnvelopeForCommand = func(c client.CypherClient, envelopeID string, recipientDeviceID string) (client.AckEnvelopeResponse, error) {
		ackCalled = true
		return client.AckEnvelopeResponse{}, nil
	}

	var err error
	output := captureOutput(func() {
		err = Run([]string{
			"message-inbox-dev",
			"--state", statePath,
			"--sidecar-device-label", "carbonstack-bob-device",
			"--conversation", "carbonstack-test-conversation",
			"--ack",
		})
	})

	if err != nil {
		t.Fatalf("message-inbox-dev: %v", err)
	}
	if openCalled {
		t.Fatal("message-open should not be called for unsupported envelope")
	}
	if ackCalled {
		t.Fatal("ack should not be called for unsupported envelope")
	}
	for _, want := range []string{
		"message skipped",
		"reason: unsupported_envelope",
		"unsupported_envelopes: 1",
		"open_failures: 0",
		"ack_failures: 0",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("unsupported-envelope output missing %q\n%s", want, output)
		}
	}
}

func TestMessageInboxDevReportsMessageOpenFailureWithoutAck(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubInboxDevHooks(t)
	defer restore()

	inboxForCommand = oneOpenMLSInboxResponse

	runOpenMLSMessageOpenForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, messageArtifactPath string) (openMLSMessageOpenResult, error) {
		return openMLSMessageOpenResult{}, errors.New("message-open failed")
	}

	ackCalled := false
	ackEnvelopeForCommand = func(c client.CypherClient, envelopeID string, recipientDeviceID string) (client.AckEnvelopeResponse, error) {
		ackCalled = true
		return client.AckEnvelopeResponse{}, nil
	}

	var err error
	output := captureOutput(func() {
		err = Run([]string{
			"message-inbox-dev",
			"--state", statePath,
			"--sidecar-device-label", "carbonstack-bob-device",
			"--conversation", "carbonstack-test-conversation",
			"--ack",
		})
	})

	if err != nil {
		t.Fatalf("message-inbox-dev should report open failure without failing command: %v", err)
	}
	if ackCalled {
		t.Fatal("ack should not be called when message-open fails")
	}
	for _, want := range []string{
		"message open failed",
		"error: message-open failed",
		"acked: false",
		"open_failures: 1",
		"ack_failures: 0",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("message-open failure output missing %q\n%s", want, output)
		}
	}
}
