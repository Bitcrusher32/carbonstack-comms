package app

import (
	"errors"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
)

func TestOpenMLSInboxDevRejectsMissingRequiredFlags(t *testing.T) {
	statePath := writeReadyState(t)

	err := Run([]string{
		"openmls-inbox-dev",
		"--state", statePath,
	})

	if err == nil {
		t.Fatal("expected missing required flags error")
	}
}

func TestOpenMLSInboxDevSkipsUnsupportedEnvelopes(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubInboxDevHooks(t)
	defer restore()

	inboxForCommand = func(c client.CypherClient, deviceID string) (client.InboxResponse, error) {
		return client.InboxResponse{
			DeviceID: deviceID,
			Envelopes: []client.EnvelopeRecord{
				{
					EnvelopeID:      "stub-envelope",
					ContentType:     "carbonstack.message.text.stub.v0",
					ProtocolVersion: "stub-v0",
				},
			},
		}, nil
	}

	opened := false
	runOpenMLSMessageOpenForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, messageArtifactPath string) (openMLSMessageOpenResult, error) {
		opened = true
		return openMLSMessageOpenResult{}, nil
	}

	err := Run([]string{
		"openmls-inbox-dev",
		"--state", statePath,
		"--sidecar-device-label", "carbonstack-bob-device",
		"--conversation", "carbonstack-test-conversation",
	})

	if err != nil {
		t.Fatalf("openmls-inbox-dev: %v", err)
	}
	if opened {
		t.Fatal("message-open should not be called for unsupported envelope")
	}
}

func TestOpenMLSInboxDevDoesNotAckWhenMessageOpenFails(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubInboxDevHooks(t)
	defer restore()

	inboxForCommand = oneOpenMLSInboxResponse

	ackCalled := false
	ackEnvelopeForCommand = func(c client.CypherClient, envelopeID string, recipientDeviceID string) (client.AckEnvelopeResponse, error) {
		ackCalled = true
		return client.AckEnvelopeResponse{}, nil
	}

	runOpenMLSMessageOpenForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, messageArtifactPath string) (openMLSMessageOpenResult, error) {
		return openMLSMessageOpenResult{}, errors.New("message-open failed")
	}

	err := Run([]string{
		"openmls-inbox-dev",
		"--state", statePath,
		"--sidecar-device-label", "carbonstack-bob-device",
		"--conversation", "carbonstack-test-conversation",
		"--ack",
	})

	if err != nil {
		t.Fatalf("openmls-inbox-dev should report failed open without failing command: %v", err)
	}
	if ackCalled {
		t.Fatal("ack should not be called when message-open fails")
	}
}

func TestOpenMLSInboxDevAcksOnlyAfterMessageOpenSuccess(t *testing.T) {
	statePath := writeReadyState(t)

	restore := stubInboxDevHooks(t)
	defer restore()

	inboxForCommand = oneOpenMLSInboxResponse

	openCalled := false
	runOpenMLSMessageOpenForCommand = func(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, messageArtifactPath string) (openMLSMessageOpenResult, error) {
		openCalled = true

		if deviceLabel != "carbonstack-bob-device" {
			t.Fatalf("deviceLabel = %q", deviceLabel)
		}
		if conversationLabel != "carbonstack-test-conversation" {
			t.Fatalf("conversationLabel = %q", conversationLabel)
		}
		if messageLabel != "message-0007" {
			t.Fatalf("messageLabel = %q", messageLabel)
		}
		if messageArtifactPath == "" {
			t.Fatal("messageArtifactPath should be set")
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

	ackCalled := false
	ackEnvelopeForCommand = func(c client.CypherClient, envelopeID string, recipientDeviceID string) (client.AckEnvelopeResponse, error) {
		if !openCalled {
			t.Fatal("ack called before message-open")
		}
		ackCalled = true

		if envelopeID != "env-openmls-1" {
			t.Fatalf("envelopeID = %q", envelopeID)
		}
		if recipientDeviceID != "sender-device" {
			t.Fatalf("recipientDeviceID = %q", recipientDeviceID)
		}

		return client.AckEnvelopeResponse{
			EnvelopeID:     envelopeID,
			DeliveryState:  "acknowledged",
			AcknowledgedAt: "2026-06-05T00:00:00Z",
		}, nil
	}

	err := Run([]string{
		"openmls-inbox-dev",
		"--state", statePath,
		"--sidecar-device-label", "carbonstack-bob-device",
		"--conversation", "carbonstack-test-conversation",
		"--message-label", "message-0007",
		"--ack",
	})

	if err != nil {
		t.Fatalf("openmls-inbox-dev: %v", err)
	}
	if !openCalled {
		t.Fatal("message-open should be called")
	}
	if !ackCalled {
		t.Fatal("ack should be called after message-open succeeds")
	}
}

func stubInboxDevHooks(t *testing.T) func() {
	t.Helper()

	oldInbox := inboxForCommand
	oldAck := ackEnvelopeForCommand
	oldRelaySpaceInbox := relaySpaceOpenMLSArtifactInboxForMessageCommand
	oldRelaySpaceAck := ackRelaySpaceEnvelopeForMessageCommand
	oldWrite := writeOpenMLSArtifactFromEnvelopeForCommand
	oldOpen := runOpenMLSMessageOpenForCommand

	writeOpenMLSArtifactFromEnvelopeForCommand = func(outputPath string, envelope client.EnvelopeRecord) error {
		if outputPath == "" {
			t.Fatal("outputPath should be set")
		}
		return nil
	}

	return func() {
		inboxForCommand = oldInbox
		ackEnvelopeForCommand = oldAck
		relaySpaceOpenMLSArtifactInboxForMessageCommand = oldRelaySpaceInbox
		ackRelaySpaceEnvelopeForMessageCommand = oldRelaySpaceAck
		writeOpenMLSArtifactFromEnvelopeForCommand = oldWrite
		runOpenMLSMessageOpenForCommand = oldOpen
	}
}

func oneOpenMLSInboxResponse(c client.CypherClient, deviceID string) (client.InboxResponse, error) {
	return client.InboxResponse{
		DeviceID: deviceID,
		Envelopes: []client.EnvelopeRecord{
			{
				EnvelopeID:        "env-openmls-1",
				SenderDeviceID:    "alice-device",
				RecipientDeviceID: deviceID,
				ContentType:       relay.ContentTypeOpenMLSApplicationMessage,
				ProtocolVersion:   relay.ProtocolVersionOpenMLSSidecar,
				CiphertextB64:     relay.EncodePayloadBase64([]byte("protected OpenMLS bytes")),
				PayloadSizeBytes:  int64(len("protected OpenMLS bytes")),
			},
		},
	}, nil
}
