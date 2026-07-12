package app

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/trust"
)

var submitRelaySpaceOpenMLSArtifactEnvelopeForMessageCommand = relay.SubmitRelaySpaceOpenMLSArtifactEnvelope
var relaySpaceOpenMLSArtifactInboxForMessageCommand = relay.RelaySpaceOpenMLSArtifactInbox
var ackRelaySpaceEnvelopeForMessageCommand = func(
	c client.CypherClient,
	relaySpaceID string,
	envelopeID string,
	recipientDeviceID string,
) (client.AckRelaySpaceEnvelopeResponse, error) {
	return c.AckRelaySpaceEnvelope(
		relaySpaceID,
		envelopeID,
		recipientDeviceID,
	)
}

func relaySpaceEnvelopeAsUnscopedRecord(
	envelope client.RelaySpaceEnvelopeRecord,
) client.EnvelopeRecord {
	return client.EnvelopeRecord{
		EnvelopeID:        envelope.EnvelopeID,
		SenderDeviceID:    envelope.SenderDeviceID,
		RecipientDeviceID: envelope.RecipientDeviceID,
		ContentType:       envelope.ContentType,
		ProtocolVersion:   envelope.ProtocolVersion,
		CiphertextB64:     envelope.CiphertextB64,
		PayloadSHA256:     envelope.PayloadSHA256,
		PayloadSizeBytes:  envelope.PayloadSizeBytes,
		ClientCreatedAt:   envelope.ClientCreatedAt,
		ServerReceivedAt:  envelope.ServerReceivedAt,
		DeliveryState:     envelope.DeliveryState,
	}
}

func cmdMessageSendDev(args []string) error {
	fs := flag.NewFlagSet("message-send-dev", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID")
	toDevice := fs.String("to-device", "", "recipient Cypher device ID")
	message := fs.String("message", "", "plaintext message text")
	strict := fs.Bool("strict", false, "block sending to unknown, unverified, or changed devices")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "sender OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS sidecar conversation label")
	messageLabel := fs.String("message-label", "", "OpenMLS sidecar message label; sidecar default is used when omitted")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*relaySpaceID) == "" || *toDevice == "" || *message == "" || *sidecarDeviceLabel == "" || *conversationLabel == "" {
		return errors.New("--relay-space, --to-device, --message, --sidecar-device-label, and --conversation are required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	commandPaths, err := resolveCommandStatePaths(*statePath)
	if err != nil {
		return err
	}
	decision, err := trust.EvaluateSend(commandPaths.TrustPaths, *toDevice, *strict)
	if err != nil {
		return err
	}

	if decision.Warning != "" {
		fmt.Printf("warning: %s\n", decision.Warning)
	}
	if !*strict {
		fmt.Println("warning: message-send-dev is running in dev trust mode; use --strict to block unknown or unverified recipients")
	}

	if !decision.Allowed {
		return fmt.Errorf("message-send-dev blocked by trust policy: recipient trust_state=%s", decision.TrustState)
	}

	protect, err := runOpenMLSMessageProtectForCommand(*sidecarDir, *sidecarDeviceLabel, *conversationLabel, *messageLabel, *message)
	if err != nil {
		return err
	}

	artifactPath := protect.MessageArtifactPathHint
	if artifactPath == "" {
		return errors.New("OpenMLS sidecar message-protect did not return message_artifact_path_hint")
	}
	if !filepath.IsAbs(artifactPath) {
		artifactPath = filepath.Join(*sidecarDir, artifactPath)
	}

	c := client.New(s.ServerURL)
	resp, err := submitRelaySpaceOpenMLSArtifactEnvelopeForMessageCommand(
		c,
		*relaySpaceID,
		s.DeviceID,
		*toDevice,
		relay.ArtifactKindApplicationMessage,
		artifactPath,
		relay.DefaultClientCreatedAt(),
	)
	if err != nil {
		return err
	}

	fmt.Println("message sent")
	fmt.Println("command: message-send-dev")
	fmt.Println("implementation_path: openmls-send-dev")
	fmt.Println("backend: OpenMLS sidecar + Cypher Relay Space-scoped application-message envelope")
	fmt.Printf("status: sent\n")
	fmt.Printf("relay_space_id: %s\n", *relaySpaceID)
	fmt.Printf("recipient_device_id: %s\n", *toDevice)
	fmt.Printf("conversation: %s\n", protect.ConversationLabel)
	fmt.Printf("message_label: %s\n", protect.MessageLabel)
	fmt.Printf("envelope_id: %s\n", resp.EnvelopeID)
	fmt.Printf("delivery_state: %s\n", resp.DeliveryState)
	fmt.Printf("payload_sha256: %s\n", resp.PayloadSHA256)
	fmt.Printf("payload_size_bytes: %d\n", resp.PayloadSizeBytes)
	fmt.Println("warning: dev/pre-alpha OpenMLS message wrapper; not production messaging UX")
	return nil
}

func cmdMessageInboxDev(args []string) error {
	fs := flag.NewFlagSet("message-inbox-dev", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "recipient OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS sidecar conversation label")
	messageLabel := fs.String("message-label", "", "OpenMLS sidecar message label; generated per envelope when omitted")
	limit := fs.Int("limit", 1, "maximum OpenMLS application-message envelopes to open")
	ack := fs.Bool("ack", false, "ack each envelope only after sidecar message-open succeeds")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*relaySpaceID) == "" || *sidecarDeviceLabel == "" || *conversationLabel == "" {
		return errors.New("--relay-space, --sidecar-device-label, and --conversation are required")
	}
	if *limit < 1 {
		return errors.New("--limit must be >= 1")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	c := client.New(s.ServerURL)
	envelopes, err := relaySpaceOpenMLSArtifactInboxForMessageCommand(
		c,
		*relaySpaceID,
		s.DeviceID,
		relay.ArtifactKindApplicationMessage,
	)
	if err != nil {
		return err
	}

	fmt.Println("message inbox")
	fmt.Println("command: message-inbox-dev")
	fmt.Println("implementation_path: openmls-inbox-dev")
	fmt.Println("backend: OpenMLS sidecar + Cypher Relay Space-scoped application-message envelope")
	fmt.Printf("relay_space_id: %s\n", *relaySpaceID)
	fmt.Printf("device_id: %s\n", s.DeviceID)
	fmt.Printf("queued_envelopes: %d\n", len(envelopes))
	fmt.Printf("limit: %d\n", *limit)
	fmt.Printf("ack_requested: %t\n", *ack)
	fmt.Println("warning: dev/pre-alpha OpenMLS message wrapper; not production messaging UX")

	opened := 0
	unsupported := 0
	openFailures := 0
	ackFailures := 0

	for i, envelope := range envelopes {
		if opened >= *limit {
			break
		}

		if envelope.ContentType != relay.ContentTypeOpenMLSApplicationMessage || envelope.ProtocolVersion != relay.ProtocolVersionOpenMLSSidecar {
			unsupported++
			fmt.Println()
			fmt.Println("message skipped")
			fmt.Printf("reason: unsupported_envelope\n")
			fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
			continue
		}

		label := strings.TrimSpace(*messageLabel)
		if label == "" {
			label = "inbox-" + strconv.Itoa(opened+1)
		}

		artifactPath, err := writeOpenMLSInboxDevArtifact(
			relaySpaceEnvelopeAsUnscopedRecord(envelope),
			i,
		)
		if err != nil {
			openFailures++
			fmt.Println()
			fmt.Println("message open failed")
			fmt.Printf("stage: artifact_write\n")
			fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
			fmt.Printf("error: %v\n", err)
			fmt.Println("acked: false")
			continue
		}

		openedResult, err := runOpenMLSMessageOpenForCommand(*sidecarDir, *sidecarDeviceLabel, *conversationLabel, label, artifactPath)
		if err != nil {
			openFailures++
			fmt.Println()
			fmt.Println("message open failed")
			fmt.Printf("stage: message_open\n")
			fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
			fmt.Printf("error: %v\n", err)
			fmt.Println("acked: false")
			continue
		}

		opened++
		acked := false

		fmt.Println()
		fmt.Println("message opened")
		fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)

		if *ack {
			ackResp, err := ackRelaySpaceEnvelopeForMessageCommand(
				c,
				*relaySpaceID,
				envelope.EnvelopeID,
				s.DeviceID,
			)
			if err != nil {
				ackFailures++
				fmt.Printf("ack_error: %v\n", err)
			} else {
				acked = true
				fmt.Printf("ack_delivery_state: %s\n", ackResp.DeliveryState)
				fmt.Printf("acknowledged_at: %s\n", ackResp.AcknowledgedAt)
			}
		}

		fmt.Printf("from_device: %s\n", envelope.SenderDeviceID)
		fmt.Printf("from_device_unverified: %s\n", envelope.SenderDeviceID)
		fmt.Println("sender_identity_verified: false")
		fmt.Println("warning: from_device is relay envelope metadata, not verified identity")
		fmt.Printf("conversation: %s\n", openedResult.ConversationLabel)
		fmt.Printf("message_label: %s\n", openedResult.MessageLabel)
		fmt.Printf("plaintext_utf8: %s\n", openedResult.PlaintextUTF8)
		fmt.Printf("acked: %t\n", acked)
	}

	fmt.Println()
	fmt.Println("message inbox summary")
	fmt.Printf("opened_envelopes: %d\n", opened)
	fmt.Printf("unsupported_envelopes: %d\n", unsupported)
	fmt.Printf("open_failures: %d\n", openFailures)
	fmt.Printf("ack_failures: %d\n", ackFailures)
	return nil
}
