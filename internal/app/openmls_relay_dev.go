package app

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

var submitRelaySpaceKeyPackageEnvelopeForCommand = relay.SubmitRelaySpaceKeyPackageEnvelope
var submitRelaySpaceWelcomeEnvelopeForCommand = relay.SubmitRelaySpaceWelcomeEnvelope
var relaySpaceOpenMLSArtifactInboxForCommand = relay.RelaySpaceOpenMLSArtifactInbox
var writeRelaySpaceKeyPackageFromEnvelopeForCommand = relay.WriteRelaySpaceKeyPackageFromEnvelope
var writeRelaySpaceWelcomeFromEnvelopeForCommand = relay.WriteRelaySpaceWelcomeFromEnvelope
var ackRelaySpaceEnvelopeForCommand = func(c client.CypherClient, relaySpaceID string, envelopeID string, recipientDeviceID string) (client.AckRelaySpaceEnvelopeResponse, error) {
	return c.AckRelaySpaceEnvelope(relaySpaceID, envelopeID, recipientDeviceID)
}

func cmdOpenMLSRelayKeyPackageSubmitDev(args []string) error {
	fs := flag.NewFlagSet("openmls-relay-keypackage-submit-dev", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID")
	toDevice := fs.String("to-device", "", "recipient Cypher device ID")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	clientCreatedAt := fs.String("client-created-at", "", "client-created-at override; defaults to current UTC time")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*relaySpaceID) == "" || strings.TrimSpace(*toDevice) == "" || strings.TrimSpace(*sidecarDeviceLabel) == "" {
		return errors.New("--relay-space, --to-device, and --sidecar-device-label are required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"public-bundle-export",
		"--device-label", *sidecarDeviceLabel,
		"--write-artifact",
	)
	if err != nil {
		return err
	}

	keyPackageHint := bootstrapStringField(envelope.Data, "key_package_artifact_path_hint")
	keyPackagePath := bootstrapPathFromHint(*sidecarDir, keyPackageHint)
	if keyPackagePath == "" {
		return errors.New("OpenMLS sidecar public-bundle-export did not return key_package_artifact_path_hint")
	}

	c := client.New(s.ServerURL)
	resp, err := submitRelaySpaceKeyPackageEnvelopeForCommand(
		c,
		*relaySpaceID,
		s.DeviceID,
		*toDevice,
		keyPackagePath,
		*clientCreatedAt,
	)
	if err != nil {
		return err
	}

	deviceLabel := bootstrapStringField(envelope.Data, "device_label")
	if deviceLabel == "" {
		deviceLabel = *sidecarDeviceLabel
	}

	fmt.Println("openmls relay keypackage submit dev")
	fmt.Println("command: openmls-relay-keypackage-submit-dev")
	fmt.Println("status: sent")
	fmt.Printf("relay_space_id: %s\n", *relaySpaceID)
	fmt.Printf("sender_device_id: %s\n", s.DeviceID)
	fmt.Printf("recipient_device_id: %s\n", *toDevice)
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	fmt.Printf("sidecar_device_label: %s\n", deviceLabel)
	fmt.Printf("key_package_artifact_path: %s\n", keyPackagePath)
	fmt.Printf("content_type: %s\n", relay.ContentTypeOpenMLSKeyPackage)
	fmt.Printf("protocol_version: %s\n", relay.ProtocolVersionOpenMLSSidecar)
	fmt.Printf("envelope_id: %s\n", resp.EnvelopeID)
	fmt.Printf("delivery_state: %s\n", resp.DeliveryState)
	fmt.Printf("server_received_at: %s\n", resp.ServerReceivedAt)
	fmt.Printf("payload_sha256: %s\n", resp.PayloadSHA256)
	fmt.Printf("payload_size_bytes: %d\n", resp.PayloadSizeBytes)
	fmt.Println("warning: dev/pre-alpha Relay Space KeyPackage transport; not join automation or identity verification")
	return nil
}

func cmdOpenMLSRelayKeyPackageInboxDev(args []string) error {
	fs := flag.NewFlagSet("openmls-relay-keypackage-inbox-dev", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID")
	limit := fs.Int("limit", 1, "maximum KeyPackage envelopes to write")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*relaySpaceID) == "" {
		return errors.New("--relay-space is required")
	}
	if *limit < 1 {
		return errors.New("--limit must be >= 1")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	c := client.New(s.ServerURL)
	envelopes, err := relaySpaceOpenMLSArtifactInboxForCommand(c, *relaySpaceID, s.DeviceID, relay.ArtifactKindKeyPackage)
	if err != nil {
		return err
	}

	fmt.Println("openmls relay keypackage inbox dev")
	fmt.Println("command: openmls-relay-keypackage-inbox-dev")
	fmt.Printf("relay_space_id: %s\n", *relaySpaceID)
	fmt.Printf("device_id: %s\n", s.DeviceID)
	fmt.Printf("queued_keypackage_envelopes: %d\n", len(envelopes))
	fmt.Printf("limit: %d\n", *limit)
	fmt.Println("ack_requested: false")
	fmt.Println("warning: dev/pre-alpha Relay Space KeyPackage inbox; no add-member, ack, trust mutation, or verification")

	written := 0
	writeFailures := 0

	for i, envelope := range envelopes {
		if written >= *limit {
			break
		}

		artifactPath, err := writeRelayKeyPackageInboxDevArtifact(envelope, i)
		if err != nil {
			writeFailures++
			fmt.Println()
			fmt.Println("relay_keypackage_write_failed")
			fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
			fmt.Printf("error: %v\n", err)
			continue
		}

		written++
		fmt.Println()
		fmt.Println("relay_keypackage_written")
		fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
		fmt.Printf("from_device: %s\n", envelope.SenderDeviceID)
		fmt.Printf("artifact_path: %s\n", artifactPath)
		fmt.Printf("content_type: %s\n", envelope.ContentType)
		fmt.Printf("protocol_version: %s\n", envelope.ProtocolVersion)
		fmt.Println("acked: false")
	}

	fmt.Println()
	fmt.Println("openmls relay keypackage inbox summary")
	fmt.Printf("written_artifacts: %d\n", written)
	fmt.Printf("write_failures: %d\n", writeFailures)
	return nil
}

func cmdOpenMLSRelayWelcomeSubmitDev(args []string) error {
	fs := flag.NewFlagSet("openmls-relay-welcome-submit-dev", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID")
	toDevice := fs.String("to-device", "", "recipient Cypher device ID")
	welcome := fs.String("welcome", "", "OpenMLS Welcome artifact path")
	clientCreatedAt := fs.String("client-created-at", "", "client-created-at override; defaults to current UTC time")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*relaySpaceID) == "" || strings.TrimSpace(*toDevice) == "" || strings.TrimSpace(*welcome) == "" {
		return errors.New("--relay-space, --to-device, and --welcome are required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	welcomeAbs, err := filepath.Abs(*welcome)
	if err != nil {
		return fmt.Errorf("resolve --welcome: %w", err)
	}

	c := client.New(s.ServerURL)
	resp, err := submitRelaySpaceWelcomeEnvelopeForCommand(
		c,
		*relaySpaceID,
		s.DeviceID,
		*toDevice,
		welcomeAbs,
		*clientCreatedAt,
	)
	if err != nil {
		return err
	}

	fmt.Println("openmls relay welcome submit dev")
	fmt.Println("command: openmls-relay-welcome-submit-dev")
	fmt.Println("status: sent")
	fmt.Printf("relay_space_id: %s\n", *relaySpaceID)
	fmt.Printf("sender_device_id: %s\n", s.DeviceID)
	fmt.Printf("recipient_device_id: %s\n", *toDevice)
	fmt.Printf("welcome_artifact_path: %s\n", welcomeAbs)
	fmt.Printf("content_type: %s\n", relay.ContentTypeOpenMLSWelcome)
	fmt.Printf("protocol_version: %s\n", relay.ProtocolVersionOpenMLSSidecar)
	fmt.Printf("envelope_id: %s\n", resp.EnvelopeID)
	fmt.Printf("delivery_state: %s\n", resp.DeliveryState)
	fmt.Printf("server_received_at: %s\n", resp.ServerReceivedAt)
	fmt.Printf("payload_sha256: %s\n", resp.PayloadSHA256)
	fmt.Printf("payload_size_bytes: %d\n", resp.PayloadSizeBytes)
	fmt.Println("warning: dev/pre-alpha Relay Space Welcome transport; not join automation or identity verification")
	return nil
}

func cmdOpenMLSRelayWelcomeInboxDev(args []string) error {
	fs := flag.NewFlagSet("openmls-relay-welcome-inbox-dev", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID")
	limit := fs.Int("limit", 1, "maximum Welcome envelopes to write")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*relaySpaceID) == "" {
		return errors.New("--relay-space is required")
	}
	if *limit < 1 {
		return errors.New("--limit must be >= 1")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	c := client.New(s.ServerURL)
	envelopes, err := relaySpaceOpenMLSArtifactInboxForCommand(c, *relaySpaceID, s.DeviceID, relay.ArtifactKindWelcome)
	if err != nil {
		return err
	}

	fmt.Println("openmls relay welcome inbox dev")
	fmt.Println("command: openmls-relay-welcome-inbox-dev")
	fmt.Printf("relay_space_id: %s\n", *relaySpaceID)
	fmt.Printf("device_id: %s\n", s.DeviceID)
	fmt.Printf("queued_welcome_envelopes: %d\n", len(envelopes))
	fmt.Printf("limit: %d\n", *limit)
	fmt.Println("ack_requested: false")
	fmt.Println("warning: dev/pre-alpha Relay Space Welcome inbox; no conversation-join, ack, trust mutation, or verification")

	written := 0
	writeFailures := 0

	for i, envelope := range envelopes {
		if written >= *limit {
			break
		}

		artifactPath, err := writeRelayWelcomeInboxDevArtifact(envelope, i)
		if err != nil {
			writeFailures++
			fmt.Println()
			fmt.Println("relay_welcome_write_failed")
			fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
			fmt.Printf("error: %v\n", err)
			continue
		}

		written++
		fmt.Println()
		fmt.Println("relay_welcome_written")
		fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
		fmt.Printf("from_device: %s\n", envelope.SenderDeviceID)
		fmt.Printf("artifact_path: %s\n", artifactPath)
		fmt.Printf("content_type: %s\n", envelope.ContentType)
		fmt.Printf("protocol_version: %s\n", envelope.ProtocolVersion)
		fmt.Println("acked: false")
	}

	fmt.Println()
	fmt.Println("openmls relay welcome inbox summary")
	fmt.Printf("written_artifacts: %d\n", written)
	fmt.Printf("write_failures: %d\n", writeFailures)
	return nil
}

func cmdOpenMLSRelayAddMemberDev(args []string) error {
	fs := flag.NewFlagSet("openmls-relay-add-member-dev", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS sidecar conversation label")
	welcomeToDevice := fs.String("welcome-to-device", "", "recipient Cypher device ID for the produced Welcome; defaults to KeyPackage envelope sender_device_id")
	clientCreatedAt := fs.String("client-created-at", "", "client-created-at override for Welcome submit; defaults to current UTC time")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*relaySpaceID) == "" || strings.TrimSpace(*sidecarDeviceLabel) == "" || strings.TrimSpace(*conversationLabel) == "" {
		return errors.New("--relay-space, --sidecar-device-label, and --conversation are required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	c := client.New(s.ServerURL)
	envelopes, err := relaySpaceOpenMLSArtifactInboxForCommand(c, *relaySpaceID, s.DeviceID, relay.ArtifactKindKeyPackage)
	if err != nil {
		return err
	}
	if len(envelopes) == 0 {
		return errors.New("no Relay Space KeyPackage envelopes available for add-member")
	}

	keyPackageEnvelope := envelopes[0]
	keyPackagePath, err := writeRelayKeyPackageInboxDevArtifact(keyPackageEnvelope, 0)
	if err != nil {
		return fmt.Errorf("write Relay Space KeyPackage artifact: %w", err)
	}

	welcomeRecipientDeviceID := strings.TrimSpace(*welcomeToDevice)
	if welcomeRecipientDeviceID == "" {
		welcomeRecipientDeviceID = strings.TrimSpace(keyPackageEnvelope.SenderDeviceID)
	}
	if welcomeRecipientDeviceID == "" {
		return errors.New("Welcome recipient device is required; pass --welcome-to-device or use a KeyPackage envelope with sender_device_id")
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"conversation-add-member",
		"--device-label", *sidecarDeviceLabel,
		"--conversation-label", *conversationLabel,
		"--member-keypackage", keyPackagePath,
	)
	if err != nil {
		return err
	}

	welcomeHint := bootstrapStringField(envelope.Data, "welcome_artifact_path_hint")
	welcomePath := bootstrapPathFromHint(*sidecarDir, welcomeHint)
	if welcomePath == "" {
		return errors.New("OpenMLS sidecar conversation-add-member did not return welcome_artifact_path_hint")
	}

	welcomeResp, err := submitRelaySpaceWelcomeEnvelopeForCommand(
		c,
		*relaySpaceID,
		s.DeviceID,
		welcomeRecipientDeviceID,
		welcomePath,
		*clientCreatedAt,
	)
	if err != nil {
		return err
	}

	deviceLabel := bootstrapStringField(envelope.Data, "device_label")
	if deviceLabel == "" {
		deviceLabel = *sidecarDeviceLabel
	}
	conversation := bootstrapStringField(envelope.Data, "conversation_label")
	if conversation == "" {
		conversation = *conversationLabel
	}

	fmt.Println("openmls relay add-member dev")
	fmt.Println("command: openmls-relay-add-member-dev")
	fmt.Println("status: welcome_created_and_sent")
	fmt.Printf("relay_space_id: %s\n", *relaySpaceID)
	fmt.Printf("local_device_id: %s\n", s.DeviceID)
	fmt.Printf("keypackage_envelope_id: %s\n", keyPackageEnvelope.EnvelopeID)
	fmt.Printf("keypackage_from_device: %s\n", keyPackageEnvelope.SenderDeviceID)
	fmt.Printf("keypackage_artifact_path: %s\n", keyPackagePath)
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	fmt.Printf("sidecar_device_label: %s\n", deviceLabel)
	fmt.Printf("sidecar_conversation_label: %s\n", conversation)
	fmt.Printf("welcome_recipient_device_id: %s\n", welcomeRecipientDeviceID)
	fmt.Printf("welcome_artifact_path: %s\n", welcomePath)
	fmt.Printf("welcome_envelope_id: %s\n", welcomeResp.EnvelopeID)
	fmt.Printf("welcome_delivery_state: %s\n", welcomeResp.DeliveryState)
	fmt.Printf("welcome_server_received_at: %s\n", welcomeResp.ServerReceivedAt)
	fmt.Printf("welcome_payload_sha256: %s\n", welcomeResp.PayloadSHA256)
	fmt.Printf("welcome_payload_size_bytes: %d\n", welcomeResp.PayloadSizeBytes)
	fmt.Println("keypackage_acked: false")
	fmt.Println("welcome_acked: false")
	bootstrapPrintOptionalBool("member_added", envelope.Data)
	bootstrapPrintOptionalBool("welcome_artifact_written", envelope.Data)
	bootstrapPrintOptionalBool("group_reloadable", envelope.Data)
	bootstrapPrintOptionalNumber("member_count_before", envelope.Data)
	bootstrapPrintOptionalNumber("member_count_after", envelope.Data)
	bootstrapPrintOptionalString("epoch_before", envelope.Data)
	bootstrapPrintOptionalString("epoch_after", envelope.Data)
	fmt.Println("warning: dev/pre-alpha Relay Space add-member scaffold; not join automation, identity verification, local-backbone, or production UX")
	return nil
}

func cmdOpenMLSRelayJoinDev(args []string) error {
	fs := flag.NewFlagSet("openmls-relay-join-dev", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS sidecar conversation label")
	ackAfterJoin := fs.Bool("ack-after-join", false, "ack the Relay Space Welcome envelope only after sidecar conversation-join succeeds")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*relaySpaceID) == "" || strings.TrimSpace(*sidecarDeviceLabel) == "" || strings.TrimSpace(*conversationLabel) == "" {
		return errors.New("--relay-space, --sidecar-device-label, and --conversation are required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	c := client.New(s.ServerURL)
	envelopes, err := relaySpaceOpenMLSArtifactInboxForCommand(c, *relaySpaceID, s.DeviceID, relay.ArtifactKindWelcome)
	if err != nil {
		return err
	}
	if len(envelopes) == 0 {
		return errors.New("no Relay Space Welcome envelopes available for join")
	}

	welcomeEnvelope := envelopes[0]
	welcomePath, err := writeRelayWelcomeInboxDevArtifact(welcomeEnvelope, 0)
	if err != nil {
		return fmt.Errorf("write Relay Space Welcome artifact: %w", err)
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"conversation-join",
		"--device-label", *sidecarDeviceLabel,
		"--conversation-label", *conversationLabel,
		"--welcome", welcomePath,
	)
	if err != nil {
		return err
	}

	var ackResp client.AckRelaySpaceEnvelopeResponse
	if *ackAfterJoin {
		ackResp, err = ackRelaySpaceEnvelopeForCommand(c, *relaySpaceID, welcomeEnvelope.EnvelopeID, s.DeviceID)
		if err != nil {
			return fmt.Errorf("ack Relay Space Welcome after join: %w", err)
		}
	}

	deviceLabel := bootstrapStringField(envelope.Data, "device_label")
	if deviceLabel == "" {
		deviceLabel = *sidecarDeviceLabel
	}
	conversation := bootstrapStringField(envelope.Data, "conversation_label")
	if conversation == "" {
		conversation = *conversationLabel
	}

	fmt.Println("openmls relay join dev")
	fmt.Println("command: openmls-relay-join-dev")
	fmt.Println("status: joined")
	fmt.Printf("relay_space_id: %s\n", *relaySpaceID)
	fmt.Printf("local_device_id: %s\n", s.DeviceID)
	fmt.Printf("welcome_envelope_id: %s\n", welcomeEnvelope.EnvelopeID)
	fmt.Printf("welcome_from_device: %s\n", welcomeEnvelope.SenderDeviceID)
	fmt.Printf("welcome_artifact_path: %s\n", welcomePath)
	fmt.Printf("sidecar_command: %s\n", envelope.Command)
	fmt.Printf("sidecar_device_label: %s\n", deviceLabel)
	fmt.Printf("sidecar_conversation_label: %s\n", conversation)
	fmt.Printf("ack_requested: %t\n", *ackAfterJoin)
	fmt.Printf("welcome_acked: %t\n", *ackAfterJoin)
	if *ackAfterJoin {
		fmt.Printf("ack_envelope_id: %s\n", ackResp.EnvelopeID)
		fmt.Printf("ack_delivery_state: %s\n", ackResp.DeliveryState)
		fmt.Printf("acknowledged_at: %s\n", ackResp.AcknowledgedAt)
	}
	bootstrapPrintOptionalString("welcome_artifact_path_hint", envelope.Data)
	bootstrapPrintOptionalBool("joined", envelope.Data)
	bootstrapPrintOptionalBool("group_reloadable", envelope.Data)
	bootstrapPrintOptionalNumber("member_count", envelope.Data)
	bootstrapPrintOptionalString("epoch", envelope.Data)
	bootstrapPrintOptionalString("join_summary_path_hint", envelope.Data)
	bootstrapPrintOptionalString("conversation_state_path_hint", envelope.Data)
	bootstrapPrintOptionalString("conversation_summary_path_hint", envelope.Data)
	bootstrapPrintOptionalString("provider_storage_path_hint", envelope.Data)
	fmt.Println("warning: dev/pre-alpha Relay Space join scaffold; not identity verification, local-backbone, or production UX")
	return nil
}

func writeRelayKeyPackageInboxDevArtifact(envelope client.RelaySpaceEnvelopeRecord, index int) (string, error) {
	root, err := os.MkdirTemp("", "carbonstack-openmls-relay-keypackage-dev-")
	if err != nil {
		return "", err
	}

	path := filepath.Join(root, "envelope-"+strconv.Itoa(index+1), "public-bundle.keypackage.bin")
	if err := writeRelaySpaceKeyPackageFromEnvelopeForCommand(path, envelope); err != nil {
		return "", err
	}

	return path, nil
}

func writeRelayWelcomeInboxDevArtifact(envelope client.RelaySpaceEnvelopeRecord, index int) (string, error) {
	root, err := os.MkdirTemp("", "carbonstack-openmls-relay-welcome-dev-")
	if err != nil {
		return "", err
	}

	path := filepath.Join(root, "envelope-"+strconv.Itoa(index+1), "welcome.bin")
	if err := writeRelaySpaceWelcomeFromEnvelopeForCommand(path, envelope); err != nil {
		return "", err
	}

	return path, nil
}
