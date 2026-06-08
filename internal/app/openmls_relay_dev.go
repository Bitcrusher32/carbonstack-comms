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
