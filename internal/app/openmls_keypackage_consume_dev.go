package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

const keyPackageConsumeReceiptSchema = "carbonstack-keypackage-consume-receipt/v0"

type keyPackageConsumeReceipt struct {
	SchemaVersion                string `json:"schema_version"`
	Command                      string `json:"command"`
	ConsumeClassification        string `json:"consume_classification"`
	EnvelopeID                   string `json:"envelope_id"`
	RelaySpaceID                 string `json:"relay_space_id"`
	SenderDeviceID               string `json:"sender_device_id"`
	RecipientDeviceID            string `json:"recipient_device_id"`
	ContentType                  string `json:"content_type"`
	ProtocolVersion              string `json:"protocol_version"`
	DeliveryStateBeforeAck       string `json:"delivery_state_before_ack"`
	PayloadSHA256                string `json:"payload_sha256"`
	PayloadSizeBytes             int64  `json:"payload_size_bytes"`
	ArtifactSHA256               string `json:"artifact_sha256"`
	ArtifactSizeBytes            int64  `json:"artifact_size_bytes"`
	ExpectedKeyPackageRef        string `json:"expected_key_package_ref,omitempty"`
	KeyPackageRefVerified        bool   `json:"key_package_ref_verified"`
	ArtifactPath                 string `json:"artifact_path"`
	ReceiptManifestPath          string `json:"receipt_manifest_path"`
	ConsumedAt                   string `json:"consumed_at"`
	AckedAt                      string `json:"acked_at,omitempty"`
	AckDeliveryState             string `json:"ack_delivery_state,omitempty"`
	LocalReceiptPersisted        bool   `json:"local_receipt_persisted"`
	KeyPackageAcked              bool   `json:"keypackage_acked"`
	AddMemberRun                 bool   `json:"add_member_run"`
	WelcomeSubmitted             bool   `json:"welcome_submitted"`
	TrustOrCandidateStateMutated bool   `json:"trust_or_candidate_state_mutated"`
	PublicDirectoryMutated       bool   `json:"public_directory_mutated"`
}

type keyPackageConsumeLock struct {
	path string
}

func (l keyPackageConsumeLock) release() {
	if l.path != "" {
		_ = os.Remove(l.path)
	}
}

func cmdOpenMLSRelayKeyPackageConsumeDev(args []string) error {
	fs := flag.NewFlagSet("openmls-relay-keypackage-consume-dev", flag.ContinueOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID")
	envelopeID := fs.String("envelope-id", "", "Relay Space KeyPackage envelope ID")
	receiptRoot := fs.String("receipt-root", "", "local receipt root; defaults beside the Comms state file")
	expectedPayloadSHA256 := fs.String("expected-payload-sha256", "", "optional expected decoded payload SHA-256 hex")
	expectedKeyPackageRef := fs.String("expected-key-package-ref", "", "optional expected KeyPackage ref recorded as operator expectation; not cryptographically verified by this command")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*relaySpaceID) == "" {
		return errors.New("--relay-space is required")
	}
	if strings.TrimSpace(*envelopeID) == "" {
		return errors.New("--envelope-id is required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	root := strings.TrimSpace(*receiptRoot)
	if root == "" {
		root = defaultKeyPackageConsumeReceiptRoot(*statePath)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create KeyPackage receipt root: %w", err)
	}

	lock, err := acquireKeyPackageConsumeLock(root)
	if err != nil {
		return err
	}
	defer lock.release()

	manifestPath := keyPackageConsumeReceiptManifestPath(root, *envelopeID)
	artifactPath := keyPackageConsumeReceiptArtifactPath(root, *envelopeID)

	if _, err := os.Stat(artifactPath); err == nil {
		if _, manifestErr := os.Stat(manifestPath); manifestErr != nil {
			return fmt.Errorf("incomplete_local_consume: artifact exists without receipt manifest for envelope %s", *envelopeID)
		}
	}

	c := client.New(s.ServerURL)

	if receipt, ok, err := loadKeyPackageConsumeReceipt(manifestPath); err != nil {
		return err
	} else if ok {
		if err := validateExistingKeyPackageConsumeReceipt(receipt, *relaySpaceID, *envelopeID, s.DeviceID, *expectedPayloadSHA256, *expectedKeyPackageRef); err != nil {
			return err
		}
		if receipt.AckedAt == "" || !receipt.KeyPackageAcked {
			ackResp, err := c.AckRelaySpaceEnvelope(*relaySpaceID, *envelopeID, s.DeviceID)
			if err != nil {
				return fmt.Errorf("retry ACK for persisted KeyPackage receipt: %w", err)
			}
			receipt.ConsumeClassification = "ack_retried_after_persisted_receipt"
			receipt.AckedAt = ackResp.AcknowledgedAt
			receipt.AckDeliveryState = ackResp.DeliveryState
			receipt.KeyPackageAcked = ackResp.DeliveryState == "acknowledged"
			if err := writeKeyPackageConsumeReceiptAtomic(manifestPath, receipt); err != nil {
				return err
			}
		} else {
			receipt.ConsumeClassification = "already_consumed"
		}
		printKeyPackageConsumeReceipt(receipt)
		return nil
	}

	envelopes, err := relay.RelaySpaceOpenMLSArtifactInbox(c, *relaySpaceID, s.DeviceID, relay.ArtifactKindKeyPackage)
	if err != nil {
		return err
	}

	var selected *client.RelaySpaceEnvelopeRecord
	for i := range envelopes {
		if envelopes[i].EnvelopeID == *envelopeID {
			if selected != nil {
				return fmt.Errorf("ambiguous_envelope_selection: duplicate envelope_id %s", *envelopeID)
			}
			selected = &envelopes[i]
		}
	}
	if selected == nil {
		return fmt.Errorf("envelope_not_found: no queued KeyPackage envelope %s for local device %s in Relay Space %s", *envelopeID, s.DeviceID, *relaySpaceID)
	}
	if selected.RecipientDeviceID != s.DeviceID {
		return fmt.Errorf("recipient_mismatch: envelope recipient %s does not match local device %s", selected.RecipientDeviceID, s.DeviceID)
	}
	if selected.DeliveryState != "" && selected.DeliveryState != "queued" {
		return fmt.Errorf("unsupported_delivery_state: %s", selected.DeliveryState)
	}

	if err := os.MkdirAll(filepath.Dir(artifactPath), 0o700); err != nil {
		return err
	}

	tempArtifactPath := artifactPath + ".tmp"
	_ = os.Remove(tempArtifactPath)
	if err := relay.WriteRelaySpaceKeyPackageFromEnvelope(tempArtifactPath, *selected); err != nil {
		return err
	}

	payload, err := os.ReadFile(tempArtifactPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	artifactSHA256 := hex.EncodeToString(sum[:])
	if strings.TrimSpace(*expectedPayloadSHA256) != "" &&
		artifactSHA256 != strings.TrimSpace(*expectedPayloadSHA256) {
		_ = os.Remove(tempArtifactPath)
		return fmt.Errorf("expected_payload_sha256_mismatch: got %s want %s", artifactSHA256, strings.TrimSpace(*expectedPayloadSHA256))
	}
	if err := os.Rename(tempArtifactPath, artifactPath); err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	receipt := keyPackageConsumeReceipt{
		SchemaVersion:                keyPackageConsumeReceiptSchema,
		Command:                      "openmls-relay-keypackage-consume-dev",
		ConsumeClassification:        "consumed_and_receipt_persisted_before_ack",
		EnvelopeID:                   selected.EnvelopeID,
		RelaySpaceID:                 selected.RelaySpaceID,
		SenderDeviceID:               selected.SenderDeviceID,
		RecipientDeviceID:            selected.RecipientDeviceID,
		ContentType:                  selected.ContentType,
		ProtocolVersion:              selected.ProtocolVersion,
		DeliveryStateBeforeAck:       selected.DeliveryState,
		PayloadSHA256:                selected.PayloadSHA256,
		PayloadSizeBytes:             selected.PayloadSizeBytes,
		ArtifactSHA256:               artifactSHA256,
		ArtifactSizeBytes:            int64(len(payload)),
		ExpectedKeyPackageRef:        strings.TrimSpace(*expectedKeyPackageRef),
		KeyPackageRefVerified:        false,
		ArtifactPath:                 artifactPath,
		ReceiptManifestPath:          manifestPath,
		ConsumedAt:                   now,
		LocalReceiptPersisted:        true,
		KeyPackageAcked:              false,
		AddMemberRun:                 false,
		WelcomeSubmitted:             false,
		TrustOrCandidateStateMutated: false,
		PublicDirectoryMutated:       false,
	}
	if err := writeKeyPackageConsumeReceiptAtomic(manifestPath, receipt); err != nil {
		return err
	}

	ackResp, err := c.AckRelaySpaceEnvelope(*relaySpaceID, selected.EnvelopeID, s.DeviceID)
	if err != nil {
		return fmt.Errorf("local receipt persisted but ACK failed: %w", err)
	}
	receipt.ConsumeClassification = "consumed_and_acked"
	receipt.AckedAt = ackResp.AcknowledgedAt
	receipt.AckDeliveryState = ackResp.DeliveryState
	receipt.KeyPackageAcked = ackResp.DeliveryState == "acknowledged"
	if err := writeKeyPackageConsumeReceiptAtomic(manifestPath, receipt); err != nil {
		return err
	}

	printKeyPackageConsumeReceipt(receipt)
	return nil
}

func defaultKeyPackageConsumeReceiptRoot(statePath string) string {
	dir := filepath.Dir(statePath)
	if dir == "." || dir == "" {
		dir = ".carbonstack-comms"
	}
	return filepath.Join(dir, "keypackage-receipts")
}

func acquireKeyPackageConsumeLock(root string) (keyPackageConsumeLock, error) {
	lockPath := filepath.Join(root, ".keypackage-consume-lock")
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		return keyPackageConsumeLock{}, fmt.Errorf("keypackage_consume_lock_unavailable: %w", err)
	}
	return keyPackageConsumeLock{path: lockPath}, nil
}

func keyPackageConsumeReceiptDir(root string, envelopeID string) string {
	return filepath.Join(root, safeKeyPackageReceiptID(envelopeID))
}

func keyPackageConsumeReceiptArtifactPath(root string, envelopeID string) string {
	return filepath.Join(keyPackageConsumeReceiptDir(root, envelopeID), "keypackage.bin")
}

func keyPackageConsumeReceiptManifestPath(root string, envelopeID string) string {
	return filepath.Join(keyPackageConsumeReceiptDir(root, envelopeID), "receipt.json")
}

func safeKeyPackageReceiptID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "empty"
	}
	var b strings.Builder
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	cleaned := strings.Trim(b.String(), "._-")
	if cleaned == "" {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}
	return cleaned
}

func loadKeyPackageConsumeReceipt(path string) (keyPackageConsumeReceipt, bool, error) {
	var receipt keyPackageConsumeReceipt
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return receipt, false, nil
	}
	if err != nil {
		return receipt, false, err
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		return receipt, false, fmt.Errorf("decode KeyPackage receipt manifest: %w", err)
	}
	if receipt.SchemaVersion != keyPackageConsumeReceiptSchema {
		return receipt, false, fmt.Errorf("unsupported KeyPackage receipt schema: %s", receipt.SchemaVersion)
	}
	return receipt, true, nil
}

func validateExistingKeyPackageConsumeReceipt(receipt keyPackageConsumeReceipt, relaySpaceID string, envelopeID string, deviceID string, expectedPayloadSHA256 string, expectedKeyPackageRef string) error {
	if receipt.EnvelopeID != envelopeID ||
		receipt.RelaySpaceID != relaySpaceID ||
		receipt.RecipientDeviceID != deviceID {
		return errors.New("local_receipt_conflict: receipt identity does not match requested consume identity")
	}
	if strings.TrimSpace(expectedPayloadSHA256) != "" &&
		receipt.ArtifactSHA256 != strings.TrimSpace(expectedPayloadSHA256) &&
		receipt.PayloadSHA256 != strings.TrimSpace(expectedPayloadSHA256) {
		return errors.New("local_receipt_conflict: expected payload SHA-256 does not match receipt")
	}
	if strings.TrimSpace(expectedKeyPackageRef) != "" &&
		receipt.ExpectedKeyPackageRef != "" &&
		receipt.ExpectedKeyPackageRef != strings.TrimSpace(expectedKeyPackageRef) {
		return errors.New("local_receipt_conflict: expected KeyPackage reference does not match receipt")
	}
	return nil
}

func writeKeyPackageConsumeReceiptAtomic(path string, receipt keyPackageConsumeReceipt) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func printKeyPackageConsumeReceipt(receipt keyPackageConsumeReceipt) {
	fmt.Println("command: openmls-relay-keypackage-consume-dev")
	fmt.Printf("consume_classification: %s\n", receipt.ConsumeClassification)
	fmt.Printf("envelope_id: %s\n", receipt.EnvelopeID)
	fmt.Printf("relay_space_id: %s\n", receipt.RelaySpaceID)
	fmt.Printf("sender_device_id: %s\n", receipt.SenderDeviceID)
	fmt.Printf("recipient_device_id: %s\n", receipt.RecipientDeviceID)
	fmt.Printf("content_type: %s\n", receipt.ContentType)
	fmt.Printf("protocol_version: %s\n", receipt.ProtocolVersion)
	fmt.Printf("delivery_state_before_ack: %s\n", receipt.DeliveryStateBeforeAck)
	fmt.Printf("payload_sha256: %s\n", receipt.PayloadSHA256)
	fmt.Printf("artifact_sha256: %s\n", receipt.ArtifactSHA256)
	fmt.Printf("artifact_path: %s\n", receipt.ArtifactPath)
	fmt.Printf("receipt_manifest_path: %s\n", receipt.ReceiptManifestPath)
	fmt.Printf("local_receipt_persisted: %t\n", receipt.LocalReceiptPersisted)
	fmt.Printf("ack_delivery_state: %s\n", receipt.AckDeliveryState)
	fmt.Printf("acknowledged_at: %s\n", receipt.AckedAt)
	fmt.Printf("keypackage_acked: %t\n", receipt.KeyPackageAcked)
	fmt.Printf("add_member_run: %t\n", receipt.AddMemberRun)
	fmt.Printf("welcome_submitted: %t\n", receipt.WelcomeSubmitted)
	fmt.Printf("trust_or_candidate_state_mutated: %t\n", receipt.TrustOrCandidateStateMutated)
	fmt.Printf("public_directory_mutated: %t\n", receipt.PublicDirectoryMutated)
	if receipt.ExpectedKeyPackageRef != "" {
		fmt.Printf("expected_key_package_ref: %s\n", receipt.ExpectedKeyPackageRef)
		fmt.Printf("key_package_ref_verified: %t\n", receipt.KeyPackageRefVerified)
	}
	fmt.Println("warning: dev/pre-alpha KeyPackage delivery consume/receipt only; not add-member, not Welcome lifecycle, not identity verification, not trust promotion, not production key distribution")
}
