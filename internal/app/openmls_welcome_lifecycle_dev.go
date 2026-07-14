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

const welcomeConsumeReceiptSchema = "carbonstack-welcome-consume-receipt/v0"

type welcomeConsumeReceipt struct {
	SchemaVersion                string `json:"schema_version"`
	Command                      string `json:"command"`
	JoinClassification           string `json:"join_classification"`
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
	SidecarDeviceLabel           string `json:"sidecar_device_label"`
	ConversationLabel            string `json:"conversation_label"`
	WelcomeArtifactPath          string `json:"welcome_artifact_path"`
	ReceiptManifestPath          string `json:"receipt_manifest_path"`
	WelcomePersistedAt           string `json:"welcome_persisted_at"`
	JoinAttemptedAt              string `json:"join_attempted_at,omitempty"`
	JoinedAt                     string `json:"joined_at,omitempty"`
	AckedAt                      string `json:"acked_at,omitempty"`
	AckDeliveryState             string `json:"ack_delivery_state,omitempty"`
	SidecarCommand               string `json:"sidecar_command,omitempty"`
	JoinSummaryPathHint          string `json:"join_summary_path_hint,omitempty"`
	ConversationStatePathHint    string `json:"conversation_state_path_hint,omitempty"`
	ConversationSummaryPathHint  string `json:"conversation_summary_path_hint,omitempty"`
	ProviderStoragePathHint      string `json:"provider_storage_path_hint,omitempty"`
	GroupReloadable              bool   `json:"group_reloadable"`
	Joined                       bool   `json:"joined"`
	LocalWelcomePersisted        bool   `json:"local_welcome_persisted"`
	WelcomeAcked                 bool   `json:"welcome_acked"`
	AckAfterJoin                 bool   `json:"ack_after_join"`
	AddMemberRun                 bool   `json:"add_member_run"`
	TrustOrCandidateStateMutated bool   `json:"trust_or_candidate_state_mutated"`
	VerifiedIdentityClaimed      bool   `json:"verified_identity_claimed"`
	CypherMLSReconciled          bool   `json:"cypher_mls_reconciled"`
	PublicDirectoryMutated       bool   `json:"public_directory_mutated"`
}

type welcomeConsumeLock struct {
	path string
}

func (l welcomeConsumeLock) release() {
	if l.path != "" {
		_ = os.Remove(l.path)
	}
}

func cmdOpenMLSRelayWelcomeConsumeDev(args []string) error {
	fs := flag.NewFlagSet("openmls-relay-welcome-consume-dev", flag.ContinueOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID")
	envelopeID := fs.String("envelope-id", "", "Relay Space Welcome envelope ID")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS sidecar conversation label")
	receiptRoot := fs.String("receipt-root", "", "local Welcome receipt root; defaults beside the Comms state file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*relaySpaceID) == "" {
		return errors.New("--relay-space is required")
	}
	if strings.TrimSpace(*envelopeID) == "" {
		return errors.New("--envelope-id is required")
	}
	if strings.TrimSpace(*sidecarDeviceLabel) == "" {
		return errors.New("--sidecar-device-label is required")
	}
	if strings.TrimSpace(*conversationLabel) == "" {
		return errors.New("--conversation is required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	root := strings.TrimSpace(*receiptRoot)
	if root == "" {
		root = defaultWelcomeConsumeReceiptRoot(*statePath)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create Welcome receipt root: %w", err)
	}

	lock, err := acquireWelcomeConsumeLock(root)
	if err != nil {
		return err
	}
	defer lock.release()

	manifestPath := welcomeConsumeReceiptManifestPath(root, *envelopeID)
	artifactPath := welcomeConsumeReceiptArtifactPath(root, *envelopeID)

	if _, err := os.Stat(artifactPath); err == nil {
		if _, manifestErr := os.Stat(manifestPath); manifestErr != nil {
			return fmt.Errorf("incomplete_welcome_consume: artifact exists without receipt manifest for envelope %s", *envelopeID)
		}
	}

	c := client.New(s.ServerURL)

	if receipt, ok, err := loadWelcomeConsumeReceipt(manifestPath); err != nil {
		return err
	} else if ok {
		if err := validateExistingWelcomeConsumeReceipt(receipt, *relaySpaceID, *envelopeID, s.DeviceID, *sidecarDeviceLabel, *conversationLabel); err != nil {
			return err
		}
		if receipt.Joined && !receipt.WelcomeAcked {
			ackResp, err := c.AckRelaySpaceEnvelope(*relaySpaceID, *envelopeID, s.DeviceID)
			if err != nil {
				return fmt.Errorf("retry ACK for joined Welcome receipt: %w", err)
			}
			receipt.JoinClassification = "ack_retried_after_join"
			receipt.AckedAt = ackResp.AcknowledgedAt
			receipt.AckDeliveryState = ackResp.DeliveryState
			receipt.WelcomeAcked = ackResp.DeliveryState == "acknowledged"
			if err := writeWelcomeConsumeReceiptAtomic(manifestPath, receipt); err != nil {
				return err
			}
		} else if receipt.Joined && receipt.WelcomeAcked {
			receipt.JoinClassification = "already_joined"
		} else {
			return fmt.Errorf("incomplete_welcome_consume: receipt exists but join/ACK did not complete for envelope %s", *envelopeID)
		}
		printWelcomeConsumeReceipt(receipt)
		return nil
	}

	envelopes, err := relay.RelaySpaceOpenMLSArtifactInbox(c, *relaySpaceID, s.DeviceID, relay.ArtifactKindWelcome)
	if err != nil {
		return err
	}

	var selected *client.RelaySpaceEnvelopeRecord
	for i := range envelopes {
		if envelopes[i].EnvelopeID == *envelopeID {
			if selected != nil {
				return fmt.Errorf("ambiguous_welcome_selection: duplicate envelope_id %s", *envelopeID)
			}
			selected = &envelopes[i]
		}
	}
	if selected == nil {
		return fmt.Errorf("welcome_envelope_not_found: no queued Welcome envelope %s for local device %s in Relay Space %s", *envelopeID, s.DeviceID, *relaySpaceID)
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

	tmpArtifactPath := artifactPath + ".tmp"
	_ = os.Remove(tmpArtifactPath)
	if err := relay.WriteRelaySpaceWelcomeFromEnvelope(tmpArtifactPath, *selected); err != nil {
		return err
	}

	payload, err := os.ReadFile(tmpArtifactPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	artifactSHA256 := hex.EncodeToString(sum[:])
	if err := os.Rename(tmpArtifactPath, artifactPath); err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	receipt := welcomeConsumeReceipt{
		SchemaVersion:                welcomeConsumeReceiptSchema,
		Command:                      "openmls-relay-welcome-consume-dev",
		JoinClassification:           "welcome_persisted_before_join",
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
		SidecarDeviceLabel:           strings.TrimSpace(*sidecarDeviceLabel),
		ConversationLabel:            strings.TrimSpace(*conversationLabel),
		WelcomeArtifactPath:          artifactPath,
		ReceiptManifestPath:          manifestPath,
		WelcomePersistedAt:           now,
		LocalWelcomePersisted:        true,
		WelcomeAcked:                 false,
		AckAfterJoin:                 true,
		AddMemberRun:                 false,
		TrustOrCandidateStateMutated: false,
		VerifiedIdentityClaimed:      false,
		CypherMLSReconciled:          false,
		PublicDirectoryMutated:       false,
	}
	if err := writeWelcomeConsumeReceiptAtomic(manifestPath, receipt); err != nil {
		return err
	}

	receipt.JoinAttemptedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeWelcomeConsumeReceiptAtomic(manifestPath, receipt); err != nil {
		return err
	}

	envelope, err := runOpenMLSBootstrapSidecarForCommand(
		*sidecarDir,
		"conversation-join",
		"--device-label", *sidecarDeviceLabel,
		"--conversation-label", *conversationLabel,
		"--welcome", artifactPath,
	)
	if err != nil {
		return fmt.Errorf("local Welcome receipt persisted but join failed: %w", err)
	}

	receipt.JoinClassification = "joined_receipt_persisted_before_ack"
	receipt.SidecarCommand = envelope.Command
	receipt.Joined = bootstrapBoolFieldDefault(envelope.Data, "joined", true)
	receipt.GroupReloadable = bootstrapBoolFieldDefault(envelope.Data, "group_reloadable", false)
	receipt.JoinSummaryPathHint = bootstrapStringField(envelope.Data, "join_summary_path_hint")
	receipt.ConversationStatePathHint = bootstrapStringField(envelope.Data, "conversation_state_path_hint")
	receipt.ConversationSummaryPathHint = bootstrapStringField(envelope.Data, "conversation_summary_path_hint")
	receipt.ProviderStoragePathHint = bootstrapStringField(envelope.Data, "provider_storage_path_hint")
	receipt.JoinedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeWelcomeConsumeReceiptAtomic(manifestPath, receipt); err != nil {
		return err
	}

	ackResp, err := c.AckRelaySpaceEnvelope(*relaySpaceID, selected.EnvelopeID, s.DeviceID)
	if err != nil {
		return fmt.Errorf("local Welcome join persisted but ACK failed: %w", err)
	}

	receipt.JoinClassification = "joined_and_acked"
	receipt.AckedAt = ackResp.AcknowledgedAt
	receipt.AckDeliveryState = ackResp.DeliveryState
	receipt.WelcomeAcked = ackResp.DeliveryState == "acknowledged"
	if err := writeWelcomeConsumeReceiptAtomic(manifestPath, receipt); err != nil {
		return err
	}

	printWelcomeConsumeReceipt(receipt)
	return nil
}

func defaultWelcomeConsumeReceiptRoot(statePath string) string {
	dir := filepath.Dir(statePath)
	if dir == "." || dir == "" {
		dir = ".carbonstack-comms"
	}
	return filepath.Join(dir, "welcome-receipts")
}

func acquireWelcomeConsumeLock(root string) (welcomeConsumeLock, error) {
	lockPath := filepath.Join(root, ".welcome-consume-lock")
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		return welcomeConsumeLock{}, fmt.Errorf("welcome_consume_lock_unavailable: %w", err)
	}
	return welcomeConsumeLock{path: lockPath}, nil
}

func welcomeConsumeReceiptDir(root string, envelopeID string) string {
	return filepath.Join(root, safeWelcomeReceiptID(envelopeID))
}

func welcomeConsumeReceiptArtifactPath(root string, envelopeID string) string {
	return filepath.Join(welcomeConsumeReceiptDir(root, envelopeID), "welcome.bin")
}

func welcomeConsumeReceiptManifestPath(root string, envelopeID string) string {
	return filepath.Join(welcomeConsumeReceiptDir(root, envelopeID), "receipt.json")
}

func safeWelcomeReceiptID(value string) string {
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

func loadWelcomeConsumeReceipt(path string) (welcomeConsumeReceipt, bool, error) {
	var receipt welcomeConsumeReceipt
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return receipt, false, nil
	}
	if err != nil {
		return receipt, false, err
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		return receipt, false, fmt.Errorf("decode Welcome receipt manifest: %w", err)
	}
	if receipt.SchemaVersion != welcomeConsumeReceiptSchema {
		return receipt, false, fmt.Errorf("unsupported Welcome receipt schema: %s", receipt.SchemaVersion)
	}
	return receipt, true, nil
}

func validateExistingWelcomeConsumeReceipt(receipt welcomeConsumeReceipt, relaySpaceID string, envelopeID string, deviceID string, sidecarDeviceLabel string, conversationLabel string) error {
	if receipt.EnvelopeID != envelopeID ||
		receipt.RelaySpaceID != relaySpaceID ||
		receipt.RecipientDeviceID != deviceID ||
		receipt.SidecarDeviceLabel != strings.TrimSpace(sidecarDeviceLabel) ||
		receipt.ConversationLabel != strings.TrimSpace(conversationLabel) {
		return errors.New("local_welcome_receipt_conflict: receipt identity does not match requested consume/join identity")
	}
	return nil
}

func writeWelcomeConsumeReceiptAtomic(path string, receipt welcomeConsumeReceipt) error {
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

func bootstrapBoolFieldDefault(data map[string]any, name string, fallback bool) bool {
	if value, ok := bootstrapBoolField(data, name); ok {
		return value
	}
	return fallback
}

func printWelcomeConsumeReceipt(receipt welcomeConsumeReceipt) {
	fmt.Println("openmls relay welcome consume dev")
	fmt.Println("command: openmls-relay-welcome-consume-dev")
	fmt.Printf("join_classification: %s\n", receipt.JoinClassification)
	fmt.Printf("envelope_id: %s\n", receipt.EnvelopeID)
	fmt.Printf("relay_space_id: %s\n", receipt.RelaySpaceID)
	fmt.Printf("welcome_from_device: %s\n", receipt.SenderDeviceID)
	fmt.Printf("recipient_device_id: %s\n", receipt.RecipientDeviceID)
	fmt.Printf("content_type: %s\n", receipt.ContentType)
	fmt.Printf("protocol_version: %s\n", receipt.ProtocolVersion)
	fmt.Printf("delivery_state_before_ack: %s\n", receipt.DeliveryStateBeforeAck)
	fmt.Printf("payload_sha256: %s\n", receipt.PayloadSHA256)
	fmt.Printf("artifact_sha256: %s\n", receipt.ArtifactSHA256)
	fmt.Printf("welcome_artifact_path: %s\n", receipt.WelcomeArtifactPath)
	fmt.Printf("receipt_manifest_path: %s\n", receipt.ReceiptManifestPath)
	fmt.Printf("sidecar_device_label: %s\n", receipt.SidecarDeviceLabel)
	fmt.Printf("sidecar_conversation_label: %s\n", receipt.ConversationLabel)
	fmt.Printf("local_welcome_persisted: %t\n", receipt.LocalWelcomePersisted)
	fmt.Printf("joined: %t\n", receipt.Joined)
	fmt.Printf("ack_after_join: %t\n", receipt.AckAfterJoin)
	fmt.Printf("welcome_acked: %t\n", receipt.WelcomeAcked)
	fmt.Printf("ack_delivery_state: %s\n", receipt.AckDeliveryState)
	fmt.Printf("acknowledged_at: %s\n", receipt.AckedAt)
	fmt.Printf("add_member_run: %t\n", receipt.AddMemberRun)
	fmt.Printf("trust_or_candidate_state_mutated: %t\n", receipt.TrustOrCandidateStateMutated)
	fmt.Printf("verified_identity_claimed: %t\n", receipt.VerifiedIdentityClaimed)
	fmt.Printf("cypher_mls_reconciled: %t\n", receipt.CypherMLSReconciled)
	fmt.Printf("public_directory_mutated: %t\n", receipt.PublicDirectoryMutated)
	if receipt.SidecarCommand != "" {
		fmt.Printf("sidecar_command: %s\n", receipt.SidecarCommand)
	}
	if receipt.JoinSummaryPathHint != "" {
		fmt.Printf("join_summary_path_hint: %s\n", receipt.JoinSummaryPathHint)
	}
	if receipt.ConversationStatePathHint != "" {
		fmt.Printf("conversation_state_path_hint: %s\n", receipt.ConversationStatePathHint)
	}
	if receipt.ConversationSummaryPathHint != "" {
		fmt.Printf("conversation_summary_path_hint: %s\n", receipt.ConversationSummaryPathHint)
	}
	if receipt.ProviderStoragePathHint != "" {
		fmt.Printf("provider_storage_path_hint: %s\n", receipt.ProviderStoragePathHint)
	}
	fmt.Println("warning: dev/pre-alpha Welcome consume/join lifecycle only; not identity verification, not trust promotion, not Cypher/MLS reconciliation, not production E2EE")
}
