package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/trust"
)

const defaultOpenMLSSidecarDir = "internal/protocol/mls/openmls-sidecar"

type openMLSMessageProtectResult struct {
	DeviceLabel             string
	ConversationLabel       string
	MessageLabel            string
	MessageArtifactPathHint string
}

type openMLSSidecarErrorEnvelope struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type openMLSSidecarProtectEnvelope struct {
	OK      bool                         `json:"ok"`
	Command string                       `json:"command"`
	Data    openMLSSidecarProtectData    `json:"data"`
	Error   *openMLSSidecarErrorEnvelope `json:"error"`
}

type openMLSSidecarProtectData struct {
	DeviceLabel             string `json:"device_label"`
	ConversationLabel       string `json:"conversation_label"`
	MessageLabel            string `json:"message_label"`
	MessageArtifactPathHint string `json:"message_artifact_path_hint"`
}

var runOpenMLSMessageProtectForCommand = runOpenMLSMessageProtect

var submitOpenMLSArtifactEnvelopeForCommand = relay.SubmitOpenMLSArtifactEnvelope

func cmdOpenMLSSendDev(args []string) error {
	fs := flag.NewFlagSet("openmls-send-dev", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
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

	if *toDevice == "" || *message == "" || *sidecarDeviceLabel == "" || *conversationLabel == "" {
		return errors.New("--to-device, --message, --sidecar-device-label, and --conversation are required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	commandPaths, err := resolveCommandStatePaths(*statePath)
	if err != nil {
		return err
	}
	paths := commandPaths.TrustPaths
	decision, err := trust.EvaluateSend(paths, *toDevice, *strict)
	if err != nil {
		return err
	}

	if decision.Warning != "" {
		fmt.Printf("WARNING: %s\n", decision.Warning)
	}
	if !*strict {
		fmt.Println("WARNING: openmls-send-dev is running in dev trust mode; use --strict to block unknown or unverified recipients")
	}

	if !decision.Allowed {
		return fmt.Errorf("openmls-send-dev blocked by trust policy: recipient trust_state=%s", decision.TrustState)
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
	resp, err := submitOpenMLSArtifactEnvelopeForCommand(
		c,
		s.DeviceID,
		*toDevice,
		relay.ArtifactKindApplicationMessage,
		artifactPath,
		relay.DefaultClientCreatedAt(),
	)
	if err != nil {
		return err
	}

	fmt.Println("openmls dev envelope sent")
	fmt.Printf("command: openmls-send-dev\n")
	fmt.Printf("status: sent\n")
	fmt.Printf("sender_device_id: %s\n", s.DeviceID)
	fmt.Printf("recipient_device_id: %s\n", *toDevice)
	fmt.Printf("content_type: %s\n", relay.ContentTypeOpenMLSApplicationMessage)
	fmt.Printf("protocol_version: %s\n", relay.ProtocolVersionOpenMLSSidecar)
	fmt.Printf("envelope_id: %s\n", resp.EnvelopeID)
	fmt.Printf("delivery_state: %s\n", resp.DeliveryState)
	fmt.Printf("server_received_at: %s\n", resp.ServerReceivedAt)
	fmt.Printf("payload_sha256: %s\n", resp.PayloadSHA256)
	fmt.Printf("payload_size_bytes: %d\n", resp.PayloadSizeBytes)
	fmt.Printf("sidecar_device_label: %s\n", protect.DeviceLabel)
	fmt.Printf("sidecar_conversation_label: %s\n", protect.ConversationLabel)
	fmt.Printf("sidecar_message_label: %s\n", protect.MessageLabel)
	fmt.Println("warning: dev/pre-alpha OpenMLS runtime path; not production messaging UX")
	return nil
}

func runOpenMLSMessageProtect(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, plaintext string) (openMLSMessageProtectResult, error) {
	if strings.TrimSpace(sidecarDir) == "" {
		return openMLSMessageProtectResult{}, errors.New("sidecar directory is required")
	}

	cmdArgs := []string{
		"run",
		"--quiet",
		"--",
		"message-protect",
		"--device-label", deviceLabel,
		"--conversation-label", conversationLabel,
		"--plaintext", plaintext,
	}
	if strings.TrimSpace(messageLabel) != "" {
		cmdArgs = append(cmdArgs, "--message-label", messageLabel)
	}

	cmd := exec.Command("cargo", cmdArgs...)
	cmd.Dir = sidecarDir

	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			parsed, parseErr := parseOpenMLSProtectEnvelope(output)
			if parseErr == nil && parsed.Error != nil {
				return openMLSMessageProtectResult{}, fmt.Errorf("OpenMLS sidecar message-protect failed: %s: %s", parsed.Error.Code, parsed.Error.Message)
			}
		}
		return openMLSMessageProtectResult{}, fmt.Errorf("run OpenMLS sidecar message-protect: %w", err)
	}

	parsed, err := parseOpenMLSProtectEnvelope(output)
	if err != nil {
		return openMLSMessageProtectResult{}, err
	}

	if !parsed.OK {
		if parsed.Error != nil {
			return openMLSMessageProtectResult{}, fmt.Errorf("OpenMLS sidecar message-protect failed: %s: %s", parsed.Error.Code, parsed.Error.Message)
		}
		return openMLSMessageProtectResult{}, errors.New("OpenMLS sidecar message-protect returned ok=false")
	}

	if parsed.Data.MessageArtifactPathHint == "" {
		return openMLSMessageProtectResult{}, errors.New("OpenMLS sidecar message-protect returned empty message_artifact_path_hint")
	}

	return openMLSMessageProtectResult{
		DeviceLabel:             parsed.Data.DeviceLabel,
		ConversationLabel:       parsed.Data.ConversationLabel,
		MessageLabel:            parsed.Data.MessageLabel,
		MessageArtifactPathHint: parsed.Data.MessageArtifactPathHint,
	}, nil
}

func parseOpenMLSProtectEnvelope(output []byte) (openMLSSidecarProtectEnvelope, error) {
	var parsed openMLSSidecarProtectEnvelope
	if err := json.Unmarshal(output, &parsed); err != nil {
		return parsed, fmt.Errorf("decode OpenMLS sidecar message-protect envelope: %w", err)
	}
	return parsed, nil
}

type openMLSMessageOpenResult struct {
	DeviceLabel                string
	ConversationLabel          string
	MessageLabel               string
	MessageArtifactPathHint    string
	MessageOpenSummaryPathHint string
	PlaintextUTF8              string
	PlaintextLen               int
	MessageOpened              bool
}

type openMLSSidecarOpenEnvelope struct {
	OK      bool                         `json:"ok"`
	Command string                       `json:"command"`
	Data    openMLSSidecarOpenData       `json:"data"`
	Error   *openMLSSidecarErrorEnvelope `json:"error"`
}

type openMLSSidecarOpenData struct {
	DeviceLabel                string `json:"device_label"`
	ConversationLabel          string `json:"conversation_label"`
	MessageLabel               string `json:"message_label"`
	MessageArtifactPathHint    string `json:"message_artifact_path_hint"`
	MessageOpenSummaryPathHint string `json:"message_open_summary_path_hint"`
	PlaintextUTF8              string `json:"plaintext_utf8"`
	PlaintextLen               int    `json:"plaintext_len"`
	MessageOpened              bool   `json:"message_opened"`
}

var inboxForCommand = func(c client.CypherClient, deviceID string) (client.InboxResponse, error) {
	return c.Inbox(deviceID)
}

var ackEnvelopeForCommand = func(c client.CypherClient, envelopeID string, recipientDeviceID string) (client.AckEnvelopeResponse, error) {
	return c.AckEnvelope(envelopeID, recipientDeviceID)
}

var writeOpenMLSArtifactFromEnvelopeForCommand = relay.WriteOpenMLSArtifactFromEnvelope

var runOpenMLSMessageOpenForCommand = runOpenMLSMessageOpen

func cmdOpenMLSInboxDev(args []string) error {
	fs := flag.NewFlagSet("openmls-inbox-dev", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "recipient OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS sidecar conversation label")
	messageLabel := fs.String("message-label", "", "OpenMLS sidecar message label; generated per envelope when omitted")
	limit := fs.Int("limit", 1, "maximum OpenMLS application-message envelopes to open")
	ack := fs.Bool("ack", false, "ack each envelope only after sidecar message-open succeeds")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *sidecarDeviceLabel == "" || *conversationLabel == "" {
		return errors.New("--sidecar-device-label and --conversation are required")
	}

	if *limit < 1 {
		return errors.New("--limit must be >= 1")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	c := client.New(s.ServerURL)
	inbox, err := inboxForCommand(c, s.DeviceID)
	if err != nil {
		return err
	}

	fmt.Println("openmls dev inbox")
	fmt.Printf("command: openmls-inbox-dev\n")
	fmt.Printf("device_id: %s\n", inbox.DeviceID)
	fmt.Printf("queued_envelopes: %d\n", len(inbox.Envelopes))
	fmt.Printf("limit: %d\n", *limit)
	fmt.Printf("ack_requested: %t\n", *ack)
	fmt.Println("warning: dev/pre-alpha OpenMLS runtime path; not production messaging UX")

	opened := 0
	unsupported := 0
	openFailures := 0
	ackFailures := 0

	for i, envelope := range inbox.Envelopes {
		if opened >= *limit {
			break
		}

		if envelope.ContentType != relay.ContentTypeOpenMLSApplicationMessage || envelope.ProtocolVersion != relay.ProtocolVersionOpenMLSSidecar {
			unsupported++
			fmt.Println()
			fmt.Println("skipped_unsupported_envelope")
			fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
			fmt.Printf("content_type: %s\n", envelope.ContentType)
			fmt.Printf("protocol_version: %s\n", envelope.ProtocolVersion)
			continue
		}

		label := strings.TrimSpace(*messageLabel)
		if label == "" {
			label = "inbox-" + strconv.Itoa(opened+1)
		}

		artifactPath, err := writeOpenMLSInboxDevArtifact(envelope, i)
		if err != nil {
			openFailures++
			fmt.Println()
			fmt.Println("openmls_envelope_write_failed")
			fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
			fmt.Printf("error: %v\n", err)
			continue
		}

		openedResult, err := runOpenMLSMessageOpenForCommand(*sidecarDir, *sidecarDeviceLabel, *conversationLabel, label, artifactPath)
		if err != nil {
			openFailures++
			fmt.Println()
			fmt.Println("openmls_message_open_failed")
			fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
			fmt.Printf("error: %v\n", err)
			fmt.Println("acked: false")
			continue
		}

		opened++
		acked := false

		if *ack {
			ackResp, err := ackEnvelopeForCommand(c, envelope.EnvelopeID, s.DeviceID)
			if err != nil {
				ackFailures++
				fmt.Println()
				fmt.Println("openmls_message_opened_but_ack_failed")
				fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
				fmt.Printf("error: %v\n", err)
			} else {
				acked = true
				fmt.Println()
				fmt.Println("openmls_message_opened")
				fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
				fmt.Printf("ack_delivery_state: %s\n", ackResp.DeliveryState)
				fmt.Printf("acknowledged_at: %s\n", ackResp.AcknowledgedAt)
			}
		} else {
			fmt.Println()
			fmt.Println("openmls_message_opened")
			fmt.Printf("envelope_id: %s\n", envelope.EnvelopeID)
		}

		fmt.Printf("from_device: %s\n", envelope.SenderDeviceID)
		fmt.Printf("content_type: %s\n", envelope.ContentType)
		fmt.Printf("protocol_version: %s\n", envelope.ProtocolVersion)
		fmt.Printf("sidecar_device_label: %s\n", openedResult.DeviceLabel)
		fmt.Printf("sidecar_conversation_label: %s\n", openedResult.ConversationLabel)
		fmt.Printf("sidecar_message_label: %s\n", openedResult.MessageLabel)
		fmt.Printf("message_opened: %t\n", openedResult.MessageOpened)
		fmt.Printf("plaintext_len: %d\n", openedResult.PlaintextLen)
		fmt.Printf("plaintext_utf8: %s\n", openedResult.PlaintextUTF8)
		fmt.Printf("acked: %t\n", acked)
	}

	fmt.Println()
	fmt.Println("openmls dev inbox summary")
	fmt.Printf("opened_envelopes: %d\n", opened)
	fmt.Printf("unsupported_envelopes: %d\n", unsupported)
	fmt.Printf("open_failures: %d\n", openFailures)
	fmt.Printf("ack_failures: %d\n", ackFailures)

	return nil
}

func writeOpenMLSInboxDevArtifact(envelope client.EnvelopeRecord, index int) (string, error) {
	root, err := os.MkdirTemp("", "carbonstack-openmls-inbox-dev-")
	if err != nil {
		return "", err
	}

	path := filepath.Join(root, "envelope-"+strconv.Itoa(index+1), "application-message.bin")
	if err := writeOpenMLSArtifactFromEnvelopeForCommand(path, envelope); err != nil {
		return "", err
	}

	return path, nil
}

func runOpenMLSMessageOpen(sidecarDir string, deviceLabel string, conversationLabel string, messageLabel string, messageArtifactPath string) (openMLSMessageOpenResult, error) {
	if strings.TrimSpace(sidecarDir) == "" {
		return openMLSMessageOpenResult{}, errors.New("sidecar directory is required")
	}
	if strings.TrimSpace(messageArtifactPath) == "" {
		return openMLSMessageOpenResult{}, errors.New("message artifact path is required")
	}

	cmdArgs := []string{
		"run",
		"--quiet",
		"--",
		"message-open",
		"--device-label", deviceLabel,
		"--conversation-label", conversationLabel,
		"--message", messageArtifactPath,
	}
	if strings.TrimSpace(messageLabel) != "" {
		cmdArgs = append(cmdArgs, "--message-label", messageLabel)
	}

	cmd := exec.Command("cargo", cmdArgs...)
	cmd.Dir = sidecarDir

	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			parsed, parseErr := parseOpenMLSOpenEnvelope(output)
			if parseErr == nil && parsed.Error != nil {
				return openMLSMessageOpenResult{}, fmt.Errorf("OpenMLS sidecar message-open failed: %s: %s", parsed.Error.Code, parsed.Error.Message)
			}
		}
		return openMLSMessageOpenResult{}, fmt.Errorf("run OpenMLS sidecar message-open: %w", err)
	}

	parsed, err := parseOpenMLSOpenEnvelope(output)
	if err != nil {
		return openMLSMessageOpenResult{}, err
	}

	if !parsed.OK {
		if parsed.Error != nil {
			return openMLSMessageOpenResult{}, fmt.Errorf("OpenMLS sidecar message-open failed: %s: %s", parsed.Error.Code, parsed.Error.Message)
		}
		return openMLSMessageOpenResult{}, errors.New("OpenMLS sidecar message-open returned ok=false")
	}

	if !parsed.Data.MessageOpened {
		return openMLSMessageOpenResult{}, errors.New("OpenMLS sidecar message-open returned message_opened=false")
	}

	return openMLSMessageOpenResult{
		DeviceLabel:                parsed.Data.DeviceLabel,
		ConversationLabel:          parsed.Data.ConversationLabel,
		MessageLabel:               parsed.Data.MessageLabel,
		MessageArtifactPathHint:    parsed.Data.MessageArtifactPathHint,
		MessageOpenSummaryPathHint: parsed.Data.MessageOpenSummaryPathHint,
		PlaintextUTF8:              parsed.Data.PlaintextUTF8,
		PlaintextLen:               parsed.Data.PlaintextLen,
		MessageOpened:              parsed.Data.MessageOpened,
	}, nil
}

func parseOpenMLSOpenEnvelope(output []byte) (openMLSSidecarOpenEnvelope, error) {
	var parsed openMLSSidecarOpenEnvelope
	if err := json.Unmarshal(output, &parsed); err != nil {
		return parsed, fmt.Errorf("decode OpenMLS sidecar message-open envelope: %w", err)
	}
	return parsed, nil
}
