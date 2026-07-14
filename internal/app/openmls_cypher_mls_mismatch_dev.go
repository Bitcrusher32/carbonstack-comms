package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

const cypherMLSMismatchReportSchema = "carbonstack-cypher-mls-mismatch-report/v0"

type cypherMLSMismatchInput struct {
	RelaySpaceID          string
	LocalDeviceID         string
	CypherMemberState     string
	MLSGroupState         string
	SidecarDeviceLabel    string
	ConversationLabel     string
	ConversationStatePath string
	KeyPackageReceiptPath string
	WelcomeReceiptPath    string
	AllowRefusalExitZero  bool
}

type cypherMLSMismatchReport struct {
	SchemaVersion                string   `json:"schema_version"`
	Command                      string   `json:"command"`
	Classification               string   `json:"classification"`
	Action                       string   `json:"action"`
	RelaySpaceID                 string   `json:"relay_space_id"`
	LocalDeviceID                string   `json:"local_device_id"`
	CypherMemberState            string   `json:"cypher_member_state"`
	MLSGroupState                string   `json:"mls_group_state"`
	SidecarDeviceLabel           string   `json:"sidecar_device_label,omitempty"`
	ConversationLabel            string   `json:"conversation_label,omitempty"`
	ConversationStatePath        string   `json:"conversation_state_path,omitempty"`
	KeyPackageReceiptPath        string   `json:"keypackage_receipt_path,omitempty"`
	WelcomeReceiptPath           string   `json:"welcome_receipt_path,omitempty"`
	KeyPackageReceiptPresent     bool     `json:"keypackage_receipt_present"`
	WelcomeReceiptPresent        bool     `json:"welcome_receipt_present"`
	KeyPackageReceiptPersisted   bool     `json:"keypackage_receipt_persisted"`
	KeyPackageAcked              bool     `json:"keypackage_acked"`
	WelcomePersisted             bool     `json:"welcome_persisted"`
	WelcomeJoined                bool     `json:"welcome_joined"`
	WelcomeAcked                 bool     `json:"welcome_acked"`
	ReceiptRelaySpaceMismatch    bool     `json:"receipt_relay_space_mismatch"`
	ReceiptDeviceMismatch        bool     `json:"receipt_device_mismatch"`
	SidecarDeviceLabelMismatch   bool     `json:"sidecar_device_label_mismatch"`
	ConversationLabelMismatch    bool     `json:"conversation_label_mismatch"`
	RefusalReasons               []string `json:"refusal_reasons"`
	NoSilentRepair               bool     `json:"no_silent_repair"`
	NoSilentRejoin               bool     `json:"no_silent_rejoin"`
	TrustOrCandidateStateMutated bool     `json:"trust_or_candidate_state_mutated"`
	VerifiedIdentityClaimed      bool     `json:"verified_identity_claimed"`
	CypherMLSReconciled          bool     `json:"cypher_mls_reconciled"`
	PublicDirectoryMutated       bool     `json:"public_directory_mutated"`
}

type b7KeyPackageReceipt struct {
	SchemaVersion                string `json:"schema_version"`
	EnvelopeID                   string `json:"envelope_id"`
	RelaySpaceID                 string `json:"relay_space_id"`
	SenderDeviceID               string `json:"sender_device_id"`
	RecipientDeviceID            string `json:"recipient_device_id"`
	LocalReceiptPersisted        bool   `json:"local_receipt_persisted"`
	KeyPackageAcked              bool   `json:"keypackage_acked"`
	AddMemberRun                 bool   `json:"add_member_run"`
	WelcomeSubmitted             bool   `json:"welcome_submitted"`
	TrustOrCandidateStateMutated bool   `json:"trust_or_candidate_state_mutated"`
}

type b7WelcomeReceipt struct {
	SchemaVersion                string `json:"schema_version"`
	EnvelopeID                   string `json:"envelope_id"`
	RelaySpaceID                 string `json:"relay_space_id"`
	SenderDeviceID               string `json:"sender_device_id"`
	RecipientDeviceID            string `json:"recipient_device_id"`
	SidecarDeviceLabel           string `json:"sidecar_device_label"`
	ConversationLabel            string `json:"conversation_label"`
	LocalWelcomePersisted        bool   `json:"local_welcome_persisted"`
	Joined                       bool   `json:"joined"`
	WelcomeAcked                 bool   `json:"welcome_acked"`
	TrustOrCandidateStateMutated bool   `json:"trust_or_candidate_state_mutated"`
	VerifiedIdentityClaimed      bool   `json:"verified_identity_claimed"`
	CypherMLSReconciled          bool   `json:"cypher_mls_reconciled"`
	PublicDirectoryMutated       bool   `json:"public_directory_mutated"`
}

func cmdOpenMLSCypherMLSMismatchInspectDev(args []string) error {
	fs := flag.NewFlagSet("openmls-cypher-mls-mismatch-inspect-dev", flag.ContinueOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local Comms state path")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID being inspected")
	cypherMemberState := fs.String("cypher-member-state", "", "explicit Cypher Relay Space member state snapshot: active, disabled, left, absent, pending, unknown")
	mlsGroupState := fs.String("mls-group-state", "auto", "local MLS group state: present, absent, unknown, or auto")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS conversation label")
	conversationStatePath := fs.String("conversation-state", "", "explicit OpenMLS conversation-state path")
	keyPackageReceiptPath := fs.String("keypackage-receipt", "", "optional B5d KeyPackage receipt manifest")
	welcomeReceiptPath := fs.String("welcome-receipt", "", "optional B6 Welcome receipt manifest")
	allowRefusalExitZero := fs.Bool("allow-refusal-exit-zero", false, "print refusal report but return exit 0 for profile/reporting harnesses")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*relaySpaceID) == "" {
		return errors.New("--relay-space is required")
	}
	if strings.TrimSpace(*cypherMemberState) == "" {
		return errors.New("--cypher-member-state is required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	convPath := strings.TrimSpace(*conversationStatePath)
	if convPath == "" && strings.TrimSpace(*sidecarDeviceLabel) != "" && strings.TrimSpace(*conversationLabel) != "" {
		convPath = filepath.Join(*sidecarDir, "devices", strings.TrimSpace(*sidecarDeviceLabel), "conversations", strings.TrimSpace(*conversationLabel), "conversation-state.json")
	}

	input := cypherMLSMismatchInput{
		RelaySpaceID:          strings.TrimSpace(*relaySpaceID),
		LocalDeviceID:         s.DeviceID,
		CypherMemberState:     strings.TrimSpace(*cypherMemberState),
		MLSGroupState:         strings.TrimSpace(*mlsGroupState),
		SidecarDeviceLabel:    strings.TrimSpace(*sidecarDeviceLabel),
		ConversationLabel:     strings.TrimSpace(*conversationLabel),
		ConversationStatePath: convPath,
		KeyPackageReceiptPath: strings.TrimSpace(*keyPackageReceiptPath),
		WelcomeReceiptPath:    strings.TrimSpace(*welcomeReceiptPath),
		AllowRefusalExitZero:  *allowRefusalExitZero,
	}

	report, err := evaluateCypherMLSMismatch(input)
	if err != nil {
		return err
	}
	printCypherMLSMismatchReport(report)

	if report.Action == "refuse" && !input.AllowRefusalExitZero {
		return fmt.Errorf("cypher_mls_mismatch_refusal: %s", report.Classification)
	}
	return nil
}

func evaluateCypherMLSMismatch(input cypherMLSMismatchInput) (cypherMLSMismatchReport, error) {
	report := cypherMLSMismatchReport{
		SchemaVersion:                cypherMLSMismatchReportSchema,
		Command:                      "openmls-cypher-mls-mismatch-inspect-dev",
		RelaySpaceID:                 strings.TrimSpace(input.RelaySpaceID),
		LocalDeviceID:                strings.TrimSpace(input.LocalDeviceID),
		CypherMemberState:            normalizeCypherMemberState(input.CypherMemberState),
		MLSGroupState:                normalizeMLSGroupState(input.MLSGroupState),
		SidecarDeviceLabel:           strings.TrimSpace(input.SidecarDeviceLabel),
		ConversationLabel:            strings.TrimSpace(input.ConversationLabel),
		ConversationStatePath:        strings.TrimSpace(input.ConversationStatePath),
		KeyPackageReceiptPath:        strings.TrimSpace(input.KeyPackageReceiptPath),
		WelcomeReceiptPath:           strings.TrimSpace(input.WelcomeReceiptPath),
		NoSilentRepair:               true,
		NoSilentRejoin:               true,
		TrustOrCandidateStateMutated: false,
		VerifiedIdentityClaimed:      false,
		CypherMLSReconciled:          false,
		PublicDirectoryMutated:       false,
	}

	if report.RelaySpaceID == "" {
		return report, errors.New("relay_space_required")
	}
	if report.LocalDeviceID == "" {
		return report, errors.New("local_device_required")
	}
	if report.CypherMemberState == "unsupported" || report.MLSGroupState == "unsupported" {
		report.Classification = "unsupported_or_unknown_state_version"
		report.Action = "refuse"
		report.RefusalReasons = append(report.RefusalReasons, "unsupported state token")
		return report, nil
	}

	if report.MLSGroupState == "auto" {
		report.MLSGroupState = "absent"
		if report.ConversationStatePath != "" {
			if _, err := os.Stat(report.ConversationStatePath); err == nil {
				report.MLSGroupState = "present"
			} else if !os.IsNotExist(err) {
				report.MLSGroupState = "unknown"
				report.RefusalReasons = append(report.RefusalReasons, "conversation state path could not be inspected")
			}
		}
	}

	kp, kpPresent, err := readB7KeyPackageReceipt(report.KeyPackageReceiptPath)
	if err != nil {
		report.Classification = "unsupported_or_unknown_state_version"
		report.Action = "refuse"
		report.RefusalReasons = append(report.RefusalReasons, err.Error())
		return report, nil
	}
	report.KeyPackageReceiptPresent = kpPresent
	if kpPresent {
		report.KeyPackageReceiptPersisted = kp.LocalReceiptPersisted
		report.KeyPackageAcked = kp.KeyPackageAcked
		if kp.RelaySpaceID != "" && kp.RelaySpaceID != report.RelaySpaceID {
			report.ReceiptRelaySpaceMismatch = true
		}
		if kp.RecipientDeviceID != "" && kp.RecipientDeviceID != report.LocalDeviceID {
			report.ReceiptDeviceMismatch = true
		}
		if !kp.LocalReceiptPersisted {
			report.RefusalReasons = append(report.RefusalReasons, "KeyPackage receipt is incomplete")
		}
		if kp.AddMemberRun || kp.WelcomeSubmitted || kp.TrustOrCandidateStateMutated {
			report.RefusalReasons = append(report.RefusalReasons, "KeyPackage receipt contains impossible B5d nonclaim mutation")
		}
	}

	wr, wrPresent, err := readB7WelcomeReceipt(report.WelcomeReceiptPath)
	if err != nil {
		report.Classification = "unsupported_or_unknown_state_version"
		report.Action = "refuse"
		report.RefusalReasons = append(report.RefusalReasons, err.Error())
		return report, nil
	}
	report.WelcomeReceiptPresent = wrPresent
	if wrPresent {
		report.WelcomePersisted = wr.LocalWelcomePersisted
		report.WelcomeJoined = wr.Joined
		report.WelcomeAcked = wr.WelcomeAcked
		if wr.RelaySpaceID != "" && wr.RelaySpaceID != report.RelaySpaceID {
			report.ReceiptRelaySpaceMismatch = true
		}
		if wr.RecipientDeviceID != "" && wr.RecipientDeviceID != report.LocalDeviceID {
			report.ReceiptDeviceMismatch = true
		}
		if report.SidecarDeviceLabel != "" && wr.SidecarDeviceLabel != "" && wr.SidecarDeviceLabel != report.SidecarDeviceLabel {
			report.SidecarDeviceLabelMismatch = true
		}
		if report.ConversationLabel != "" && wr.ConversationLabel != "" && wr.ConversationLabel != report.ConversationLabel {
			report.ConversationLabelMismatch = true
		}
		if wr.TrustOrCandidateStateMutated || wr.VerifiedIdentityClaimed || wr.CypherMLSReconciled || wr.PublicDirectoryMutated {
			report.RefusalReasons = append(report.RefusalReasons, "Welcome receipt contains impossible B6 nonclaim mutation")
		}
		if wr.LocalWelcomePersisted && !wr.Joined {
			report.RefusalReasons = append(report.RefusalReasons, "Welcome receipt is persisted but not joined")
		}
	}

	switch {
	case report.ReceiptDeviceMismatch:
		report.Classification = "local_device_id_mismatch"
		report.Action = "refuse"
	case report.SidecarDeviceLabelMismatch:
		report.Classification = "sidecar_device_label_mismatch"
		report.Action = "refuse"
	case report.ConversationLabelMismatch:
		report.Classification = "conversation_label_mismatch"
		report.Action = "refuse"
	case report.ReceiptRelaySpaceMismatch:
		report.Classification = "mls_conversation_present_wrong_relay_space"
		report.Action = "refuse"
	case containsIncompleteReason(report.RefusalReasons):
		report.Classification = "incomplete_local_consume_or_join"
		report.Action = "refuse"
	case report.CypherMemberState == "active" && report.MLSGroupState == "absent":
		report.Classification = "relay_member_active_but_mls_group_absent"
		report.Action = "refuse"
	case isInactiveCypherMemberState(report.CypherMemberState) && wrPresent && wr.Joined:
		report.Classification = "welcome_receipt_joined_but_cypher_member_inactive"
		report.Action = "refuse"
	case isInactiveCypherMemberState(report.CypherMemberState) && kpPresent && kp.LocalReceiptPersisted:
		report.Classification = "keypackage_receipt_exists_but_cypher_member_inactive"
		report.Action = "refuse"
	case isInactiveCypherMemberState(report.CypherMemberState) && report.MLSGroupState == "present":
		report.Classification = "relay_member_inactive_but_mls_group_present"
		report.Action = "refuse"
	case report.CypherMemberState == "active" && report.MLSGroupState == "present":
		report.Classification = "aligned"
		report.Action = "allow"
	case report.CypherMemberState == "pending" || report.MLSGroupState == "unknown" || report.CypherMemberState == "unknown":
		report.Classification = "stale_or_ambiguous"
		report.Action = "refuse"
	default:
		report.Classification = "unsupported_or_unknown_state_version"
		report.Action = "refuse"
	}

	if report.Action == "refuse" && len(report.RefusalReasons) == 0 {
		report.RefusalReasons = append(report.RefusalReasons, "Cypher routing membership and local MLS state are not aligned")
	}
	return report, nil
}

func normalizeCypherMemberState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "active":
		return "active"
	case "disabled", "left", "absent", "removed":
		if strings.ToLower(strings.TrimSpace(value)) == "removed" {
			return "absent"
		}
		return strings.ToLower(strings.TrimSpace(value))
	case "pending":
		return "pending"
	case "unknown", "":
		return "unknown"
	default:
		return "unsupported"
	}
}

func normalizeMLSGroupState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "present", "joined", "exists":
		return "present"
	case "absent", "missing":
		return "absent"
	case "auto", "":
		return "auto"
	case "unknown":
		return "unknown"
	default:
		return "unsupported"
	}
}

func isInactiveCypherMemberState(value string) bool {
	return value == "disabled" || value == "left" || value == "absent"
}

func containsIncompleteReason(reasons []string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, "incomplete") || strings.Contains(reason, "not joined") || strings.Contains(reason, "impossible") {
			return true
		}
	}
	return false
}

func readB7KeyPackageReceipt(path string) (b7KeyPackageReceipt, bool, error) {
	var receipt b7KeyPackageReceipt
	if strings.TrimSpace(path) == "" {
		return receipt, false, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return receipt, false, fmt.Errorf("read KeyPackage receipt: %w", err)
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		return receipt, false, fmt.Errorf("decode KeyPackage receipt: %w", err)
	}
	if receipt.SchemaVersion != "" && receipt.SchemaVersion != "carbonstack-keypackage-consume-receipt/v0" {
		return receipt, true, fmt.Errorf("unsupported KeyPackage receipt schema: %s", receipt.SchemaVersion)
	}
	return receipt, true, nil
}

func readB7WelcomeReceipt(path string) (b7WelcomeReceipt, bool, error) {
	var receipt b7WelcomeReceipt
	if strings.TrimSpace(path) == "" {
		return receipt, false, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return receipt, false, fmt.Errorf("read Welcome receipt: %w", err)
	}
	if err := json.Unmarshal(body, &receipt); err != nil {
		return receipt, false, fmt.Errorf("decode Welcome receipt: %w", err)
	}
	if receipt.SchemaVersion != "" && receipt.SchemaVersion != "carbonstack-welcome-consume-receipt/v0" {
		return receipt, true, fmt.Errorf("unsupported Welcome receipt schema: %s", receipt.SchemaVersion)
	}
	return receipt, true, nil
}

func printCypherMLSMismatchReport(report cypherMLSMismatchReport) {
	fmt.Println("openmls cypher mls mismatch inspect dev")
	fmt.Println("command: openmls-cypher-mls-mismatch-inspect-dev")
	fmt.Printf("classification: %s\n", report.Classification)
	fmt.Printf("action: %s\n", report.Action)
	fmt.Printf("relay_space_id: %s\n", report.RelaySpaceID)
	fmt.Printf("local_device_id: %s\n", report.LocalDeviceID)
	fmt.Printf("cypher_member_state: %s\n", report.CypherMemberState)
	fmt.Printf("mls_group_state: %s\n", report.MLSGroupState)
	if report.SidecarDeviceLabel != "" {
		fmt.Printf("sidecar_device_label: %s\n", report.SidecarDeviceLabel)
	}
	if report.ConversationLabel != "" {
		fmt.Printf("conversation_label: %s\n", report.ConversationLabel)
	}
	if report.ConversationStatePath != "" {
		fmt.Printf("conversation_state_path: %s\n", report.ConversationStatePath)
	}
	if report.KeyPackageReceiptPath != "" {
		fmt.Printf("keypackage_receipt_path: %s\n", report.KeyPackageReceiptPath)
	}
	if report.WelcomeReceiptPath != "" {
		fmt.Printf("welcome_receipt_path: %s\n", report.WelcomeReceiptPath)
	}
	fmt.Printf("keypackage_receipt_present: %t\n", report.KeyPackageReceiptPresent)
	fmt.Printf("welcome_receipt_present: %t\n", report.WelcomeReceiptPresent)
	fmt.Printf("keypackage_receipt_persisted: %t\n", report.KeyPackageReceiptPersisted)
	fmt.Printf("welcome_persisted: %t\n", report.WelcomePersisted)
	fmt.Printf("welcome_joined: %t\n", report.WelcomeJoined)
	fmt.Printf("welcome_acked: %t\n", report.WelcomeAcked)
	fmt.Printf("receipt_relay_space_mismatch: %t\n", report.ReceiptRelaySpaceMismatch)
	fmt.Printf("receipt_device_mismatch: %t\n", report.ReceiptDeviceMismatch)
	fmt.Printf("sidecar_device_label_mismatch: %t\n", report.SidecarDeviceLabelMismatch)
	fmt.Printf("conversation_label_mismatch: %t\n", report.ConversationLabelMismatch)
	for _, reason := range report.RefusalReasons {
		fmt.Printf("refusal_reason: %s\n", reason)
	}
	fmt.Printf("no_silent_repair: %t\n", report.NoSilentRepair)
	fmt.Printf("no_silent_rejoin: %t\n", report.NoSilentRejoin)
	fmt.Printf("trust_or_candidate_state_mutated: %t\n", report.TrustOrCandidateStateMutated)
	fmt.Printf("verified_identity_claimed: %t\n", report.VerifiedIdentityClaimed)
	fmt.Printf("cypher_mls_reconciled: %t\n", report.CypherMLSReconciled)
	fmt.Printf("public_directory_mutated: %t\n", report.PublicDirectoryMutated)
	fmt.Println("warning: dev/pre-alpha mismatch inspection/refusal only; does not repair, rejoin, verify identity, promote trust, or reconcile Cypher and MLS state")
}
