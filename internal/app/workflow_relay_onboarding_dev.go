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

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

const workflowRelayOnboardingReportSchema = "carbonstack-workflow-relay-onboarding-report/v0"

type workflowRelayOnboardingInput struct {
	WorkflowID            string
	RelaySpaceID          string
	LocalDeviceID         string
	CypherMemberState     string
	MLSGroupState         string
	SidecarDir            string
	SidecarDeviceLabel    string
	ConversationLabel     string
	ConversationStatePath string
	KeyPackageReceiptPath string
	WelcomeReceiptPath    string
	ReportRoot            string
	AllowRefusalExitZero  bool
}

type workflowRelayOnboardingStage struct {
	Name           string   `json:"name"`
	Status         string   `json:"status"`
	Classification string   `json:"classification"`
	Action         string   `json:"action"`
	EvidencePath   string   `json:"evidence_path,omitempty"`
	RefusalReasons []string `json:"refusal_reasons,omitempty"`
}

type workflowRelayOnboardingReport struct {
	SchemaVersion                   string                         `json:"schema_version"`
	Command                         string                         `json:"command"`
	WorkflowID                      string                         `json:"workflow_id"`
	Classification                  string                         `json:"classification"`
	Action                          string                         `json:"action"`
	RelaySpaceID                    string                         `json:"relay_space_id"`
	LocalDeviceID                   string                         `json:"local_device_id"`
	CypherMemberState               string                         `json:"cypher_member_state"`
	MLSGroupState                   string                         `json:"mls_group_state"`
	SidecarDeviceLabel              string                         `json:"sidecar_device_label,omitempty"`
	ConversationLabel               string                         `json:"conversation_label,omitempty"`
	ConversationStatePath           string                         `json:"conversation_state_path,omitempty"`
	KeyPackageReceiptPath           string                         `json:"keypackage_receipt_path,omitempty"`
	WelcomeReceiptPath              string                         `json:"welcome_receipt_path,omitempty"`
	ReportPath                      string                         `json:"report_path,omitempty"`
	CreatedAt                       string                         `json:"created_at"`
	Stages                          []workflowRelayOnboardingStage `json:"stages"`
	CypherMLSMismatchClassification string                         `json:"cypher_mls_mismatch_classification"`
	CypherMLSMismatchAction         string                         `json:"cypher_mls_mismatch_action"`
	KeyPackageReceiptPresent        bool                           `json:"keypackage_receipt_present"`
	KeyPackageReceiptPersisted      bool                           `json:"keypackage_receipt_persisted"`
	KeyPackageAcked                 bool                           `json:"keypackage_acked"`
	WelcomeReceiptPresent           bool                           `json:"welcome_receipt_present"`
	WelcomePersisted                bool                           `json:"welcome_persisted"`
	WelcomeJoined                   bool                           `json:"welcome_joined"`
	WelcomeAcked                    bool                           `json:"welcome_acked"`
	ReplayClassification            string                         `json:"replay_classification,omitempty"`
	NoSilentRepair                  bool                           `json:"no_silent_repair"`
	NoSilentRejoin                  bool                           `json:"no_silent_rejoin"`
	LeafBoundariesPreserved         bool                           `json:"leaf_boundaries_preserved"`
	TrustOrCandidateStateMutated    bool                           `json:"trust_or_candidate_state_mutated"`
	VerifiedIdentityClaimed         bool                           `json:"verified_identity_claimed"`
	CypherMLSReconciled             bool                           `json:"cypher_mls_reconciled"`
	PublicDirectoryMutated          bool                           `json:"public_directory_mutated"`
	B9GateBClosureClaimed           bool                           `json:"b9_gate_b_closure_claimed"`
}

func cmdWorkflowRelayOnboardingDev(args []string) error {
	fs := flag.NewFlagSet("workflow-relay-onboarding-dev", flag.ContinueOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local Comms state path")
	workflowID := fs.String("workflow-id", "", "stable workflow report ID; default derives from relay/device/conversation")
	relaySpaceID := fs.String("relay-space", "", "Relay Space ID being evaluated")
	cypherMemberState := fs.String("cypher-member-state", "", "explicit Cypher Relay Space member-state snapshot")
	mlsGroupState := fs.String("mls-group-state", "auto", "local MLS group state snapshot: present, absent, unknown, or auto")
	sidecarDir := fs.String("sidecar-dir", defaultOpenMLSSidecarDir, "OpenMLS sidecar directory")
	sidecarDeviceLabel := fs.String("sidecar-device-label", "", "OpenMLS sidecar device label")
	conversationLabel := fs.String("conversation", "", "OpenMLS conversation label")
	conversationStatePath := fs.String("conversation-state", "", "explicit OpenMLS conversation-state path")
	keyPackageReceiptPath := fs.String("keypackage-receipt", "", "optional B5d KeyPackage receipt manifest")
	welcomeReceiptPath := fs.String("welcome-receipt", "", "optional B6 Welcome receipt manifest")
	reportRoot := fs.String("report-root", "", "workflow report root; defaults beside the Comms state file")
	allowRefusalExitZero := fs.Bool("allow-refusal-exit-zero", false, "print refusal report but return exit 0 for reporting harnesses")
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

	root := strings.TrimSpace(*reportRoot)
	if root == "" {
		root = defaultWorkflowRelayOnboardingReportRoot(*statePath)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return fmt.Errorf("create workflow report root: %w", err)
	}

	convPath := strings.TrimSpace(*conversationStatePath)
	if convPath == "" && strings.TrimSpace(*sidecarDeviceLabel) != "" && strings.TrimSpace(*conversationLabel) != "" {
		convPath = filepath.Join(*sidecarDir, "devices", strings.TrimSpace(*sidecarDeviceLabel), "conversations", strings.TrimSpace(*conversationLabel), "conversation-state.json")
	}

	input := workflowRelayOnboardingInput{
		WorkflowID:            strings.TrimSpace(*workflowID),
		RelaySpaceID:          strings.TrimSpace(*relaySpaceID),
		LocalDeviceID:         s.DeviceID,
		CypherMemberState:     strings.TrimSpace(*cypherMemberState),
		MLSGroupState:         strings.TrimSpace(*mlsGroupState),
		SidecarDir:            strings.TrimSpace(*sidecarDir),
		SidecarDeviceLabel:    strings.TrimSpace(*sidecarDeviceLabel),
		ConversationLabel:     strings.TrimSpace(*conversationLabel),
		ConversationStatePath: convPath,
		KeyPackageReceiptPath: strings.TrimSpace(*keyPackageReceiptPath),
		WelcomeReceiptPath:    strings.TrimSpace(*welcomeReceiptPath),
		ReportRoot:            root,
		AllowRefusalExitZero:  *allowRefusalExitZero,
	}

	if input.WorkflowID == "" {
		input.WorkflowID = deriveWorkflowRelayOnboardingID(input)
	}
	reportPath := workflowRelayOnboardingReportPath(root, input.WorkflowID)

	if existing, ok, err := loadWorkflowRelayOnboardingReport(reportPath); err != nil {
		return err
	} else if ok {
		if err := validateExistingWorkflowRelayOnboardingReport(existing, input); err != nil {
			return err
		}
		existing.ReplayClassification = "already_reported"
		printWorkflowRelayOnboardingReport(existing)
		if existing.Action == "refuse" && !input.AllowRefusalExitZero {
			return fmt.Errorf("workflow_relay_onboarding_refusal: %s", existing.Classification)
		}
		return nil
	}

	report, err := evaluateWorkflowRelayOnboarding(input)
	if err != nil {
		return err
	}
	report.ReportPath = reportPath

	if err := writeWorkflowRelayOnboardingReportAtomic(reportPath, report); err != nil {
		return err
	}
	printWorkflowRelayOnboardingReport(report)

	if report.Action == "refuse" && !input.AllowRefusalExitZero {
		return fmt.Errorf("workflow_relay_onboarding_refusal: %s", report.Classification)
	}
	return nil
}

func evaluateWorkflowRelayOnboarding(input workflowRelayOnboardingInput) (workflowRelayOnboardingReport, error) {
	report := workflowRelayOnboardingReport{
		SchemaVersion:                workflowRelayOnboardingReportSchema,
		Command:                      "workflow-relay-onboarding-dev",
		WorkflowID:                   strings.TrimSpace(input.WorkflowID),
		RelaySpaceID:                 strings.TrimSpace(input.RelaySpaceID),
		LocalDeviceID:                strings.TrimSpace(input.LocalDeviceID),
		CypherMemberState:            normalizeCypherMemberState(input.CypherMemberState),
		MLSGroupState:                normalizeMLSGroupState(input.MLSGroupState),
		SidecarDeviceLabel:           strings.TrimSpace(input.SidecarDeviceLabel),
		ConversationLabel:            strings.TrimSpace(input.ConversationLabel),
		ConversationStatePath:        strings.TrimSpace(input.ConversationStatePath),
		KeyPackageReceiptPath:        strings.TrimSpace(input.KeyPackageReceiptPath),
		WelcomeReceiptPath:           strings.TrimSpace(input.WelcomeReceiptPath),
		CreatedAt:                    time.Now().UTC().Format(time.RFC3339),
		NoSilentRepair:               true,
		NoSilentRejoin:               true,
		LeafBoundariesPreserved:      true,
		TrustOrCandidateStateMutated: false,
		VerifiedIdentityClaimed:      false,
		CypherMLSReconciled:          false,
		PublicDirectoryMutated:       false,
		B9GateBClosureClaimed:        false,
	}

	if report.WorkflowID == "" {
		report.WorkflowID = deriveWorkflowRelayOnboardingID(input)
	}
	if report.RelaySpaceID == "" {
		return report, errors.New("relay_space_required")
	}
	if report.LocalDeviceID == "" {
		return report, errors.New("local_device_required")
	}

	report.Stages = append(report.Stages, workflowRelayOnboardingStage{
		Name:           "state_ready",
		Status:         "complete",
		Classification: "ready_device_state_loaded",
		Action:         "allow",
	})

	b7Report, err := evaluateCypherMLSMismatch(cypherMLSMismatchInput{
		RelaySpaceID:          report.RelaySpaceID,
		LocalDeviceID:         report.LocalDeviceID,
		CypherMemberState:     report.CypherMemberState,
		MLSGroupState:         report.MLSGroupState,
		SidecarDeviceLabel:    report.SidecarDeviceLabel,
		ConversationLabel:     report.ConversationLabel,
		ConversationStatePath: report.ConversationStatePath,
		KeyPackageReceiptPath: report.KeyPackageReceiptPath,
		WelcomeReceiptPath:    report.WelcomeReceiptPath,
		AllowRefusalExitZero:  true,
	})
	if err != nil {
		return report, err
	}

	report.CypherMLSMismatchClassification = b7Report.Classification
	report.CypherMLSMismatchAction = b7Report.Action
	report.MLSGroupState = b7Report.MLSGroupState
	report.KeyPackageReceiptPresent = b7Report.KeyPackageReceiptPresent
	report.KeyPackageReceiptPersisted = b7Report.KeyPackageReceiptPersisted
	report.KeyPackageAcked = b7Report.KeyPackageAcked
	report.WelcomeReceiptPresent = b7Report.WelcomeReceiptPresent
	report.WelcomePersisted = b7Report.WelcomePersisted
	report.WelcomeJoined = b7Report.WelcomeJoined
	report.WelcomeAcked = b7Report.WelcomeAcked

	report.Stages = append(report.Stages, workflowRelayOnboardingStage{
		Name:           "cypher_mls_mismatch",
		Status:         stageStatusFromAction(b7Report.Action),
		Classification: b7Report.Classification,
		Action:         b7Report.Action,
		RefusalReasons: b7Report.RefusalReasons,
	})

	kpStage := workflowRelayOnboardingStage{
		Name:         "keypackage_receipt",
		EvidencePath: report.KeyPackageReceiptPath,
	}
	switch {
	case report.KeyPackageReceiptPath == "":
		kpStage.Status = "missing"
		kpStage.Classification = "keypackage_receipt_missing"
		kpStage.Action = "refuse"
	case !report.KeyPackageReceiptPresent:
		kpStage.Status = "missing"
		kpStage.Classification = "keypackage_receipt_unreadable"
		kpStage.Action = "refuse"
	case !report.KeyPackageReceiptPersisted:
		kpStage.Status = "incomplete"
		kpStage.Classification = "keypackage_receipt_not_persisted"
		kpStage.Action = "refuse"
	case !report.KeyPackageAcked:
		kpStage.Status = "partial"
		kpStage.Classification = "keypackage_receipt_not_acked"
		kpStage.Action = "refuse"
	default:
		kpStage.Status = "complete"
		kpStage.Classification = "keypackage_receipt_ready"
		kpStage.Action = "allow"
	}
	report.Stages = append(report.Stages, kpStage)

	welcomeStage := workflowRelayOnboardingStage{
		Name:         "welcome_receipt",
		EvidencePath: report.WelcomeReceiptPath,
	}
	switch {
	case report.WelcomeReceiptPath == "":
		welcomeStage.Status = "missing"
		welcomeStage.Classification = "welcome_receipt_missing"
		welcomeStage.Action = "refuse"
	case !report.WelcomeReceiptPresent:
		welcomeStage.Status = "missing"
		welcomeStage.Classification = "welcome_receipt_unreadable"
		welcomeStage.Action = "refuse"
	case !report.WelcomePersisted:
		welcomeStage.Status = "incomplete"
		welcomeStage.Classification = "welcome_not_persisted"
		welcomeStage.Action = "refuse"
	case !report.WelcomeJoined:
		welcomeStage.Status = "partial"
		welcomeStage.Classification = "welcome_not_joined"
		welcomeStage.Action = "refuse"
	case !report.WelcomeAcked:
		welcomeStage.Status = "partial"
		welcomeStage.Classification = "welcome_not_acked"
		welcomeStage.Action = "refuse"
	default:
		welcomeStage.Status = "complete"
		welcomeStage.Classification = "welcome_receipt_ready"
		welcomeStage.Action = "allow"
	}
	report.Stages = append(report.Stages, welcomeStage)

	switch {
	case b7Report.Action == "refuse":
		report.Classification = b7Report.Classification
		report.Action = "refuse"
	case kpStage.Action == "refuse" || welcomeStage.Action == "refuse":
		report.Classification = "partial_onboarding_state"
		report.Action = "refuse"
	default:
		report.Classification = "workflow_ready"
		report.Action = "allow"
	}

	report.Stages = append(report.Stages, workflowRelayOnboardingStage{
		Name:           "workflow_result",
		Status:         stageStatusFromAction(report.Action),
		Classification: report.Classification,
		Action:         report.Action,
	})
	return report, nil
}

func stageStatusFromAction(action string) string {
	if action == "allow" {
		return "complete"
	}
	return "refused"
}

func defaultWorkflowRelayOnboardingReportRoot(statePath string) string {
	dir := filepath.Dir(statePath)
	if dir == "." || dir == "" {
		dir = ".carbonstack-comms"
	}
	return filepath.Join(dir, "workflow-reports")
}

func deriveWorkflowRelayOnboardingID(input workflowRelayOnboardingInput) string {
	material := strings.Join([]string{
		input.RelaySpaceID,
		input.LocalDeviceID,
		input.SidecarDeviceLabel,
		input.ConversationLabel,
		input.KeyPackageReceiptPath,
		input.WelcomeReceiptPath,
	}, "\x00")
	sum := sha256.Sum256([]byte(material))
	return "workflow-" + hex.EncodeToString(sum[:])[:24]
}

func workflowRelayOnboardingReportPath(root string, workflowID string) string {
	return filepath.Join(root, safeWorkflowRelayOnboardingID(workflowID), "workflow-report.json")
}

func safeWorkflowRelayOnboardingID(value string) string {
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

func loadWorkflowRelayOnboardingReport(path string) (workflowRelayOnboardingReport, bool, error) {
	var report workflowRelayOnboardingReport
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return report, false, nil
	}
	if err != nil {
		return report, false, err
	}
	if err := json.Unmarshal(body, &report); err != nil {
		return report, false, fmt.Errorf("decode workflow report: %w", err)
	}
	if report.SchemaVersion != workflowRelayOnboardingReportSchema {
		return report, false, fmt.Errorf("unsupported workflow report schema: %s", report.SchemaVersion)
	}
	return report, true, nil
}

func validateExistingWorkflowRelayOnboardingReport(report workflowRelayOnboardingReport, input workflowRelayOnboardingInput) error {
	if report.WorkflowID != input.WorkflowID ||
		report.RelaySpaceID != input.RelaySpaceID ||
		report.LocalDeviceID != input.LocalDeviceID {
		return errors.New("workflow_report_conflict: report identity does not match requested workflow")
	}
	return nil
}

func writeWorkflowRelayOnboardingReportAtomic(path string, report workflowRelayOnboardingReport) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func printWorkflowRelayOnboardingReport(report workflowRelayOnboardingReport) {
	fmt.Println("workflow relay onboarding dev")
	fmt.Println("command: workflow-relay-onboarding-dev")
	fmt.Printf("workflow_id: %s\n", report.WorkflowID)
	if report.ReplayClassification != "" {
		fmt.Printf("replay_classification: %s\n", report.ReplayClassification)
	}
	fmt.Printf("classification: %s\n", report.Classification)
	fmt.Printf("action: %s\n", report.Action)
	fmt.Printf("relay_space_id: %s\n", report.RelaySpaceID)
	fmt.Printf("local_device_id: %s\n", report.LocalDeviceID)
	fmt.Printf("cypher_member_state: %s\n", report.CypherMemberState)
	fmt.Printf("mls_group_state: %s\n", report.MLSGroupState)
	fmt.Printf("cypher_mls_mismatch_classification: %s\n", report.CypherMLSMismatchClassification)
	fmt.Printf("cypher_mls_mismatch_action: %s\n", report.CypherMLSMismatchAction)
	fmt.Printf("keypackage_receipt_present: %t\n", report.KeyPackageReceiptPresent)
	fmt.Printf("keypackage_receipt_persisted: %t\n", report.KeyPackageReceiptPersisted)
	fmt.Printf("keypackage_acked: %t\n", report.KeyPackageAcked)
	fmt.Printf("welcome_receipt_present: %t\n", report.WelcomeReceiptPresent)
	fmt.Printf("welcome_persisted: %t\n", report.WelcomePersisted)
	fmt.Printf("welcome_joined: %t\n", report.WelcomeJoined)
	fmt.Printf("welcome_acked: %t\n", report.WelcomeAcked)
	fmt.Printf("report_path: %s\n", report.ReportPath)
	for _, stage := range report.Stages {
		fmt.Printf("stage: %s status=%s classification=%s action=%s\n", stage.Name, stage.Status, stage.Classification, stage.Action)
	}
	fmt.Printf("no_silent_repair: %t\n", report.NoSilentRepair)
	fmt.Printf("no_silent_rejoin: %t\n", report.NoSilentRejoin)
	fmt.Printf("leaf_boundaries_preserved: %t\n", report.LeafBoundariesPreserved)
	fmt.Printf("trust_or_candidate_state_mutated: %t\n", report.TrustOrCandidateStateMutated)
	fmt.Printf("verified_identity_claimed: %t\n", report.VerifiedIdentityClaimed)
	fmt.Printf("cypher_mls_reconciled: %t\n", report.CypherMLSReconciled)
	fmt.Printf("public_directory_mutated: %t\n", report.PublicDirectoryMutated)
	fmt.Printf("b9_gate_b_closure_claimed: %t\n", report.B9GateBClosureClaimed)
	fmt.Println("warning: dev/pre-alpha workflow report/evaluator only; does not repair, rejoin, verify identity, promote trust, reconcile Cypher/MLS, or close Gate B")
}
