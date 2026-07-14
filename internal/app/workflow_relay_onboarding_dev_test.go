package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func TestWorkflowRelayOnboardingReady(t *testing.T) {
	tmp := t.TempDir()
	kp := filepath.Join(tmp, "kp.json")
	wr := filepath.Join(tmp, "welcome.json")
	writeWorkflowJSON(t, kp, b7KeyPackageReceipt{
		SchemaVersion:         "carbonstack-keypackage-consume-receipt/v0",
		RelaySpaceID:          "rs",
		RecipientDeviceID:     "dev",
		LocalReceiptPersisted: true,
		KeyPackageAcked:       true,
	})
	writeWorkflowJSON(t, wr, b7WelcomeReceipt{
		SchemaVersion:         "carbonstack-welcome-consume-receipt/v0",
		RelaySpaceID:          "rs",
		RecipientDeviceID:     "dev",
		SidecarDeviceLabel:    "bob",
		ConversationLabel:     "conv",
		LocalWelcomePersisted: true,
		Joined:                true,
		WelcomeAcked:          true,
	})

	report, err := evaluateWorkflowRelayOnboarding(workflowRelayOnboardingInput{
		WorkflowID:            "wf",
		RelaySpaceID:          "rs",
		LocalDeviceID:         "dev",
		CypherMemberState:     "active",
		MLSGroupState:         "present",
		SidecarDeviceLabel:    "bob",
		ConversationLabel:     "conv",
		KeyPackageReceiptPath: kp,
		WelcomeReceiptPath:    wr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != "workflow_ready" || report.Action != "allow" {
		t.Fatalf("classification=%q action=%q", report.Classification, report.Action)
	}
	if report.CypherMLSReconciled || report.TrustOrCandidateStateMutated || report.VerifiedIdentityClaimed || report.B9GateBClosureClaimed {
		t.Fatalf("nonclaim mutated: %+v", report)
	}
}

func TestWorkflowRelayOnboardingRefusesB7Mismatch(t *testing.T) {
	report, err := evaluateWorkflowRelayOnboarding(workflowRelayOnboardingInput{
		WorkflowID:        "wf",
		RelaySpaceID:      "rs",
		LocalDeviceID:     "dev",
		CypherMemberState: "active",
		MLSGroupState:     "absent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != "relay_member_active_but_mls_group_absent" || report.Action != "refuse" {
		t.Fatalf("classification=%q action=%q", report.Classification, report.Action)
	}
}

func TestWorkflowRelayOnboardingPartialMissingWelcome(t *testing.T) {
	tmp := t.TempDir()
	kp := filepath.Join(tmp, "kp.json")
	writeWorkflowJSON(t, kp, b7KeyPackageReceipt{
		SchemaVersion:         "carbonstack-keypackage-consume-receipt/v0",
		RelaySpaceID:          "rs",
		RecipientDeviceID:     "dev",
		LocalReceiptPersisted: true,
		KeyPackageAcked:       true,
	})

	report, err := evaluateWorkflowRelayOnboarding(workflowRelayOnboardingInput{
		WorkflowID:            "wf",
		RelaySpaceID:          "rs",
		LocalDeviceID:         "dev",
		CypherMemberState:     "active",
		MLSGroupState:         "present",
		KeyPackageReceiptPath: kp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != "partial_onboarding_state" || report.Action != "refuse" {
		t.Fatalf("classification=%q action=%q", report.Classification, report.Action)
	}
}

func TestWorkflowRelayOnboardingWritesAndReplaysReport(t *testing.T) {
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	reportRoot := filepath.Join(tmp, "reports")
	kp := filepath.Join(tmp, "kp.json")
	wr := filepath.Join(tmp, "welcome.json")

	writeWorkflowJSON(t, kp, b7KeyPackageReceipt{
		SchemaVersion:         "carbonstack-keypackage-consume-receipt/v0",
		RelaySpaceID:          "rs",
		RecipientDeviceID:     "dev",
		LocalReceiptPersisted: true,
		KeyPackageAcked:       true,
	})
	writeWorkflowJSON(t, wr, b7WelcomeReceipt{
		SchemaVersion:         "carbonstack-welcome-consume-receipt/v0",
		RelaySpaceID:          "rs",
		RecipientDeviceID:     "dev",
		SidecarDeviceLabel:    "bob",
		ConversationLabel:     "conv",
		LocalWelcomePersisted: true,
		Joined:                true,
		WelcomeAcked:          true,
	})

	if err := state.Save(statePath, state.State{
		ServerURL: "http://127.0.0.1:1",
		AccountID: "acct",
		DeviceID:  "dev",
	}); err != nil {
		t.Fatal(err)
	}

	args := []string{
		"--state", statePath,
		"--workflow-id", "wf-report",
		"--relay-space", "rs",
		"--cypher-member-state", "active",
		"--mls-group-state", "present",
		"--sidecar-device-label", "bob",
		"--conversation", "conv",
		"--keypackage-receipt", kp,
		"--welcome-receipt", wr,
		"--report-root", reportRoot,
	}
	if err := cmdWorkflowRelayOnboardingDev(args); err != nil {
		t.Fatal(err)
	}
	if err := cmdWorkflowRelayOnboardingDev(args); err != nil {
		t.Fatal(err)
	}

	reportPath := workflowRelayOnboardingReportPath(reportRoot, "wf-report")
	report, ok, err := loadWorkflowRelayOnboardingReport(reportPath)
	if err != nil || !ok {
		t.Fatalf("load report ok=%v err=%v", ok, err)
	}
	if report.Classification != "workflow_ready" || report.Action != "allow" {
		t.Fatalf("classification=%q action=%q", report.Classification, report.Action)
	}
}

func writeWorkflowJSON(t *testing.T, path string, v any) {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
