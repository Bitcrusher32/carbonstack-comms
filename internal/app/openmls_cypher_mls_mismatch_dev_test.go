package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCypherMLSMismatchAligned(t *testing.T) {
	report, err := evaluateCypherMLSMismatch(cypherMLSMismatchInput{
		RelaySpaceID:      "rs",
		LocalDeviceID:     "dev",
		CypherMemberState: "active",
		MLSGroupState:     "present",
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != "aligned" || report.Action != "allow" {
		t.Fatalf("classification=%q action=%q", report.Classification, report.Action)
	}
	if report.CypherMLSReconciled || report.TrustOrCandidateStateMutated || report.VerifiedIdentityClaimed {
		t.Fatalf("nonclaim mutated: %+v", report)
	}
}

func TestCypherMLSMismatchActiveButMLSAbsent(t *testing.T) {
	report, err := evaluateCypherMLSMismatch(cypherMLSMismatchInput{
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

func TestCypherMLSMismatchWelcomeJoinedButCypherInactive(t *testing.T) {
	tmp := t.TempDir()
	receiptPath := filepath.Join(tmp, "welcome-receipt.json")
	writeJSON(t, receiptPath, b7WelcomeReceipt{
		SchemaVersion:         "carbonstack-welcome-consume-receipt/v0",
		RelaySpaceID:          "rs",
		RecipientDeviceID:     "dev",
		SidecarDeviceLabel:    "bob",
		ConversationLabel:     "conv",
		LocalWelcomePersisted: true,
		Joined:                true,
		WelcomeAcked:          true,
	})

	report, err := evaluateCypherMLSMismatch(cypherMLSMismatchInput{
		RelaySpaceID:       "rs",
		LocalDeviceID:      "dev",
		CypherMemberState:  "disabled",
		MLSGroupState:      "present",
		SidecarDeviceLabel: "bob",
		ConversationLabel:  "conv",
		WelcomeReceiptPath: receiptPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != "welcome_receipt_joined_but_cypher_member_inactive" || report.Action != "refuse" {
		t.Fatalf("classification=%q action=%q", report.Classification, report.Action)
	}
}

func TestCypherMLSMismatchKeyPackageReceiptButCypherInactive(t *testing.T) {
	tmp := t.TempDir()
	receiptPath := filepath.Join(tmp, "keypackage-receipt.json")
	writeJSON(t, receiptPath, b7KeyPackageReceipt{
		SchemaVersion:         "carbonstack-keypackage-consume-receipt/v0",
		RelaySpaceID:          "rs",
		RecipientDeviceID:     "dev",
		LocalReceiptPersisted: true,
		KeyPackageAcked:       true,
	})

	report, err := evaluateCypherMLSMismatch(cypherMLSMismatchInput{
		RelaySpaceID:          "rs",
		LocalDeviceID:         "dev",
		CypherMemberState:     "left",
		MLSGroupState:         "absent",
		KeyPackageReceiptPath: receiptPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != "keypackage_receipt_exists_but_cypher_member_inactive" || report.Action != "refuse" {
		t.Fatalf("classification=%q action=%q", report.Classification, report.Action)
	}
}

func TestCypherMLSMismatchReceiptDeviceMismatch(t *testing.T) {
	tmp := t.TempDir()
	receiptPath := filepath.Join(tmp, "welcome-receipt.json")
	writeJSON(t, receiptPath, b7WelcomeReceipt{
		SchemaVersion:         "carbonstack-welcome-consume-receipt/v0",
		RelaySpaceID:          "rs",
		RecipientDeviceID:     "other-dev",
		SidecarDeviceLabel:    "bob",
		ConversationLabel:     "conv",
		LocalWelcomePersisted: true,
		Joined:                true,
	})

	report, err := evaluateCypherMLSMismatch(cypherMLSMismatchInput{
		RelaySpaceID:       "rs",
		LocalDeviceID:      "dev",
		CypherMemberState:  "active",
		MLSGroupState:      "present",
		WelcomeReceiptPath: receiptPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != "local_device_id_mismatch" || report.Action != "refuse" {
		t.Fatalf("classification=%q action=%q", report.Classification, report.Action)
	}
}

func TestCypherMLSMismatchIncompleteWelcomeReceipt(t *testing.T) {
	tmp := t.TempDir()
	receiptPath := filepath.Join(tmp, "welcome-receipt.json")
	writeJSON(t, receiptPath, b7WelcomeReceipt{
		SchemaVersion:         "carbonstack-welcome-consume-receipt/v0",
		RelaySpaceID:          "rs",
		RecipientDeviceID:     "dev",
		SidecarDeviceLabel:    "bob",
		ConversationLabel:     "conv",
		LocalWelcomePersisted: true,
		Joined:                false,
	})

	report, err := evaluateCypherMLSMismatch(cypherMLSMismatchInput{
		RelaySpaceID:       "rs",
		LocalDeviceID:      "dev",
		CypherMemberState:  "active",
		MLSGroupState:      "present",
		WelcomeReceiptPath: receiptPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != "incomplete_local_consume_or_join" || report.Action != "refuse" {
		t.Fatalf("classification=%q action=%q", report.Classification, report.Action)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
