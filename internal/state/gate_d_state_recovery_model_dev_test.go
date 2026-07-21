package state

import (
	"testing"
	"time"
)

func TestGateDStateRecoveryReportClassifiesSafeNonSecretDryRun(t *testing.T) {
	report, err := BuildGateDStateRecoveryReport(
		"gate-d-test",
		[]GateDStateDomainInput{{
			RepoOrComponent:    "carbonstack-comms",
			StateDomain:        "state-substrate-inventory",
			StatePathOrLocator: "generated/report.json",
			StateRoot:          "/tmp/carbonstack-state",
			ExistingCode:       true,
		}},
		time.Date(2026, 7, 21, 16, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatalf("BuildGateDStateRecoveryReport: %v", err)
	}
	if report.SchemaVersion != GateDStateRecoveryModelSchema {
		t.Fatalf("unexpected schema: %s", report.SchemaVersion)
	}
	if len(report.StateInventory) != 1 {
		t.Fatalf("unexpected inventory count: %d", len(report.StateInventory))
	}
	item := report.StateInventory[0]
	if item.RestoreClassification != GateDClassificationSafeNonSecretDryRun {
		t.Fatalf("restore classification = %s", item.RestoreClassification)
	}
	if item.MigrationCompatibilityClassification != GateDClassificationSafeNonSecretDryRun {
		t.Fatalf("migration classification = %s", item.MigrationCompatibilityClassification)
	}
}

func TestGateDStateRecoveryBlocksSecretBearingRestore(t *testing.T) {
	item := ClassifyGateDStateDomain(GateDStateDomainInput{RepoOrComponent: "carbonstack-comms", StateDomain: "openmls-provider-state", StatePathOrLocator: "sidecar/provider", StateRoot: "/tmp/carbonstack-state", SecretBearing: true, FutureVaultRequired: true})
	if item.RestoreClassification != GateDClassificationBlockedSecretBearing {
		t.Fatalf("secret restore classification = %s", item.RestoreClassification)
	}
	if item.BackupManifestClassification != GateDClassificationBlockedSecretBearing {
		t.Fatalf("secret backup classification = %s", item.BackupManifestClassification)
	}
	if item.RefusalOrWarning == "" {
		t.Fatal("expected refusal/warning for secret-bearing state")
	}
}

func TestGateDStateRecoveryReferencesTrustWithoutImportingIt(t *testing.T) {
	item := ClassifyGateDStateDomain(GateDStateDomainInput{RepoOrComponent: "carbonstack-comms", StateDomain: "local-trust-candidate-state", StatePathOrLocator: "trust/candidate.json", StateRoot: "/tmp/carbonstack-state", ReferencesTrustCandidate: true, ReferencesChangedLineage: true, ReferencesDemotionRevocation: true, ExistingCode: true})
	if item.TrustCandidateStateReference != "referenced_inventory_only_not_backup_target" {
		t.Fatalf("unexpected trust reference: %s", item.TrustCandidateStateReference)
	}
	if item.ChangedLineageWarningReference != "referenced_warning_only_not_repair_target" {
		t.Fatalf("unexpected changed lineage reference: %s", item.ChangedLineageWarningReference)
	}
	if item.DemotionOrRevocationReference != "referenced_event_only_not_restore_authority" {
		t.Fatalf("unexpected demotion/revocation reference: %s", item.DemotionOrRevocationReference)
	}
}

func TestGateDStateRecoveryNonclaimsRemainFalse(t *testing.T) {
	for key, value := range GateDStateRecoveryClaims() {
		if value {
			t.Fatalf("Gate D claim %s unexpectedly true", key)
		}
	}
}
