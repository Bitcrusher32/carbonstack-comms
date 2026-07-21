package adversarial

import "testing"

func TestGateERelayOnboardingCasesFrozen(t *testing.T) {
	ids := GateERelayOnboardingCaseIDs()
	if len(ids) != 17 {
		t.Fatalf("expected 17 Gate E cases, got %d", len(ids))
	}
	required := []string{"ADV-RELAY-KEYPACKAGE-STALE-001", "ADV-RELAY-WELCOME-WRONG-DEVICE-001", "ADV-RELAY-CYPHER-MLS-MEMBERSHIP-MISMATCH-001", "ADV-RELAY-ACK-AFTER-FAILED-JOIN-001", "ADV-RELAY-LOCAL-STATE-ROLLBACK-ONBOARDING-001"}
	got := map[string]bool{}
	for _, id := range ids {
		got[id] = true
	}
	for _, id := range required {
		if !got[id] {
			t.Fatalf("missing required Gate E case %s", id)
		}
	}
}

func TestGateERelayOnboardingReportBuilds(t *testing.T) {
	report, err := BuildGateERelayOnboardingReport("gate-e-test")
	if err != nil {
		t.Fatalf("BuildGateERelayOnboardingReport: %v", err)
	}
	if report.SchemaVersion != GateERelayOnboardingReportSchema {
		t.Fatalf("unexpected schema: %s", report.SchemaVersion)
	}
	for _, c := range report.Cases {
		if c.CaseStatus != "classified_from_existing_coverage" {
			t.Fatalf("case %s unexpectedly status %s", c.CaseID, c.CaseStatus)
		}
	}
}

func TestGateERelayOnboardingNonclaimsRemainFalse(t *testing.T) {
	for key, value := range GateERelayOnboardingClaims() {
		if value {
			t.Fatalf("Gate E claim %s unexpectedly true", key)
		}
	}
}
