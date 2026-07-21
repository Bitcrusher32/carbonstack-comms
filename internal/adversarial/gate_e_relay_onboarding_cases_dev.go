package adversarial

import (
	"errors"
	"sort"
	"strings"
)

const GateERelayOnboardingReportSchema = "carbonstack-gate-e-relay-onboarding-adversarial-report/v0"

type GateERelayOnboardingCase struct {
	CaseID             string `json:"case_id"`
	Label              string `json:"label"`
	Surface            string `json:"case_surface"`
	CaseStatus         string `json:"case_status"`
	FindingDisposition string `json:"finding_disposition"`
	Severity           string `json:"severity"`
}

type GateERelayOnboardingReport struct {
	SchemaVersion string                     `json:"schema_version"`
	ReportID      string                     `json:"report_id"`
	Cases         []GateERelayOnboardingCase `json:"cases"`
	Nonclaims     []string                   `json:"nonclaims"`
}

func GateERelayOnboardingCases() []GateERelayOnboardingCase {
	return []GateERelayOnboardingCase{
		{CaseID: "ADV-RELAY-KEYPACKAGE-STALE-001", Label: "stale KeyPackage", Surface: "keypackage", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-KEYPACKAGE-REPLAYED-001", Label: "replayed KeyPackage", Surface: "keypackage", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-KEYPACKAGE-WRONG-RECIPIENT-001", Label: "wrong-recipient KeyPackage", Surface: "keypackage", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-KEYPACKAGE-MALFORMED-ENVELOPE-001", Label: "malformed KeyPackage envelope", Surface: "keypackage", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-WELCOME-STALE-001", Label: "stale Welcome", Surface: "welcome", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-WELCOME-REPLAYED-001", Label: "replayed Welcome", Surface: "welcome", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-WELCOME-DUPLICATE-001", Label: "duplicate Welcome", Surface: "welcome", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-WELCOME-WRONG-GROUP-001", Label: "wrong-group Welcome", Surface: "welcome", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-WELCOME-WRONG-DEVICE-001", Label: "wrong-device Welcome", Surface: "welcome", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-CYPHER-MLS-MEMBERSHIP-MISMATCH-001", Label: "Cypher membership vs local MLS mismatch", Surface: "membership_mismatch", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-MEMBER-DISABLED-BEHAVIOR-001", Label: "disabled member behavior", Surface: "membership_state", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-MEMBER-LEFT-BEHAVIOR-001", Label: "left member behavior", Surface: "membership_state", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-ACK-AFTER-FAILED-JOIN-001", Label: "ACK after failed join/open", Surface: "ack_failure", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-SELECTIVE-WITHHOLDING-DROP-DELAY-REORDER-001", Label: "selective withholding/drop/delay/reorder", Surface: "delivery_ordering", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-METADATA-LIES-001", Label: "Relay metadata lies", Surface: "metadata", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-ROUTING-MEMBERSHIP-MUTATION-001", Label: "routing membership mutation", Surface: "routing_membership", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
		{CaseID: "ADV-RELAY-LOCAL-STATE-ROLLBACK-ONBOARDING-001", Label: "local state rollback interacting with onboarding", Surface: "rollback_onboarding", CaseStatus: "classified_from_existing_coverage", FindingDisposition: "nonclaim_preserved", Severity: "informational"},
	}
}

func BuildGateERelayOnboardingReport(reportID string) (GateERelayOnboardingReport, error) {
	reportID = strings.TrimSpace(reportID)
	if reportID == "" {
		return GateERelayOnboardingReport{}, errors.New("report ID is required")
	}
	cases := GateERelayOnboardingCases()
	if len(cases) != 17 {
		return GateERelayOnboardingReport{}, errors.New("Gate E must keep exactly 17 frozen cases")
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if c.CaseID == "" || c.Label == "" || c.Surface == "" || c.CaseStatus == "" {
			return GateERelayOnboardingReport{}, errors.New("Gate E case has empty required field")
		}
		if seen[c.CaseID] {
			return GateERelayOnboardingReport{}, errors.New("Gate E case IDs must be unique")
		}
		seen[c.CaseID] = true
		if c.CaseStatus != "classified_from_existing_coverage" {
			return GateERelayOnboardingReport{}, errors.New("Gate E v0.8.5 cases must be classified from existing coverage")
		}
	}
	return GateERelayOnboardingReport{SchemaVersion: GateERelayOnboardingReportSchema, ReportID: reportID, Cases: cases, Nonclaims: GateERelayOnboardingNonclaims()}, nil
}

func GateERelayOnboardingCaseIDs() []string {
	cases := GateERelayOnboardingCases()
	ids := make([]string, 0, len(cases))
	for _, c := range cases {
		ids = append(ids, c.CaseID)
	}
	sort.Strings(ids)
	return ids
}

func GateERelayOnboardingNonclaims() []string {
	return []string{"not malicious-relay safety", "not metadata privacy", "not verified identity", "not hostile-server proof", "not production security", "not production E2EE", "not external pen-test completion", "not silent repair", "not silent trust promotion", "not migration safety", "not production vault"}
}

func GateERelayOnboardingClaims() map[string]bool {
	return map[string]bool{"malicious_relay_safety": false, "metadata_privacy": false, "verified_identity": false, "hostile_server_proof": false, "production_security": false, "production_e2ee": false, "external_pen_test_completion": false, "silent_repair": false, "silent_trust_promotion": false, "migration_safety": false, "production_vault": false}
}
