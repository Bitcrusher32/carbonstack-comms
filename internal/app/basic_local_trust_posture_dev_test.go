package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBasicLocalTrustPostureReportNonclaims(t *testing.T) {
	input := basicLocalTrustInput{
		SubjectLabel:       "Alice",
		CypherAccountID:    "acct-alice",
		CypherDeviceID:     "device-alice",
		CommsFingerprint:   "fp-alice",
		OpenMLSDeviceLabel: "alice-sidecar",
		OpenMLSKeyPackage:  "kp-alice",
		RelaySpaceID:       "relay-a",
	}
	report := buildBasicLocalTrustPostureReport(input, time.Unix(1700000000, 0).UTC())
	if report["schema_version"] != basicLocalTrustPostureSchema {
		t.Fatalf("unexpected schema: %v", report["schema_version"])
	}
	if report["ready_for_manual_local_acceptance"] != true {
		t.Fatalf("expected ready report: %#v", report)
	}
	claims := report["claims"].(map[string]bool)
	if claims["verified_identity"] || claims["trust_promotion"] || claims["cryptographic_binding_across_cypher_comms_openmls"] || claims["automatic_trust_promotion"] {
		t.Fatalf("unexpected trust/identity claim: %#v", claims)
	}
}

func TestBasicLocalTrustPostureMissingEvidence(t *testing.T) {
	report := buildBasicLocalTrustPostureReport(basicLocalTrustInput{SubjectLabel: "Alice"}, time.Unix(1700000000, 0).UTC())
	if report["ready_for_manual_local_acceptance"] != false {
		t.Fatalf("expected missing evidence to block readiness")
	}
	missing := report["missing_required_for_manual_local_acceptance"].([]string)
	if len(missing) == 0 {
		t.Fatalf("expected missing evidence list")
	}
}

func TestBasicLocalTrustAcceptRequiresExplicitFlag(t *testing.T) {
	_, _, err := buildAndPersistBasicLocalTrustAcceptance(basicLocalTrustInput{
		SubjectLabel:     "Alice",
		CypherAccountID:  "acct",
		CypherDeviceID:   "device",
		CommsFingerprint: "fp",
		Reason:           "manual check",
	}, time.Unix(1700000000, 0).UTC())
	if err == nil {
		t.Fatalf("expected missing explicit acceptance flag to fail")
	}
}

func TestBasicLocalTrustAcceptWritesEventAndPreservesNonclaims(t *testing.T) {
	dir := t.TempDir()
	event, path, err := buildAndPersistBasicLocalTrustAcceptance(basicLocalTrustInput{
		EventRoot:          dir,
		AcceptCandidate:    true,
		SubjectLabel:       "Alice Device",
		CypherAccountID:    "acct",
		CypherDeviceID:     "device",
		CommsFingerprint:   "fp",
		OpenMLSDeviceLabel: "sidecar",
		OpenMLSKeyPackage:  "kp",
		RelaySpaceID:       "relay",
		Reason:             "manual out-of-band comparison",
	}, time.Unix(1700000000, 0).UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event["schema_version"] != basicLocalTrustAcceptanceEventSchema {
		t.Fatalf("unexpected event schema: %#v", event)
	}
	claims := event["claims"].(map[string]bool)
	if claims["verified_identity"] || claims["trust_promotion"] || claims["automatic_trust_promotion"] {
		t.Fatalf("unexpected trust claim: %#v", claims)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("event not written: %v", err)
	}
	if filepath.Base(filepath.Dir(path)) != "alice-device" {
		t.Fatalf("unexpected subject dir: %s", filepath.Dir(path))
	}
}
