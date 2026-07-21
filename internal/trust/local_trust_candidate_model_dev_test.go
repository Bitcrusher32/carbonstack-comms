package trust

import (
	"testing"
	"time"
)

func TestGateCLocalTrustCandidateStartsUnpromoted(t *testing.T) {
	candidate := NewGateCLocalTrustCandidate(
		"cand-alice",
		GateCLocalTrustEvidence{
			SubjectLabel:                 "alice",
			CypherAccountID:              "acct-alice",
			CypherDeviceID:               "device-alice",
			RelaySpaceID:                 "relay-alpha",
			RelaySpaceContext:            "friend-space",
			OpenMLSSignerFingerprint:     "signer-a",
			OpenMLSCredentialFingerprint: "credential-a",
			KeyPackageFingerprint:        "kp-fp-a",
			KeyPackageLineage:            "kp-lineage-a",
		},
		time.Date(2026, 7, 21, 15, 0, 0, 0, time.UTC),
	)

	if candidate.SchemaVersion != GateCLocalTrustCandidateSchema {
		t.Fatalf("unexpected schema: %s", candidate.SchemaVersion)
	}
	if candidate.TrustState != GateCTrustStateCandidateObserved {
		t.Fatalf("candidate started with trust state %q", candidate.TrustState)
	}
	if candidate.TrustLevel != "candidate" {
		t.Fatalf("candidate started with trust level %q", candidate.TrustLevel)
	}
	if candidate.OperatorPromotionEventID != "" {
		t.Fatalf("candidate promoted without explicit operator event: %s", candidate.OperatorPromotionEventID)
	}
	for claim, value := range GateCLocalTrustClaims() {
		if value {
			t.Fatalf("Gate C claim %s unexpectedly true", claim)
		}
	}
}

func TestGateCLocalTrustPromotionRequiresExplicitOperatorEvent(t *testing.T) {
	candidate := NewGateCLocalTrustCandidate(
		"cand-alice",
		GateCLocalTrustEvidence{SubjectLabel: "alice", CypherAccountID: "acct", CypherDeviceID: "device"},
		time.Date(2026, 7, 21, 15, 0, 0, 0, time.UTC),
	)

	if _, err := PromoteGateCLocalTrustCandidate(candidate, "", "manual out-of-band comparison", time.Now()); err == nil {
		t.Fatal("expected promotion without event ID to fail")
	}
	if _, err := PromoteGateCLocalTrustCandidate(candidate, "promote-1", "", time.Now()); err == nil {
		t.Fatal("expected promotion without verification method to fail")
	}
	promoted, err := PromoteGateCLocalTrustCandidate(candidate, "promote-1", "manual out-of-band comparison", time.Date(2026, 7, 21, 16, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("promote candidate: %v", err)
	}
	if promoted.TrustState != GateCTrustStatePromotedLocalTrust {
		t.Fatalf("unexpected promoted trust state: %s", promoted.TrustState)
	}
	if promoted.TrustLevel != "local_manual_trust" {
		t.Fatalf("unexpected promoted trust level: %s", promoted.TrustLevel)
	}
}

func TestGateCLocalTrustChangedLineageIsLoud(t *testing.T) {
	candidate := NewGateCLocalTrustCandidate(
		"cand-alice",
		GateCLocalTrustEvidence{
			SubjectLabel:                 "alice",
			CypherDeviceID:               "device-a",
			OpenMLSSignerFingerprint:     "signer-a",
			OpenMLSCredentialFingerprint: "credential-a",
			KeyPackageFingerprint:        "kp-a",
			KeyPackageLineage:            "lineage-a",
		},
		time.Date(2026, 7, 21, 15, 0, 0, 0, time.UTC),
	)

	updated := ApplyGateCLocalTrustChangedLineage(
		candidate,
		GateCLocalTrustEvidence{
			SubjectLabel:                 "alice",
			CypherDeviceID:               "device-b",
			OpenMLSSignerFingerprint:     "signer-b",
			OpenMLSCredentialFingerprint: "credential-b",
			KeyPackageFingerprint:        "kp-b",
			KeyPackageLineage:            "lineage-b",
		},
		time.Date(2026, 7, 21, 16, 0, 0, 0, time.UTC),
	)

	if updated.TrustState != GateCTrustStateChangedLineageWarning {
		t.Fatalf("expected changed lineage warning state, got %s", updated.TrustState)
	}
	if len(updated.ChangedLineageWarnings) < 5 {
		t.Fatalf("expected loud changed lineage warnings, got %#v", updated.ChangedLineageWarnings)
	}
	if _, err := PromoteGateCLocalTrustCandidate(updated, "promote-1", "manual comparison", time.Now()); err == nil {
		t.Fatal("expected promotion with changed lineage warnings to fail")
	}
}

func TestGateCLocalTrustRulesPreserveNonclaims(t *testing.T) {
	rules := GateCLocalTrustRules()
	required := []string{
		"Relay membership is not trust",
		"MLS join is not trust",
		"Provider observation is not trust",
		"candidate state is not promoted without explicit operator action",
		"changed signer/device/key lineage is loud",
	}
	for _, want := range required {
		found := false
		for _, got := range rules {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing Gate C rule %q in %#v", want, rules)
		}
	}
}
