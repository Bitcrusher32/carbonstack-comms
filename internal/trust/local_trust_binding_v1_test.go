package trust

import (
	"strings"
	"testing"
)

func sampleLocalTrustBindingEvidenceV1() LocalTrustBindingEvidenceV1 {
	return LocalTrustBindingEvidenceV1{
		SubjectLabel:                 "Bob",
		CypherAccountID:              "acct-bob",
		CypherDeviceID:               "device-bob-1",
		RelaySpaceID:                 "relay-space-alpha",
		OpenMLSCredentialFingerprint: "cred:sha256:aaaaaaaa",
		OpenMLSSignerFingerprint:     "signer:sha256:bbbbbbbb",
		KeyPackageFingerprint:        "kp:sha256:cccccccc",
		KeyPackageLineage:            "kp-lineage-1",
		FirstObservedAt:              "2026-08-09T00:00:00Z",
		LastObservedAt:               "2026-08-09T00:01:00Z",
		CandidateSource:              "openmls-cypher-dev-fixture",
	}
}

func TestLocalTrustBindingCandidateRequiresCompositeEvidence(t *testing.T) {
	evidence := sampleLocalTrustBindingEvidenceV1()
	binding, err := NewLocalTrustBindingCandidateV1(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if binding.SchemaVersion != LocalTrustBindingV1Schema {
		t.Fatalf("schema = %q", binding.SchemaVersion)
	}
	if binding.State != LocalTrustBindingCandidateObserved {
		t.Fatalf("state = %q", binding.State)
	}
	if !strings.HasPrefix(binding.BindingFingerprint, "sha256:") {
		t.Fatalf("binding fingerprint = %q", binding.BindingFingerprint)
	}
	for _, marker := range []string{
		"relay membership is not trust",
		"MLS join is not trust",
		"provider observation is not trust",
		"KeyPackage publication is not trust",
	} {
		if !contains(binding.Warnings, marker) {
			t.Fatalf("candidate warnings missing %q: %#v", marker, binding.Warnings)
		}
	}
}

func TestLocalTrustBindingRejectsIncompleteEvidence(t *testing.T) {
	evidence := sampleLocalTrustBindingEvidenceV1()
	evidence.OpenMLSSignerFingerprint = "   "
	_, err := NewLocalTrustBindingCandidateV1(evidence)
	if err == nil {
		t.Fatal("expected error for missing OpenMLS signer fingerprint")
	}
	if !strings.Contains(err.Error(), "openmls_signer_fingerprint") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLocalTrustBindingPromotionRequiresExplicitOperatorEvent(t *testing.T) {
	candidate, err := NewLocalTrustBindingCandidateV1(sampleLocalTrustBindingEvidenceV1())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PromoteLocalTrustBindingV1(candidate, "", "manual-verification"); err == nil {
		t.Fatal("expected missing operator event to refuse promotion")
	}
	if _, err := PromoteLocalTrustBindingV1(candidate, "op-event-1", ""); err == nil {
		t.Fatal("expected missing verification method to refuse promotion")
	}
	promoted, err := PromoteLocalTrustBindingV1(candidate, "op-event-1", "manual-out-of-band")
	if err != nil {
		t.Fatal(err)
	}
	if promoted.State != LocalTrustBindingPromotedLocalTrust {
		t.Fatalf("state = %q", promoted.State)
	}
	if promoted.OperatorPromotionEventID != "op-event-1" {
		t.Fatalf("operator event = %q", promoted.OperatorPromotionEventID)
	}
	if !contains(promoted.Nonclaims, "not production verified identity") {
		t.Fatalf("nonclaims missing verified identity boundary: %#v", promoted.Nonclaims)
	}
}

func TestLocalTrustBindingObservationsDoNotAutopromote(t *testing.T) {
	evidence := sampleLocalTrustBindingEvidenceV1()
	constructors := []struct {
		name string
		fn   func(LocalTrustBindingEvidenceV1) (LocalTrustBindingV1, error)
	}{
		{"relay-membership", RelayMembershipObservationV1},
		{"mls-join", MLSJoinObservationV1},
		{"provider", ProviderObservationV1},
		{"keypackage-publication", KeyPackagePublicationObservationV1},
	}
	for _, tc := range constructors {
		binding, err := tc.fn(evidence)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if binding.State != LocalTrustBindingCandidateObserved {
			t.Fatalf("%s autopromoted to %q", tc.name, binding.State)
		}
		if binding.OperatorPromotionEventID != "" {
			t.Fatalf("%s unexpectedly has operator promotion event", tc.name)
		}
	}
}

func TestLocalTrustBindingChangedSignerDeviceKeyLineageIsLoud(t *testing.T) {
	candidate, err := NewLocalTrustBindingCandidateV1(sampleLocalTrustBindingEvidenceV1())
	if err != nil {
		t.Fatal(err)
	}
	promoted, err := PromoteLocalTrustBindingV1(candidate, "op-event-1", "manual-out-of-band")
	if err != nil {
		t.Fatal(err)
	}

	signerChanged := ApplyLocalTrustBindingChangeV1(promoted, LocalTrustBindingChangeV1{NewOpenMLSSignerFingerprint: "signer:sha256:changed"})
	if signerChanged.State != LocalTrustBindingChangedSignerWarning {
		t.Fatalf("signer changed state = %q", signerChanged.State)
	}
	if !contains(signerChanged.Warnings, "changed OpenMLS signer fingerprint") {
		t.Fatalf("signer changed warnings = %#v", signerChanged.Warnings)
	}

	deviceChanged := ApplyLocalTrustBindingChangeV1(promoted, LocalTrustBindingChangeV1{NewCypherDeviceID: "device-bob-2"})
	if deviceChanged.State != LocalTrustBindingChangedDeviceWarning {
		t.Fatalf("device changed state = %q", deviceChanged.State)
	}

	keyChanged := ApplyLocalTrustBindingChangeV1(promoted, LocalTrustBindingChangeV1{NewKeyPackageFingerprint: "kp:sha256:changed"})
	if keyChanged.State != LocalTrustBindingChangedKeyWarning {
		t.Fatalf("key changed state = %q", keyChanged.State)
	}
}

func TestLocalTrustBindingDemoteAndRevokeRequireEvents(t *testing.T) {
	candidate, err := NewLocalTrustBindingCandidateV1(sampleLocalTrustBindingEvidenceV1())
	if err != nil {
		t.Fatal(err)
	}
	promoted, err := PromoteLocalTrustBindingV1(candidate, "op-event-1", "manual-out-of-band")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := DemoteLocalTrustBindingV1(promoted, ""); err == nil {
		t.Fatal("expected demotion without event to fail")
	}
	demoted, err := DemoteLocalTrustBindingV1(promoted, "demote-event-1")
	if err != nil {
		t.Fatal(err)
	}
	if demoted.State != LocalTrustBindingDemoted {
		t.Fatalf("demoted state = %q", demoted.State)
	}

	if _, err := RevokeLocalTrustBindingV1(promoted, ""); err == nil {
		t.Fatal("expected revocation without event to fail")
	}
	revoked, err := RevokeLocalTrustBindingV1(promoted, "revoke-event-1")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.State != LocalTrustBindingRevoked {
		t.Fatalf("revoked state = %q", revoked.State)
	}
}

func TestLocalTrustBindingV1NonclaimsPreserved(t *testing.T) {
	candidate, err := NewLocalTrustBindingCandidateV1(sampleLocalTrustBindingEvidenceV1())
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"not production verified identity",
		"not secure enrollment",
		"not hostile-server identity replacement proof",
		"not hardware-backed identity",
		"not production E2EE readiness",
		"not metadata privacy proof",
		"not production vault",
		"not secret-bearing backup/restore",
		"not external audit",
		"not external pen-test completion",
	} {
		if !contains(candidate.Nonclaims, marker) {
			t.Fatalf("missing nonclaim %q: %#v", marker, candidate.Nonclaims)
		}
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
