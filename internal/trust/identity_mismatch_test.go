package trust

import "testing"

func TestClassifyIdentityMismatchCandidateOnlyWithoutMapping(t *testing.T) {
	decision, err := ClassifyIdentityMismatch(IdentityMismatchInput{
		Candidate: IdentityCandidate{
			Fingerprint: "CSFP-CANDIDATE",
			Source:      "provider_keypackage",
		},
	})
	if err != nil {
		t.Fatalf("classify mismatch: %v", err)
	}

	if decision.Classification != IdentityMismatchClassificationCandidateOnly {
		t.Fatalf("classification = %q", decision.Classification)
	}
	if decision.KnownTrustState != StateUnknown {
		t.Fatalf("known trust state = %q", decision.KnownTrustState)
	}
	if !decision.BlocksSend {
		t.Fatal("unmapped candidate should block strict mature send")
	}
	if decision.MayMutateTrustStore {
		t.Fatal("classifier must not authorize trust store mutation")
	}
	if decision.MayVerifyIdentity {
		t.Fatal("classifier must not authorize verified identity")
	}
}

func TestClassifyIdentityMismatchVerifiedMatchContinuity(t *testing.T) {
	known := DeviceRecord{
		DeviceID:          "device-1",
		PublicIdentityKey: "raw-material",
		Fingerprint:       "CSFP-MATCH",
		TrustState:        StateVerified,
	}

	decision, err := ClassifyIdentityMismatch(IdentityMismatchInput{
		MappingPresent: true,
		KnownDevice:    &known,
		Candidate: IdentityCandidate{
			ClaimedDeviceID:        "device-1",
			PublicIdentityMaterial: "raw-material",
			Fingerprint:            "CSFP-MATCH",
			Source:                 "provider_keypackage",
		},
	})
	if err != nil {
		t.Fatalf("classify mismatch: %v", err)
	}

	if decision.Classification != IdentityMismatchClassificationContinuity {
		t.Fatalf("classification = %q", decision.Classification)
	}
	if !decision.MaterialMatches {
		t.Fatal("expected material match")
	}
	if decision.BlocksSend {
		t.Fatal("verified matching continuity should not block send by itself")
	}
	if decision.RequiresReverify {
		t.Fatal("verified matching continuity should not require reverify")
	}
}

func TestClassifyIdentityMismatchVerifiedDifferentRequiresReverify(t *testing.T) {
	known := DeviceRecord{
		DeviceID:          "device-1",
		PublicIdentityKey: "old-material",
		Fingerprint:       "CSFP-OLD",
		TrustState:        StateVerified,
	}

	decision, err := ClassifyIdentityMismatch(IdentityMismatchInput{
		MappingPresent: true,
		KnownDevice:    &known,
		Candidate: IdentityCandidate{
			ClaimedDeviceID:        "device-1",
			PublicIdentityMaterial: "new-material",
			Fingerprint:            "CSFP-NEW",
			Source:                 "provider_keypackage",
		},
	})
	if err != nil {
		t.Fatalf("classify mismatch: %v", err)
	}

	if decision.Classification != IdentityMismatchClassificationReverifyRequired {
		t.Fatalf("classification = %q", decision.Classification)
	}
	if decision.MaterialMatches {
		t.Fatal("expected material mismatch")
	}
	if !decision.RequiresReview {
		t.Fatal("verified mismatch should require review")
	}
	if !decision.RequiresReverify {
		t.Fatal("verified mismatch should require reverify")
	}
	if !decision.BlocksSend {
		t.Fatal("verified mismatch should block send")
	}
	if decision.MayMutateTrustStore {
		t.Fatal("pure classifier must not authorize trust mutation")
	}
	if decision.MayReplaceKeyMaterial {
		t.Fatal("pure classifier must not authorize key replacement")
	}
}

func TestClassifyIdentityMismatchUnverifiedMatchContinuityButBlocksSend(t *testing.T) {
	known := DeviceRecord{
		DeviceID:    "device-1",
		Fingerprint: "CSFP-MATCH",
		TrustState:  StateUnverified,
	}

	decision, err := ClassifyIdentityMismatch(IdentityMismatchInput{
		MappingPresent: true,
		KnownDevice:    &known,
		Candidate: IdentityCandidate{
			ClaimedDeviceID: "device-1",
			Fingerprint:     "CSFP-MATCH",
			Source:          "provider_keypackage",
		},
	})
	if err != nil {
		t.Fatalf("classify mismatch: %v", err)
	}

	if decision.Classification != IdentityMismatchClassificationContinuity {
		t.Fatalf("classification = %q", decision.Classification)
	}
	if !decision.MaterialMatches {
		t.Fatal("expected material match")
	}
	if !decision.BlocksSend {
		t.Fatal("unverified continuity should still block strict mature send")
	}
}

func TestClassifyIdentityMismatchUnverifiedDifferentReviewRequired(t *testing.T) {
	known := DeviceRecord{
		DeviceID:    "device-1",
		Fingerprint: "CSFP-OLD",
		TrustState:  StateUnverified,
	}

	decision, err := ClassifyIdentityMismatch(IdentityMismatchInput{
		MappingPresent: true,
		KnownDevice:    &known,
		Candidate: IdentityCandidate{
			ClaimedDeviceID: "device-1",
			Fingerprint:     "CSFP-NEW",
			Source:          "provider_keypackage",
		},
	})
	if err != nil {
		t.Fatalf("classify mismatch: %v", err)
	}

	if decision.Classification != IdentityMismatchClassificationReviewRequiredConflict {
		t.Fatalf("classification = %q", decision.Classification)
	}
	if !decision.RequiresReview {
		t.Fatal("unverified mismatch should require review")
	}
	if !decision.BlocksSend {
		t.Fatal("unverified mismatch should block send")
	}
}

func TestClassifyIdentityMismatchChangedCandidate(t *testing.T) {
	known := DeviceRecord{
		DeviceID:    "device-1",
		Fingerprint: "CSFP-OLD",
		TrustState:  StateChanged,
	}

	decision, err := ClassifyIdentityMismatch(IdentityMismatchInput{
		MappingPresent: true,
		KnownDevice:    &known,
		Candidate: IdentityCandidate{
			ClaimedDeviceID: "device-1",
			Fingerprint:     "CSFP-NEW",
			Source:          "provider_keypackage",
		},
	})
	if err != nil {
		t.Fatalf("classify mismatch: %v", err)
	}

	if decision.Classification != IdentityMismatchClassificationChangedCandidate {
		t.Fatalf("classification = %q", decision.Classification)
	}
	if !decision.RequiresReverify {
		t.Fatal("changed known device should require reverify")
	}
	if !decision.BlocksSend {
		t.Fatal("changed known device should block send")
	}
}

func TestClassifyIdentityMismatchRevokedBlocksPromotion(t *testing.T) {
	known := DeviceRecord{
		DeviceID:    "device-1",
		Fingerprint: "CSFP-OLD",
		TrustState:  StateRevoked,
	}

	decision, err := ClassifyIdentityMismatch(IdentityMismatchInput{
		MappingPresent: true,
		KnownDevice:    &known,
		Candidate: IdentityCandidate{
			ClaimedDeviceID: "device-1",
			Fingerprint:     "CSFP-OLD",
			Source:          "provider_keypackage",
		},
	})
	if err != nil {
		t.Fatalf("classify mismatch: %v", err)
	}

	if decision.Classification != IdentityMismatchClassificationBlockedRevoked {
		t.Fatalf("classification = %q", decision.Classification)
	}
	if !decision.BlocksPromotion {
		t.Fatal("revoked device should block promotion")
	}
	if !decision.BlocksSend {
		t.Fatal("revoked device should block send")
	}
}

func TestClassifyIdentityMismatchCompromisedBlocksPromotion(t *testing.T) {
	known := DeviceRecord{
		DeviceID:    "device-1",
		Fingerprint: "CSFP-OLD",
		TrustState:  StateCompromised,
	}

	decision, err := ClassifyIdentityMismatch(IdentityMismatchInput{
		MappingPresent: true,
		KnownDevice:    &known,
		Candidate: IdentityCandidate{
			ClaimedDeviceID: "device-1",
			Fingerprint:     "CSFP-OLD",
			Source:          "provider_keypackage",
		},
	})
	if err != nil {
		t.Fatalf("classify mismatch: %v", err)
	}

	if decision.Classification != IdentityMismatchClassificationBlockedCompromised {
		t.Fatalf("classification = %q", decision.Classification)
	}
	if !decision.BlocksPromotion {
		t.Fatal("compromised device should block promotion")
	}
	if !decision.BlocksSend {
		t.Fatal("compromised device should block send")
	}
}

func TestClassifyIdentityMismatchRejectsInvalidCandidate(t *testing.T) {
	known := DeviceRecord{
		DeviceID:    "device-1",
		Fingerprint: "CSFP-OLD",
		TrustState:  StateVerified,
	}

	_, err := ClassifyIdentityMismatch(IdentityMismatchInput{
		MappingPresent: true,
		KnownDevice:    &known,
		Candidate: IdentityCandidate{
			Fingerprint: "",
			Source:      "provider_keypackage",
		},
	})
	if err == nil {
		t.Fatal("expected invalid candidate error")
	}
}

func TestIdentityCandidateMatchFallsBackToRawMaterial(t *testing.T) {
	known := DeviceRecord{
		DeviceID:          "device-1",
		PublicIdentityKey: "raw-material",
		TrustState:        StateVerified,
	}

	decision, err := ClassifyIdentityMismatch(IdentityMismatchInput{
		MappingPresent: true,
		KnownDevice:    &known,
		Candidate: IdentityCandidate{
			ClaimedDeviceID:        "device-1",
			PublicIdentityMaterial: "raw-material",
			Fingerprint:            "CSFP-CANDIDATE",
			Source:                 "provider_keypackage",
		},
	})
	if err != nil {
		t.Fatalf("classify mismatch: %v", err)
	}

	if !decision.MaterialMatches {
		t.Fatal("expected raw material fallback match")
	}
	if decision.Classification != IdentityMismatchClassificationContinuity {
		t.Fatalf("classification = %q", decision.Classification)
	}
}
