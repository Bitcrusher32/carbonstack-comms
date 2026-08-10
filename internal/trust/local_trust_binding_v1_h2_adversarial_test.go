package trust

import (
	"testing"
)

// TestH2IntegratedAdversarialReplayLocalTrustBindingV1 is the Gate H2 executable
// adversarial replay for H0 local trust binding behavior.
//
// Scope:
//   - explicit operator promotion must be required;
//   - Relay membership, MLS join, provider observation, and KeyPackage publication
//     must not autopromote trust;
//   - changed signer/device/key lineage must be loud;
//   - demotion/revocation must require explicit events.
//
// Nonclaims:
//   - not production verified identity;
//   - not secure enrollment;
//   - not hostile-server identity replacement proof;
//   - not metadata privacy;
//   - not production E2EE;
//   - not production vault or hardware-backed storage.
func TestH2IntegratedAdversarialReplayLocalTrustBindingV1(t *testing.T) {
	cases := []struct {
		Name string
		Fn   func(*testing.T)
	}{
		{Name: "TestLocalTrustBindingPromotionRequiresExplicitOperatorEvent", Fn: TestLocalTrustBindingPromotionRequiresExplicitOperatorEvent},
		{Name: "TestLocalTrustBindingObservationsDoNotAutopromote", Fn: TestLocalTrustBindingObservationsDoNotAutopromote},
		{Name: "TestLocalTrustBindingChangedSignerDeviceKeyLineageIsLoud", Fn: TestLocalTrustBindingChangedSignerDeviceKeyLineageIsLoud},
		{Name: "TestLocalTrustBindingDemoteAndRevokeRequireEvents", Fn: TestLocalTrustBindingDemoteAndRevokeRequireEvents},
	}

	for _, tc := range cases {
		t.Run(tc.Name, tc.Fn)
	}
}

func TestH2IntegratedAdversarialCaseSurfaceAnchors(t *testing.T) {
	if LocalTrustBindingV1Schema == "" {
		t.Fatal("LocalTrustBindingV1Schema must remain non-empty")
	}
	var _ = NewLocalTrustBindingCandidateV1
	var _ = PromoteLocalTrustBindingV1
	var _ = ApplyLocalTrustBindingChangeV1
	var _ = RelayMembershipObservationV1
	var _ = MLSJoinObservationV1
	var _ = ProviderObservationV1
	var _ = KeyPackagePublicationObservationV1
}
