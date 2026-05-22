package protocol

import "testing"

func TestOpenMLSNegativeFixturesMapToTrustDecisions(t *testing.T) {
	cases := []struct {
		file             string
		event            ProviderEventName
		requiredActions  []ProviderTrustAction
		blocksSend       bool
		blocksReceive    bool
		blocksOpen       bool
		requiresReverify bool
		userVisible      bool
		historyRelevant  bool
	}{
		{
			file:  "missing-storage-error.json",
			event: ProviderEventStorageMissing,
			requiredActions: []ProviderTrustAction{
				ProviderTrustActionStopOperation,
				ProviderTrustActionShowRecoveryPath,
			},
			blocksSend:      true,
			blocksReceive:   false,
			blocksOpen:      false,
			userVisible:     true,
			historyRelevant: false,
		},
		{
			file:  "missing-signer-error.json",
			event: ProviderEventSecretUnavailable,
			requiredActions: []ProviderTrustAction{
				ProviderTrustActionFatalLocalState,
				ProviderTrustActionBlockSend,
				ProviderTrustActionShowRecoveryPath,
			},
			blocksSend:      true,
			blocksReceive:   false,
			blocksOpen:      false,
			userVisible:     true,
			historyRelevant: true,
		},
		{
			file:  "wrong-group-error.json",
			event: ProviderEventGroupUnrecoverable,
			requiredActions: []ProviderTrustAction{
				ProviderTrustActionFatalLocalState,
				ProviderTrustActionStopOperation,
				ProviderTrustActionShowRecoveryPath,
			},
			blocksSend:      true,
			blocksReceive:   true,
			blocksOpen:      true,
			userVisible:     true,
			historyRelevant: true,
		},
		{
			file:  "malformed-message-error.json",
			event: ProviderEventTamperDetected,
			requiredActions: []ProviderTrustAction{
				ProviderTrustActionBlockOpen,
				ProviderTrustActionQuarantineMessage,
				ProviderTrustActionWarnUser,
				ProviderTrustActionAppendHistory,
			},
			blocksSend:      false,
			blocksReceive:   false,
			blocksOpen:      true,
			userVisible:     true,
			historyRelevant: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			var fixture openMLSNegativeErrorFixture
			readFixtureJSON(t, tc.file, &fixture)

			if fixture.ProviderEventCandidate != string(tc.event) {
				t.Fatalf("fixture event candidate = %q, want %q", fixture.ProviderEventCandidate, tc.event)
			}

			descriptor := DescribeProviderEvent(tc.event)
			if descriptor.Class == ProviderEventClassUnknown {
				t.Fatalf("event %q unexpectedly mapped to unknown class", tc.event)
			}

			decision := DecideProviderTrust(tc.event)

			for _, action := range tc.requiredActions {
				if !ProviderTrustDecisionHasAction(decision, action) {
					t.Fatalf("event %q missing required trust action %q; got %#v", tc.event, action, decision.Actions)
				}
			}

			if decision.BlocksSend != tc.blocksSend {
				t.Fatalf("event %q BlocksSend = %v, want %v", tc.event, decision.BlocksSend, tc.blocksSend)
			}

			if decision.BlocksReceive != tc.blocksReceive {
				t.Fatalf("event %q BlocksReceive = %v, want %v", tc.event, decision.BlocksReceive, tc.blocksReceive)
			}

			if decision.BlocksOpen != tc.blocksOpen {
				t.Fatalf("event %q BlocksOpen = %v, want %v", tc.event, decision.BlocksOpen, tc.blocksOpen)
			}

			if decision.RequiresReverify != tc.requiresReverify {
				t.Fatalf("event %q RequiresReverify = %v, want %v", tc.event, decision.RequiresReverify, tc.requiresReverify)
			}

			if decision.UserVisible != tc.userVisible {
				t.Fatalf("event %q UserVisible = %v, want %v", tc.event, decision.UserVisible, tc.userVisible)
			}

			if decision.HistoryRelevant != tc.historyRelevant {
				t.Fatalf("event %q HistoryRelevant = %v, want %v", tc.event, decision.HistoryRelevant, tc.historyRelevant)
			}
		})
	}
}

func TestOpenMLSInvalidSignatureFixtureMapsToTrustDecision(t *testing.T) {
	var fixture openMLSInvalidSignatureFixture
	readFixtureJSON(t, "invalid-signature-error.json", &fixture)

	event := ProviderEventName(fixture.CarbonStackMappingCandidate)
	if event != ProviderEventSignatureInvalid {
		t.Fatalf("invalid signature fixture maps to %q, want %q", event, ProviderEventSignatureInvalid)
	}

	decision := DecideProviderTrust(event)

	requiredActions := []ProviderTrustAction{
		ProviderTrustActionBlockOpen,
		ProviderTrustActionWarnUser,
		ProviderTrustActionAppendHistory,
		ProviderTrustActionRequireReverify,
	}

	for _, action := range requiredActions {
		if !ProviderTrustDecisionHasAction(decision, action) {
			t.Fatalf("invalid signature missing required trust action %q; got %#v", action, decision.Actions)
		}
	}

	if !decision.BlocksOpen {
		t.Fatal("invalid signature should block open")
	}

	if !decision.RequiresReverify {
		t.Fatal("invalid signature should require reverify")
	}

	if !decision.UserVisible {
		t.Fatal("invalid signature should be user visible")
	}

	if !decision.HistoryRelevant {
		t.Fatal("invalid signature should be history relevant")
	}
}
