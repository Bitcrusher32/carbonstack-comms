package protocol

import "testing"

func TestDecideProviderTrustHappyPathEvents(t *testing.T) {
	cases := []ProviderEventName{
		ProviderEventPublicBundleCreated,
		ProviderEventConversationCreated,
		ProviderEventConversationWelcomeCreated,
		ProviderEventConversationWelcomeStaged,
		ProviderEventConversationJoined,
		ProviderEventConversationLoaded,
		ProviderEventMessageProtected,
		ProviderEventMessageOpened,
	}

	for _, event := range cases {
		t.Run(string(event), func(t *testing.T) {
			decision := DecideProviderTrust(event)

			if !ProviderTrustDecisionHasAction(decision, ProviderTrustActionAppendHistory) {
				t.Fatalf("expected append history action for %q", event)
			}

			if decision.BlocksSend || decision.BlocksReceive || decision.BlocksOpen {
				t.Fatalf("happy-path event %q should not block send/receive/open", event)
			}

			if decision.RequiresReverify {
				t.Fatalf("happy-path event %q should not require reverify", event)
			}
		})
	}
}

func TestDecideProviderTrustInvalidSignature(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventSignatureInvalid)

	assertHasAction(t, decision, ProviderTrustActionBlockOpen)
	assertHasAction(t, decision, ProviderTrustActionWarnUser)
	assertHasAction(t, decision, ProviderTrustActionAppendHistory)
	assertHasAction(t, decision, ProviderTrustActionRequireReverify)

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

func TestDecideProviderTrustMissingStorage(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventStorageMissing)

	assertHasAction(t, decision, ProviderTrustActionStopOperation)
	assertHasAction(t, decision, ProviderTrustActionShowRecoveryPath)

	if !decision.BlocksSend {
		t.Fatal("missing storage should block send")
	}

	if decision.BlocksOpen {
		t.Fatal("missing storage should not automatically block open in the pure mapping")
	}

	if !decision.UserVisible {
		t.Fatal("missing storage should be user visible")
	}
}

func TestDecideProviderTrustMissingSigner(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventSecretUnavailable)

	assertHasAction(t, decision, ProviderTrustActionFatalLocalState)
	assertHasAction(t, decision, ProviderTrustActionBlockSend)
	assertHasAction(t, decision, ProviderTrustActionShowRecoveryPath)

	if !decision.BlocksSend {
		t.Fatal("missing signer should block send")
	}

	if !decision.UserVisible {
		t.Fatal("missing signer should be user visible")
	}

	if !decision.HistoryRelevant {
		t.Fatal("missing signer should be history relevant")
	}
}

func TestDecideProviderTrustMalformedMessage(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventTamperDetected)

	assertHasAction(t, decision, ProviderTrustActionBlockOpen)
	assertHasAction(t, decision, ProviderTrustActionQuarantineMessage)
	assertHasAction(t, decision, ProviderTrustActionWarnUser)
	assertHasAction(t, decision, ProviderTrustActionAppendHistory)

	if !decision.BlocksOpen {
		t.Fatal("tamper-detected message should block open")
	}

	if !decision.UserVisible {
		t.Fatal("tamper-detected message should be user visible")
	}

	if !decision.HistoryRelevant {
		t.Fatal("tamper-detected message should be history relevant")
	}
}

func TestDecideProviderTrustWrongGroup(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventGroupUnrecoverable)

	assertHasAction(t, decision, ProviderTrustActionFatalLocalState)
	assertHasAction(t, decision, ProviderTrustActionStopOperation)
	assertHasAction(t, decision, ProviderTrustActionShowRecoveryPath)

	if !decision.BlocksSend || !decision.BlocksReceive || !decision.BlocksOpen {
		t.Fatal("group unrecoverable should block send, receive, and open")
	}
}

func TestDecideProviderTrustUnknownFutureEvent(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventName("provider.future.event"))

	assertHasAction(t, decision, ProviderTrustActionAppendHistory)
	assertHasAction(t, decision, ProviderTrustActionDebugOnly)

	if decision.BlocksSend || decision.BlocksReceive || decision.BlocksOpen {
		t.Fatal("unknown future event should not automatically block operation")
	}

	if decision.RequiresReverify {
		t.Fatal("unknown future event should not automatically require reverify")
	}

	if decision.Descriptor.Class != ProviderEventClassUnknown {
		t.Fatalf("unknown future event class = %q, want %q", decision.Descriptor.Class, ProviderEventClassUnknown)
	}
}

func assertHasAction(t *testing.T, decision ProviderTrustDecision, action ProviderTrustAction) {
	t.Helper()

	if !ProviderTrustDecisionHasAction(decision, action) {
		t.Fatalf("expected action %q for event %q, got %#v", action, decision.Event, decision.Actions)
	}
}

func TestDecideProviderTrustCommandUnsupported(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventCommandUnsupported)

	assertHasAction(t, decision, ProviderTrustActionAppendHistory)
	assertHasAction(t, decision, ProviderTrustActionDebugOnly)

	if decision.BlocksSend || decision.BlocksReceive || decision.BlocksOpen {
		t.Fatal("unsupported command should not block send, receive, or open")
	}

	if decision.RequiresReverify {
		t.Fatal("unsupported command should not require reverify")
	}

	if decision.UserVisible {
		t.Fatal("unsupported command should not be user visible")
	}

	if !decision.HistoryRelevant {
		t.Fatal("unsupported command should be history relevant for developer/audit continuity")
	}

	if decision.Descriptor.Severity != ProviderEventSeverityWarning {
		t.Fatalf("unsupported command severity = %q, want %q", decision.Descriptor.Severity, ProviderEventSeverityWarning)
	}

	if decision.Descriptor.TrustRelevant {
		t.Fatal("unsupported command descriptor should not be trust relevant")
	}
}

func TestDecideProviderTrustCommandInvalid(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventCommandInvalid)

	assertCommandSurfaceDecision(t, decision, ProviderEventCommandInvalid)
}

func TestDecideProviderTrustCommandNotImplemented(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventCommandNotImplemented)

	assertCommandSurfaceDecision(t, decision, ProviderEventCommandNotImplemented)
}

func assertCommandSurfaceDecision(t *testing.T, decision ProviderTrustDecision, event ProviderEventName) {
	t.Helper()

	if decision.Event != event {
		t.Fatalf("decision event = %q, want %q", decision.Event, event)
	}

	assertHasAction(t, decision, ProviderTrustActionAppendHistory)
	assertHasAction(t, decision, ProviderTrustActionDebugOnly)

	if decision.BlocksSend || decision.BlocksReceive || decision.BlocksOpen {
		t.Fatalf("%q should not block send, receive, or open", event)
	}

	if decision.RequiresReverify {
		t.Fatalf("%q should not require reverify", event)
	}

	if decision.UserVisible {
		t.Fatalf("%q should not be user visible", event)
	}

	if !decision.HistoryRelevant {
		t.Fatalf("%q should be history relevant for developer/audit continuity", event)
	}

	if decision.Descriptor.Severity != ProviderEventSeverityWarning {
		t.Fatalf("%q severity = %q, want %q", event, decision.Descriptor.Severity, ProviderEventSeverityWarning)
	}

	if decision.Descriptor.TrustRelevant {
		t.Fatalf("%q descriptor should not be trust relevant", event)
	}
}
func TestDecideProviderTrustIdentityPrepStateWritten(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventIdentityPrepStateWritten)

	assertHasAction(t, decision, ProviderTrustActionAppendHistory)
	assertHasAction(t, decision, ProviderTrustActionDebugOnly)

	if decision.BlocksSend || decision.BlocksReceive || decision.BlocksOpen {
		t.Fatal("identity prep state written should not block send, receive, or open")
	}

	if decision.RequiresReverify {
		t.Fatal("identity prep state written should not require reverify")
	}

	if decision.UserVisible {
		t.Fatal("identity prep state written should not be user visible")
	}

	if !decision.HistoryRelevant {
		t.Fatal("identity prep state written should be history relevant")
	}

	if decision.Descriptor.TrustRelevant {
		t.Fatal("identity prep state descriptor should not be trust relevant")
	}
}

func TestDecideProviderTrustIdentityExists(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventIdentityExists)

	assertHasAction(t, decision, ProviderTrustActionAppendHistory)
	assertHasAction(t, decision, ProviderTrustActionDebugOnly)

	if decision.BlocksSend || decision.BlocksReceive || decision.BlocksOpen {
		t.Fatal("identity exists should not block send, receive, or open")
	}

	if decision.RequiresReverify {
		t.Fatal("identity exists should not require reverify")
	}

	if decision.UserVisible {
		t.Fatal("identity exists should not be user visible")
	}

	if !decision.HistoryRelevant {
		t.Fatal("identity exists should be history relevant")
	}

	if decision.Descriptor.TrustRelevant {
		t.Fatal("identity exists descriptor should not be trust relevant")
	}
}

func TestDecideProviderTrustCheckpointFailed(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventCheckpointFailed)

	assertHasAction(t, decision, ProviderTrustActionStopOperation)
	assertHasAction(t, decision, ProviderTrustActionShowRecoveryPath)

	if !decision.BlocksSend {
		t.Fatal("checkpoint failed should block send/current outgoing state mutation")
	}
	if decision.RequiresReverify {
		t.Fatal("checkpoint failed should not require reverify by default")
	}

	if !decision.HistoryRelevant {
		t.Fatal("checkpoint failed should be history relevant")
	}

	if decision.Descriptor.TrustRelevant {
		t.Fatal("checkpoint failed descriptor should not be cryptographic trust relevant by default")
	}
}
func TestDecideProviderTrustIdentityCreated(t *testing.T) {
	decision := DecideProviderTrust(ProviderEventIdentityCreated)

	assertHasAction(t, decision, ProviderTrustActionAppendHistory)
	assertHasAction(t, decision, ProviderTrustActionDebugOnly)

	if decision.BlocksSend || decision.BlocksReceive || decision.BlocksOpen {
		t.Fatal("identity created should not block send, receive, or open")
	}

	if decision.RequiresReverify {
		t.Fatal("identity created should not require reverify")
	}

	if decision.UserVisible {
		t.Fatal("identity created should not be user visible")
	}

	if !decision.HistoryRelevant {
		t.Fatal("identity created should be history relevant")
	}

	if decision.Descriptor.TrustRelevant {
		t.Fatal("identity created descriptor should not be trust relevant")
	}
}
