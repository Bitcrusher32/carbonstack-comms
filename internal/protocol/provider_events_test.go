package protocol

import "testing"

func TestDescribeProviderEventFixtureEvents(t *testing.T) {
	started := DescribeProviderEvent(ProviderEventFixtureStarted)
	if started.Class != ProviderEventClassLifecycle {
		t.Fatalf("fixture started class = %q, want %q", started.Class, ProviderEventClassLifecycle)
	}
	if started.Severity != ProviderEventSeverityDebug {
		t.Fatalf("fixture started severity = %q, want %q", started.Severity, ProviderEventSeverityDebug)
	}
	if started.TrustRelevant {
		t.Fatal("fixture started should not be trust relevant")
	}
}

func TestDescribeProviderEventFixtureStreamNames(t *testing.T) {
	fixtureEvents := []ProviderEventName{
		ProviderEventFixtureStarted,
		ProviderEventPublicBundleCreated,
		ProviderEventConversationCreated,
		ProviderEventConversationWelcomeCreated,
		ProviderEventConversationMemberAdded,
		ProviderEventConversationWelcomeStaged,
		ProviderEventConversationJoined,
		ProviderEventMessageProtected,
		ProviderEventMessageOpened,
		ProviderEventConversationLoaded,
		ProviderEventFixtureCompleted,
	}

	for _, event := range fixtureEvents {
		descriptor := DescribeProviderEvent(event)
		if descriptor.Class == ProviderEventClassUnknown {
			t.Fatalf("fixture event %q mapped to unknown class", event)
		}
	}
}

func TestDescribeProviderEventInvalidSignature(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventSignatureInvalid)

	if descriptor.Class != ProviderEventClassTrustSecurity {
		t.Fatalf("invalid signature class = %q, want %q", descriptor.Class, ProviderEventClassTrustSecurity)
	}

	if descriptor.Severity != ProviderEventSeveritySecurity {
		t.Fatalf("invalid signature severity = %q, want %q", descriptor.Severity, ProviderEventSeveritySecurity)
	}

	if !descriptor.TrustRelevant {
		t.Fatal("invalid signature must be trust relevant")
	}
}

func TestDescribeProviderEventFatal(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventInvariantViolation)

	if descriptor.Class != ProviderEventClassTerminalFatal {
		t.Fatalf("fatal event class = %q, want %q", descriptor.Class, ProviderEventClassTerminalFatal)
	}

	if descriptor.Severity != ProviderEventSeverityFatal {
		t.Fatalf("fatal event severity = %q, want %q", descriptor.Severity, ProviderEventSeverityFatal)
	}

	if !descriptor.TrustRelevant {
		t.Fatal("fatal provider events should be trust/security relevant")
	}
}

func TestDescribeProviderEventUnknown(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventName("provider.future.event"))

	if descriptor.Class != ProviderEventClassUnknown {
		t.Fatalf("unknown event class = %q, want %q", descriptor.Class, ProviderEventClassUnknown)
	}

	if descriptor.Severity != ProviderEventSeverityWarning {
		t.Fatalf("unknown event severity = %q, want %q", descriptor.Severity, ProviderEventSeverityWarning)
	}

	if descriptor.TrustRelevant {
		t.Fatal("unknown events should not become trust relevant automatically")
	}
}

func TestDescribeProviderEventCommandUnsupported(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventCommandUnsupported)

	if descriptor.Name != ProviderEventCommandUnsupported {
		t.Fatalf("unsupported command event name = %q, want %q", descriptor.Name, ProviderEventCommandUnsupported)
	}

	if descriptor.Class != ProviderEventClassLifecycle {
		t.Fatalf("unsupported command class = %q, want %q", descriptor.Class, ProviderEventClassLifecycle)
	}

	if descriptor.Severity != ProviderEventSeverityWarning {
		t.Fatalf("unsupported command severity = %q, want %q", descriptor.Severity, ProviderEventSeverityWarning)
	}

	if descriptor.TrustRelevant {
		t.Fatal("unsupported command should not be trust relevant")
	}
}

func TestDescribeProviderEventCommandInvalid(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventCommandInvalid)

	if descriptor.Name != ProviderEventCommandInvalid {
		t.Fatalf("invalid command event name = %q, want %q", descriptor.Name, ProviderEventCommandInvalid)
	}

	if descriptor.Class != ProviderEventClassLifecycle {
		t.Fatalf("invalid command class = %q, want %q", descriptor.Class, ProviderEventClassLifecycle)
	}

	if descriptor.Severity != ProviderEventSeverityWarning {
		t.Fatalf("invalid command severity = %q, want %q", descriptor.Severity, ProviderEventSeverityWarning)
	}

	if descriptor.TrustRelevant {
		t.Fatal("invalid command should not be trust relevant")
	}
}

func TestDescribeProviderEventCommandNotImplemented(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventCommandNotImplemented)

	if descriptor.Name != ProviderEventCommandNotImplemented {
		t.Fatalf("not-implemented command event name = %q, want %q", descriptor.Name, ProviderEventCommandNotImplemented)
	}

	if descriptor.Class != ProviderEventClassLifecycle {
		t.Fatalf("not-implemented command class = %q, want %q", descriptor.Class, ProviderEventClassLifecycle)
	}

	if descriptor.Severity != ProviderEventSeverityWarning {
		t.Fatalf("not-implemented command severity = %q, want %q", descriptor.Severity, ProviderEventSeverityWarning)
	}

	if descriptor.TrustRelevant {
		t.Fatal("not-implemented command should not be trust relevant")
	}
}
