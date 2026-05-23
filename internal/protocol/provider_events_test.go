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
func TestDescribeProviderEventIdentityPrepStateWritten(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventIdentityPrepStateWritten)

	if descriptor.Name != ProviderEventIdentityPrepStateWritten {
		t.Fatalf("identity prep state event name = %q, want %q", descriptor.Name, ProviderEventIdentityPrepStateWritten)
	}

	if descriptor.Class != ProviderEventClassStorageCheckpoint {
		t.Fatalf("identity prep state class = %q, want %q", descriptor.Class, ProviderEventClassStorageCheckpoint)
	}

	if descriptor.Severity != ProviderEventSeverityInfo {
		t.Fatalf("identity prep state severity = %q, want %q", descriptor.Severity, ProviderEventSeverityInfo)
	}

	if descriptor.TrustRelevant {
		t.Fatal("identity prep state should not be trust relevant")
	}
}

func TestDescribeProviderEventIdentityExists(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventIdentityExists)

	if descriptor.Name != ProviderEventIdentityExists {
		t.Fatalf("identity exists event name = %q, want %q", descriptor.Name, ProviderEventIdentityExists)
	}

	if descriptor.Class != ProviderEventClassStorageCheckpoint {
		t.Fatalf("identity exists class = %q, want %q", descriptor.Class, ProviderEventClassStorageCheckpoint)
	}

	if descriptor.Severity != ProviderEventSeverityWarning {
		t.Fatalf("identity exists severity = %q, want %q", descriptor.Severity, ProviderEventSeverityWarning)
	}

	if descriptor.TrustRelevant {
		t.Fatal("identity exists should not be trust relevant")
	}
}

func TestDescribeProviderEventCheckpointFailed(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventCheckpointFailed)

	if descriptor.Name != ProviderEventCheckpointFailed {
		t.Fatalf("checkpoint failed event name = %q, want %q", descriptor.Name, ProviderEventCheckpointFailed)
	}

	if descriptor.Class != ProviderEventClassStorageCheckpoint {
		t.Fatalf("checkpoint failed class = %q, want %q", descriptor.Class, ProviderEventClassStorageCheckpoint)
	}

	if descriptor.Severity != ProviderEventSeverityWarning {
		t.Fatalf("checkpoint failed severity = %q, want %q", descriptor.Severity, ProviderEventSeverityWarning)
	}

	if descriptor.TrustRelevant {
		t.Fatal("checkpoint failed should not be trust relevant by default at this rung")
	}
}
func TestDescribeProviderEventIdentityCreated(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventIdentityCreated)

	if descriptor.Name != ProviderEventIdentityCreated {
		t.Fatalf("identity created event name = %q, want %q", descriptor.Name, ProviderEventIdentityCreated)
	}

	if descriptor.Class != ProviderEventClassStorageCheckpoint {
		t.Fatalf("identity created class = %q, want %q", descriptor.Class, ProviderEventClassStorageCheckpoint)
	}

	if descriptor.Severity != ProviderEventSeverityInfo {
		t.Fatalf("identity created severity = %q, want %q", descriptor.Severity, ProviderEventSeverityInfo)
	}

	if descriptor.TrustRelevant {
		t.Fatal("identity created should not be trust relevant")
	}
}
func TestDescribeProviderEventIdentityLoaded(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventIdentityLoaded)

	if descriptor.Name != ProviderEventIdentityLoaded {
		t.Fatalf("identity loaded event name = %q, want %q", descriptor.Name, ProviderEventIdentityLoaded)
	}

	if descriptor.Class != ProviderEventClassStorageCheckpoint {
		t.Fatalf("identity loaded class = %q, want %q", descriptor.Class, ProviderEventClassStorageCheckpoint)
	}

	if descriptor.Severity != ProviderEventSeverityInfo {
		t.Fatalf("identity loaded severity = %q, want %q", descriptor.Severity, ProviderEventSeverityInfo)
	}

	if descriptor.TrustRelevant {
		t.Fatal("identity loaded should not be trust relevant")
	}
}

func TestDescribeProviderEventIdentityMissing(t *testing.T) {
	descriptor := DescribeProviderEvent(ProviderEventIdentityMissing)

	if descriptor.Name != ProviderEventIdentityMissing {
		t.Fatalf("identity missing event name = %q, want %q", descriptor.Name, ProviderEventIdentityMissing)
	}

	if descriptor.Class != ProviderEventClassStorageCheckpoint {
		t.Fatalf("identity missing class = %q, want %q", descriptor.Class, ProviderEventClassStorageCheckpoint)
	}

	if descriptor.Severity != ProviderEventSeverityWarning {
		t.Fatalf("identity missing severity = %q, want %q", descriptor.Severity, ProviderEventSeverityWarning)
	}

	if descriptor.TrustRelevant {
		t.Fatal("identity missing should not be trust relevant by default")
	}
}
