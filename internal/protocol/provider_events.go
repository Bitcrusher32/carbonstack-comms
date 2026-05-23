package protocol

// ProviderEventClass groups provider events by how CarbonStack should reason
// about them. These are policy-facing categories, not provider-specific
// cryptographic internals.
type ProviderEventClass string

const (
	ProviderEventClassLifecycle         ProviderEventClass = "lifecycle"
	ProviderEventClassPublicSetup       ProviderEventClass = "public_setup"
	ProviderEventClassMembership        ProviderEventClass = "membership"
	ProviderEventClassMessage           ProviderEventClass = "message"
	ProviderEventClassStorageCheckpoint ProviderEventClass = "storage_checkpoint"
	ProviderEventClassTrustSecurity     ProviderEventClass = "trust_security"
	ProviderEventClassTerminalFatal     ProviderEventClass = "terminal_fatal"
	ProviderEventClassUnknown           ProviderEventClass = "unknown"
)

// ProviderEventSeverity is the local policy severity CarbonStack assigns to
// provider events before user-facing trust behavior is implemented.
type ProviderEventSeverity string

const (
	ProviderEventSeverityDebug    ProviderEventSeverity = "debug"
	ProviderEventSeverityInfo     ProviderEventSeverity = "info"
	ProviderEventSeverityNotice   ProviderEventSeverity = "notice"
	ProviderEventSeverityWarning  ProviderEventSeverity = "warning"
	ProviderEventSeveritySecurity ProviderEventSeverity = "security"
	ProviderEventSeverityFatal    ProviderEventSeverity = "fatal"
)

// ProviderEventName is the stable string name emitted or consumed by
// provider-contract code. OpenMLS scratch fixtures currently exercise a
// subset of these events.
type ProviderEventName string

const (
	ProviderEventFixtureStarted     ProviderEventName = "provider.fixture.started"
	ProviderEventFixtureCompleted   ProviderEventName = "provider.fixture.completed"
	ProviderEventCommandUnsupported ProviderEventName = "provider.command.unsupported"

	ProviderEventPublicBundleCreated ProviderEventName = "provider.public_bundle.created"

	ProviderEventConversationCreated        ProviderEventName = "conversation.created"
	ProviderEventConversationWelcomeCreated ProviderEventName = "conversation.welcome.created"
	ProviderEventConversationWelcomeStaged  ProviderEventName = "conversation.welcome.staged"
	ProviderEventConversationMemberAdded    ProviderEventName = "conversation.member_added"
	ProviderEventConversationJoined         ProviderEventName = "conversation.joined"
	ProviderEventConversationLoaded         ProviderEventName = "conversation.loaded"

	ProviderEventMessageProtected ProviderEventName = "message.protected"
	ProviderEventMessageOpened    ProviderEventName = "message.opened"

	ProviderEventStorageSaveRequired ProviderEventName = "storage.save.required"
	ProviderEventStorageSaved        ProviderEventName = "storage.saved"
	ProviderEventStorageLoadStarted  ProviderEventName = "storage.load.started"
	ProviderEventStorageLoaded       ProviderEventName = "storage.loaded"
	ProviderEventStorageMissing      ProviderEventName = "storage.missing"
	ProviderEventStorageCorrupt      ProviderEventName = "storage.corrupt"
	ProviderEventCheckpointRequired  ProviderEventName = "checkpoint.required"
	ProviderEventCheckpointCompleted ProviderEventName = "checkpoint.completed"
	ProviderEventCheckpointFailed    ProviderEventName = "checkpoint.failed"

	ProviderEventSignatureInvalid ProviderEventName = "provider.signature.invalid"
	ProviderEventIdentityChanged  ProviderEventName = "provider.identity.changed"
	ProviderEventReverifyRequired ProviderEventName = "provider.identity.reverify.required"
	ProviderEventTamperDetected   ProviderEventName = "provider.message.tamper.detected"
	ProviderEventReplayDetected   ProviderEventName = "provider.replay.detected"
	ProviderEventStaleEpoch       ProviderEventName = "provider.epoch.stale"

	ProviderEventFatal              ProviderEventName = "provider.fatal"
	ProviderEventStateInconsistent  ProviderEventName = "provider.state.inconsistent"
	ProviderEventGroupUnrecoverable ProviderEventName = "provider.group.unrecoverable"
	ProviderEventSecretUnavailable  ProviderEventName = "provider.secret.material.unavailable"
	ProviderEventInvariantViolation ProviderEventName = "provider.invariant.violation"
)

// ProviderEventDescriptor gives CarbonStack a stable local classification for
// a provider event name. It does not execute trust policy yet.
type ProviderEventDescriptor struct {
	Name          ProviderEventName
	Class         ProviderEventClass
	Severity      ProviderEventSeverity
	TrustRelevant bool
}

// DescribeProviderEvent maps a provider event name into the current
// CarbonStack event taxonomy. Unknown events are intentionally non-fatal here:
// future provider versions may introduce events before policy catches up.
func DescribeProviderEvent(name ProviderEventName) ProviderEventDescriptor {
	switch name {
	case ProviderEventFixtureStarted, ProviderEventFixtureCompleted:
		return ProviderEventDescriptor{
			Name:          name,
			Class:         ProviderEventClassLifecycle,
			Severity:      ProviderEventSeverityDebug,
			TrustRelevant: false,
		}
	case ProviderEventCommandUnsupported:
		return ProviderEventDescriptor{
			Name:          name,
			Class:         ProviderEventClassLifecycle,
			Severity:      ProviderEventSeverityWarning,
			TrustRelevant: false,
		}

	case ProviderEventPublicBundleCreated:
		return ProviderEventDescriptor{
			Name:          name,
			Class:         ProviderEventClassPublicSetup,
			Severity:      ProviderEventSeverityInfo,
			TrustRelevant: false,
		}

	case ProviderEventConversationCreated,
		ProviderEventConversationWelcomeCreated,
		ProviderEventConversationWelcomeStaged,
		ProviderEventConversationMemberAdded,
		ProviderEventConversationJoined,
		ProviderEventConversationLoaded:
		return ProviderEventDescriptor{
			Name:          name,
			Class:         ProviderEventClassMembership,
			Severity:      ProviderEventSeverityNotice,
			TrustRelevant: name == ProviderEventConversationMemberAdded,
		}

	case ProviderEventMessageProtected, ProviderEventMessageOpened:
		return ProviderEventDescriptor{
			Name:          name,
			Class:         ProviderEventClassMessage,
			Severity:      ProviderEventSeverityInfo,
			TrustRelevant: false,
		}

	case ProviderEventStorageSaveRequired,
		ProviderEventStorageSaved,
		ProviderEventStorageLoadStarted,
		ProviderEventStorageLoaded,
		ProviderEventStorageMissing,
		ProviderEventStorageCorrupt,
		ProviderEventCheckpointRequired,
		ProviderEventCheckpointCompleted,
		ProviderEventCheckpointFailed:
		severity := ProviderEventSeverityNotice
		if name == ProviderEventStorageMissing ||
			name == ProviderEventStorageCorrupt ||
			name == ProviderEventCheckpointFailed {
			severity = ProviderEventSeverityWarning
		}

		return ProviderEventDescriptor{
			Name:          name,
			Class:         ProviderEventClassStorageCheckpoint,
			Severity:      severity,
			TrustRelevant: false,
		}

	case ProviderEventSignatureInvalid,
		ProviderEventIdentityChanged,
		ProviderEventReverifyRequired,
		ProviderEventTamperDetected,
		ProviderEventReplayDetected,
		ProviderEventStaleEpoch:
		return ProviderEventDescriptor{
			Name:          name,
			Class:         ProviderEventClassTrustSecurity,
			Severity:      ProviderEventSeveritySecurity,
			TrustRelevant: true,
		}

	case ProviderEventFatal,
		ProviderEventStateInconsistent,
		ProviderEventGroupUnrecoverable,
		ProviderEventSecretUnavailable,
		ProviderEventInvariantViolation:
		return ProviderEventDescriptor{
			Name:          name,
			Class:         ProviderEventClassTerminalFatal,
			Severity:      ProviderEventSeverityFatal,
			TrustRelevant: true,
		}

	default:
		return ProviderEventDescriptor{
			Name:          name,
			Class:         ProviderEventClassUnknown,
			Severity:      ProviderEventSeverityWarning,
			TrustRelevant: false,
		}
	}
}
