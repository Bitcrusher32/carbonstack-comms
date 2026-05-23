package protocol

// ProviderTrustAction is a candidate local policy action derived from a
// provider event. These actions are not wired into CLI behavior yet.
type ProviderTrustAction string

const (
	ProviderTrustActionNone                ProviderTrustAction = "none"
	ProviderTrustActionAppendHistory       ProviderTrustAction = "append_history"
	ProviderTrustActionDebugOnly           ProviderTrustAction = "debug_only"
	ProviderTrustActionWarnUser            ProviderTrustAction = "warn_user"
	ProviderTrustActionBlockSend           ProviderTrustAction = "block_send"
	ProviderTrustActionBlockReceive        ProviderTrustAction = "block_receive"
	ProviderTrustActionBlockOpen           ProviderTrustAction = "block_open"
	ProviderTrustActionQuarantineMessage   ProviderTrustAction = "quarantine_message"
	ProviderTrustActionRequireReverify     ProviderTrustAction = "require_reverify"
	ProviderTrustActionMarkIdentityChanged ProviderTrustAction = "mark_identity_changed"
	ProviderTrustActionShowRecoveryPath    ProviderTrustAction = "show_recovery_path"
	ProviderTrustActionStopOperation       ProviderTrustAction = "stop_operation"
	ProviderTrustActionFatalLocalState     ProviderTrustAction = "fatal_local_state"
)

// ProviderTrustDecision is a pure pre-integration policy result. It does not
// mutate trust storage and does not perform user-facing CLI behavior.
type ProviderTrustDecision struct {
	Event            ProviderEventName
	Descriptor       ProviderEventDescriptor
	Actions          []ProviderTrustAction
	BlocksSend       bool
	BlocksReceive    bool
	BlocksOpen       bool
	RequiresReverify bool
	UserVisible      bool
	HistoryRelevant  bool
}

// DecideProviderTrust maps provider event descriptors to candidate trust
// actions. This is intentionally pure and pre-integration.
func DecideProviderTrust(name ProviderEventName) ProviderTrustDecision {
	descriptor := DescribeProviderEvent(name)

	decision := ProviderTrustDecision{
		Event:           name,
		Descriptor:      descriptor,
		Actions:         []ProviderTrustAction{},
		HistoryRelevant: false,
	}

	switch name {
	case ProviderEventFixtureStarted, ProviderEventFixtureCompleted:
		decision.Actions = []ProviderTrustAction{ProviderTrustActionDebugOnly}

	case ProviderEventPublicBundleCreated,
		ProviderEventConversationCreated,
		ProviderEventConversationWelcomeCreated,
		ProviderEventConversationWelcomeStaged,
		ProviderEventConversationJoined,
		ProviderEventConversationLoaded,
		ProviderEventMessageProtected,
		ProviderEventMessageOpened:
		decision.Actions = []ProviderTrustAction{ProviderTrustActionAppendHistory}
		decision.HistoryRelevant = true

	case ProviderEventConversationMemberAdded:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionAppendHistory,
			ProviderTrustActionWarnUser,
		}
		decision.HistoryRelevant = true
		decision.UserVisible = true

	case ProviderEventStorageMissing:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionStopOperation,
			ProviderTrustActionShowRecoveryPath,
		}
		decision.BlocksSend = true
		decision.UserVisible = true

	case ProviderEventStorageCorrupt, ProviderEventCheckpointFailed:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionStopOperation,
			ProviderTrustActionWarnUser,
			ProviderTrustActionShowRecoveryPath,
		}
		decision.BlocksSend = true
		decision.BlocksReceive = true
		decision.UserVisible = true
		decision.HistoryRelevant = true

	case ProviderEventSignatureInvalid:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionBlockOpen,
			ProviderTrustActionWarnUser,
			ProviderTrustActionAppendHistory,
			ProviderTrustActionRequireReverify,
		}
		decision.BlocksOpen = true
		decision.RequiresReverify = true
		decision.UserVisible = true
		decision.HistoryRelevant = true

	case ProviderEventIdentityChanged:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionMarkIdentityChanged,
			ProviderTrustActionBlockSend,
			ProviderTrustActionBlockReceive,
			ProviderTrustActionRequireReverify,
			ProviderTrustActionWarnUser,
		}
		decision.BlocksSend = true
		decision.BlocksReceive = true
		decision.RequiresReverify = true
		decision.UserVisible = true
		decision.HistoryRelevant = true

	case ProviderEventReverifyRequired:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionRequireReverify,
			ProviderTrustActionBlockSend,
			ProviderTrustActionWarnUser,
		}
		decision.BlocksSend = true
		decision.RequiresReverify = true
		decision.UserVisible = true
		decision.HistoryRelevant = true

	case ProviderEventTamperDetected, ProviderEventReplayDetected, ProviderEventStaleEpoch:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionBlockOpen,
			ProviderTrustActionQuarantineMessage,
			ProviderTrustActionWarnUser,
			ProviderTrustActionAppendHistory,
		}
		decision.BlocksOpen = true
		decision.UserVisible = true
		decision.HistoryRelevant = true

	case ProviderEventGroupUnrecoverable:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionFatalLocalState,
			ProviderTrustActionStopOperation,
			ProviderTrustActionShowRecoveryPath,
		}
		decision.BlocksSend = true
		decision.BlocksReceive = true
		decision.BlocksOpen = true
		decision.UserVisible = true
		decision.HistoryRelevant = true

	case ProviderEventSecretUnavailable:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionFatalLocalState,
			ProviderTrustActionBlockSend,
			ProviderTrustActionShowRecoveryPath,
		}
		decision.BlocksSend = true
		decision.UserVisible = true
		decision.HistoryRelevant = true

	case ProviderEventFatal,
		ProviderEventStateInconsistent,
		ProviderEventInvariantViolation:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionFatalLocalState,
			ProviderTrustActionStopOperation,
			ProviderTrustActionWarnUser,
		}
		decision.BlocksSend = true
		decision.BlocksReceive = true
		decision.BlocksOpen = true
		decision.UserVisible = true
		decision.HistoryRelevant = true
	case ProviderEventIdentityMissing:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionStopOperation,
			ProviderTrustActionShowRecoveryPath,
			ProviderTrustActionAppendHistory,
		}
		decision.BlocksSend = true
		decision.HistoryRelevant = true

	default:
		decision.Actions = []ProviderTrustAction{
			ProviderTrustActionAppendHistory,
			ProviderTrustActionDebugOnly,
		}
		decision.HistoryRelevant = true
	}

	if len(decision.Actions) == 0 {
		decision.Actions = []ProviderTrustAction{ProviderTrustActionNone}
	}

	return decision
}

func ProviderTrustDecisionHasAction(decision ProviderTrustDecision, action ProviderTrustAction) bool {
	for _, candidate := range decision.Actions {
		if candidate == action {
			return true
		}
	}

	return false
}
