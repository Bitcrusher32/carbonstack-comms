package protocol

import "context"

type ProviderName string

const (
	ProviderMock ProviderName = "mock"
)

type TrustSignal string

const (
	SignalNone               TrustSignal = "none"
	SignalIdentityCreated    TrustSignal = "identity_created"
	SignalPublicBundleMade   TrustSignal = "public_bundle_created"
	SignalConversationMade   TrustSignal = "conversation_created"
	SignalConversationJoined TrustSignal = "conversation_joined"
	SignalMessageProtected   TrustSignal = "message_protected"
	SignalMessageOpened      TrustSignal = "message_opened"
	SignalIdentityChanged    TrustSignal = "identity_changed"
	SignalMembershipChanged  TrustSignal = "membership_changed"
	SignalMemberAdded        TrustSignal = "member_added"
	SignalMemberRemoved      TrustSignal = "member_removed"
	SignalReplayDetected     TrustSignal = "replay_detected"
	SignalStaleEpoch         TrustSignal = "stale_epoch"
	SignalMalformedMessage   TrustSignal = "malformed_message"
	SignalDecryptFailed      TrustSignal = "decrypt_failed"
	SignalStateUpdated       TrustSignal = "state_updated"
)

type ProviderIdentity struct {
	Provider       ProviderName `json:"provider"`
	DeviceID       string       `json:"device_id"`
	PublicMaterial string       `json:"public_material"`
	PrivateState   []byte       `json:"private_state"`
}

type PublicBundle struct {
	Provider       ProviderName `json:"provider"`
	DeviceID       string       `json:"device_id"`
	BundleType     string       `json:"bundle_type"`
	PublicMaterial string       `json:"public_material"`
}

type PublicVerification struct {
	Provider    ProviderName `json:"provider"`
	DeviceID    string       `json:"device_id"`
	Fingerprint string       `json:"fingerprint"`
	Material    string       `json:"material"`
}

type ConversationID string
type ConversationEpoch uint64

type ConversationState struct {
	Provider       ProviderName      `json:"provider"`
	ConversationID ConversationID    `json:"conversation_id"`
	Epoch          ConversationEpoch `json:"epoch"`
	Members        []string          `json:"members"`
	ProviderState  []byte            `json:"provider_state"`
}

type ProtectRequest struct {
	ConversationID ConversationID `json:"conversation_id"`
	SenderDeviceID string         `json:"sender_device_id"`
	Plaintext      []byte         `json:"plaintext"`
}

type ProtectedMessage struct {
	Provider       ProviderName      `json:"provider"`
	ConversationID ConversationID    `json:"conversation_id"`
	Epoch          ConversationEpoch `json:"epoch"`
	SenderDeviceID string            `json:"sender_device_id"`
	ContentType    string            `json:"content_type"`
	Payload        []byte            `json:"payload"`
	Signals        []ProviderEvent   `json:"signals"`
}

type OpenRequest struct {
	ConversationID    ConversationID   `json:"conversation_id"`
	RecipientDeviceID string           `json:"recipient_device_id"`
	Message           ProtectedMessage `json:"message"`
}

type OpenedMessage struct {
	Provider       ProviderName      `json:"provider"`
	ConversationID ConversationID    `json:"conversation_id"`
	Epoch          ConversationEpoch `json:"epoch"`
	SenderDeviceID string            `json:"sender_device_id"`
	Plaintext      []byte            `json:"plaintext"`
	Signals        []ProviderEvent   `json:"signals"`
}

type ProviderEvent struct {
	Type           TrustSignal `json:"type"`
	DeviceID       string      `json:"device_id,omitempty"`
	ConversationID string      `json:"conversation_id,omitempty"`
	Epoch          uint64      `json:"epoch,omitempty"`
	Message        string      `json:"message,omitempty"`
}

type Provider interface {
	Name() ProviderName

	CreateIdentity(ctx context.Context, deviceID string) (ProviderIdentity, error)
	PublicBundle(ctx context.Context, identity ProviderIdentity) (PublicBundle, error)
	PublicVerification(ctx context.Context, identity ProviderIdentity) (PublicVerification, error)

	CreateConversation(ctx context.Context, creator ProviderIdentity, memberDeviceIDs []string) (ConversationState, error)
	JoinConversation(ctx context.Context, identity ProviderIdentity, welcome []byte) (ConversationState, error)

	ProtectMessage(ctx context.Context, state ConversationState, req ProtectRequest) (ProtectedMessage, ConversationState, error)
	OpenMessage(ctx context.Context, state ConversationState, req OpenRequest) (OpenedMessage, ConversationState, error)

	ExportState(ctx context.Context, state ConversationState) ([]byte, error)
	ImportState(ctx context.Context, data []byte) (ConversationState, error)
}
