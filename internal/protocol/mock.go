package protocol

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	MockContentType = "carbonstack.message.text.mock-provider.v0"
)

type MockProvider struct{}

func NewMockProvider() MockProvider {
	return MockProvider{}
}

func (MockProvider) Name() ProviderName {
	return ProviderMock
}

func (MockProvider) CreateIdentity(ctx context.Context, deviceID string) (ProviderIdentity, error) {
	if deviceID == "" {
		return ProviderIdentity{}, errors.New("deviceID is required")
	}

	public := "mock-public-identity-" + deviceID

	return ProviderIdentity{
		Provider:       ProviderMock,
		DeviceID:       deviceID,
		PublicMaterial: public,
		PrivateState:   []byte("mock-private-state-" + deviceID),
	}, nil
}

func (MockProvider) PublicBundle(ctx context.Context, identity ProviderIdentity) (PublicBundle, error) {
	if identity.DeviceID == "" {
		return PublicBundle{}, errors.New("identity device_id is required")
	}

	return PublicBundle{
		Provider:       ProviderMock,
		DeviceID:       identity.DeviceID,
		BundleType:     "mock-public-bundle-v0",
		PublicMaterial: identity.PublicMaterial,
	}, nil
}

func (MockProvider) PublicVerification(ctx context.Context, identity ProviderIdentity) (PublicVerification, error) {
	if identity.DeviceID == "" {
		return PublicVerification{}, errors.New("identity device_id is required")
	}

	return PublicVerification{
		Provider:    ProviderMock,
		DeviceID:    identity.DeviceID,
		Fingerprint: mockFingerprint(identity.PublicMaterial),
		Material:    identity.PublicMaterial,
	}, nil
}

func (MockProvider) CreateConversation(ctx context.Context, creator ProviderIdentity, memberDeviceIDs []string) (ConversationState, error) {
	if creator.DeviceID == "" {
		return ConversationState{}, errors.New("creator device_id is required")
	}

	members := append([]string{creator.DeviceID}, memberDeviceIDs...)

	return ConversationState{
		Provider:       ProviderMock,
		ConversationID: ConversationID("mock-conversation-" + creator.DeviceID),
		Epoch:          1,
		Members:        members,
		ProviderState:  []byte("mock-conversation-state"),
	}, nil
}

func (MockProvider) JoinConversation(ctx context.Context, identity ProviderIdentity, welcome []byte) (ConversationState, error) {
	if identity.DeviceID == "" {
		return ConversationState{}, errors.New("identity device_id is required")
	}

	return ConversationState{
		Provider:       ProviderMock,
		ConversationID: ConversationID("mock-joined-conversation-" + identity.DeviceID),
		Epoch:          1,
		Members:        []string{identity.DeviceID},
		ProviderState:  welcome,
	}, nil
}

func (MockProvider) ProtectMessage(ctx context.Context, state ConversationState, req ProtectRequest) (ProtectedMessage, ConversationState, error) {
	if req.SenderDeviceID == "" {
		return ProtectedMessage{}, state, errors.New("sender device_id is required")
	}

	payload := []byte(base64.StdEncoding.EncodeToString(req.Plaintext))

	msg := ProtectedMessage{
		Provider:       ProviderMock,
		ConversationID: state.ConversationID,
		Epoch:          state.Epoch,
		SenderDeviceID: req.SenderDeviceID,
		ContentType:    MockContentType,
		Payload:        payload,
		Signals: []ProviderEvent{
			{
				Type:           SignalMessageProtected,
				DeviceID:       req.SenderDeviceID,
				ConversationID: string(state.ConversationID),
				Epoch:          uint64(state.Epoch),
				Message:        "mock provider protected message with base64 payload",
			},
		},
	}

	return msg, state, nil
}

func (MockProvider) OpenMessage(ctx context.Context, state ConversationState, req OpenRequest) (OpenedMessage, ConversationState, error) {
	if req.RecipientDeviceID == "" {
		return OpenedMessage{}, state, errors.New("recipient device_id is required")
	}

	decoded, err := base64.StdEncoding.DecodeString(string(req.Message.Payload))
	if err != nil {
		return OpenedMessage{}, state, fmt.Errorf("mock decode payload: %w", err)
	}

	opened := OpenedMessage{
		Provider:       ProviderMock,
		ConversationID: req.Message.ConversationID,
		Epoch:          req.Message.Epoch,
		SenderDeviceID: req.Message.SenderDeviceID,
		Plaintext:      decoded,
		Signals: []ProviderEvent{
			{
				Type:           SignalMessageOpened,
				DeviceID:       req.Message.SenderDeviceID,
				ConversationID: string(req.Message.ConversationID),
				Epoch:          uint64(req.Message.Epoch),
				Message:        "mock provider opened message",
			},
		},
	}

	return opened, state, nil
}

func (MockProvider) ExportState(ctx context.Context, state ConversationState) ([]byte, error) {
	return json.Marshal(state)
}

func (MockProvider) ImportState(ctx context.Context, data []byte) (ConversationState, error) {
	var state ConversationState
	if err := json.Unmarshal(data, &state); err != nil {
		return ConversationState{}, err
	}
	return state, nil
}

func mockFingerprint(material string) string {
	if material == "" {
		return "MOCK-FP-EMPTY"
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(material))
	if len(encoded) > 16 {
		encoded = encoded[:16]
	}

	return "MOCK-FP-" + encoded
}
