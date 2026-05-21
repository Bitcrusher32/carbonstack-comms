package protocol

import (
	"context"
	"testing"
)

func TestMockProviderIdentityBundleAndVerification(t *testing.T) {
	ctx := context.Background()
	provider := NewMockProvider()

	identity, err := provider.CreateIdentity(ctx, "device-1")
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}

	if identity.Provider != ProviderMock {
		t.Fatalf("expected provider %s, got %s", ProviderMock, identity.Provider)
	}

	bundle, err := provider.PublicBundle(ctx, identity)
	if err != nil {
		t.Fatalf("public bundle: %v", err)
	}

	if bundle.DeviceID != "device-1" {
		t.Fatalf("expected device-1 bundle, got %s", bundle.DeviceID)
	}

	verification, err := provider.PublicVerification(ctx, identity)
	if err != nil {
		t.Fatalf("public verification: %v", err)
	}

	if verification.Fingerprint == "" {
		t.Fatalf("expected fingerprint")
	}
}

func TestMockProviderProtectOpenRoundTrip(t *testing.T) {
	ctx := context.Background()
	provider := NewMockProvider()

	alice, err := provider.CreateIdentity(ctx, "alice-device")
	if err != nil {
		t.Fatalf("create alice identity: %v", err)
	}

	state, err := provider.CreateConversation(ctx, alice, []string{"bob-device"})
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}

	protected, nextState, err := provider.ProtectMessage(ctx, state, ProtectRequest{
		ConversationID: state.ConversationID,
		SenderDeviceID: "alice-device",
		Plaintext:      []byte("hello through protocol provider"),
	})
	if err != nil {
		t.Fatalf("protect message: %v", err)
	}

	if protected.ContentType != MockContentType {
		t.Fatalf("unexpected content type: %s", protected.ContentType)
	}

	opened, _, err := provider.OpenMessage(ctx, nextState, OpenRequest{
		ConversationID:    state.ConversationID,
		RecipientDeviceID: "bob-device",
		Message:           protected,
	})
	if err != nil {
		t.Fatalf("open message: %v", err)
	}

	if string(opened.Plaintext) != "hello through protocol provider" {
		t.Fatalf("unexpected plaintext: %s", string(opened.Plaintext))
	}

	if len(opened.Signals) != 1 || opened.Signals[0].Type != SignalMessageOpened {
		t.Fatalf("expected message_opened signal")
	}
}

func TestMockProviderExportImportState(t *testing.T) {
	ctx := context.Background()
	provider := NewMockProvider()

	identity, err := provider.CreateIdentity(ctx, "device-1")
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}

	state, err := provider.CreateConversation(ctx, identity, []string{"device-2"})
	if err != nil {
		t.Fatalf("create conversation: %v", err)
	}

	exported, err := provider.ExportState(ctx, state)
	if err != nil {
		t.Fatalf("export state: %v", err)
	}

	imported, err := provider.ImportState(ctx, exported)
	if err != nil {
		t.Fatalf("import state: %v", err)
	}

	if imported.ConversationID != state.ConversationID {
		t.Fatalf("conversation id mismatch")
	}

	if imported.Epoch != state.Epoch {
		t.Fatalf("epoch mismatch")
	}
}
