package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenMLSSidecarMessageOpenWrongDeviceRejected(t *testing.T) {
	removeOpenMLSSidecarState(t)

	addMemberEnvelope := setupOpenMLSTwoMemberConversation(t)

	eveIdentityOutput, eveIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-eve-device")
	if eveIdentityErr != nil {
		t.Fatalf("eve identity-create failed: %v\n%s", eveIdentityErr, string(eveIdentityOutput))
	}

	message1ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0001", "hello bob wrong device probe")

	wrongDeviceOutput, wrongDeviceErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-eve-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "wrong-device-message-0001",
		"--message", message1ProtectEnvelope.Data.MessageArtifactPathHint,
	)
	assertExitCode(t, wrongDeviceErr, 3)

	wrongDeviceEnvelope := parseSidecarEnvelope(t, wrongDeviceOutput)
	if wrongDeviceEnvelope.OK {
		t.Fatal("wrong-device message-open ok = true, want false")
	}

	assertSidecarError(t, wrongDeviceEnvelope, "conversation_or_message_missing", "provider.conversation.missing", "warning", false)

	if wrongDeviceEnvelope.Error == nil {
		t.Fatal("wrong-device message-open should include error")
	}

	if wrongDeviceEnvelope.Error.Message != "device conversation provider storage is missing" {
		t.Fatalf("wrong-device message-open error message = %q, want device conversation provider storage is missing", wrongDeviceEnvelope.Error.Message)
	}

	if wrongDeviceEnvelope.Data.DeviceLabel != "carbonstack-eve-device" {
		t.Fatalf("wrong-device data device_label = %q, want carbonstack-eve-device", wrongDeviceEnvelope.Data.DeviceLabel)
	}

	if wrongDeviceEnvelope.Data.ConversationLabel != addMemberEnvelope.Data.ConversationLabel {
		t.Fatalf("wrong-device data conversation_label = %q, want %q", wrongDeviceEnvelope.Data.ConversationLabel, addMemberEnvelope.Data.ConversationLabel)
	}

	assertNoSecretMaterialInStdout(t, wrongDeviceOutput)
}

func TestOpenMLSSidecarMessageOpenWrongConversationRejected(t *testing.T) {
	removeOpenMLSSidecarState(t)

	setupOpenMLSTwoMemberConversation(t)

	message1ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0001", "hello bob wrong conversation probe")

	wrongConversationOutput, wrongConversationErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-wrong-conversation",
		"--message-label", "wrong-conversation-message-0001",
		"--message", message1ProtectEnvelope.Data.MessageArtifactPathHint,
	)
	assertExitCode(t, wrongConversationErr, 3)

	wrongConversationEnvelope := parseSidecarEnvelope(t, wrongConversationOutput)
	if wrongConversationEnvelope.OK {
		t.Fatal("wrong-conversation message-open ok = true, want false")
	}

	assertSidecarError(t, wrongConversationEnvelope, "conversation_or_message_missing", "provider.conversation.missing", "warning", false)

	if wrongConversationEnvelope.Error == nil {
		t.Fatal("wrong-conversation message-open should include error")
	}

	if wrongConversationEnvelope.Error.Message != "device conversation provider storage is missing" {
		t.Fatalf("wrong-conversation message-open error message = %q, want device conversation provider storage is missing", wrongConversationEnvelope.Error.Message)
	}

	if wrongConversationEnvelope.Data.DeviceLabel != "carbonstack-bob-device" {
		t.Fatalf("wrong-conversation data device_label = %q, want carbonstack-bob-device", wrongConversationEnvelope.Data.DeviceLabel)
	}

	if wrongConversationEnvelope.Data.ConversationLabel != "carbonstack-wrong-conversation" {
		t.Fatalf("wrong-conversation data conversation_label = %q, want carbonstack-wrong-conversation", wrongConversationEnvelope.Data.ConversationLabel)
	}

	assertNoSecretMaterialInStdout(t, wrongConversationOutput)
}

func TestOpenMLSSidecarMessageOpenDuplicateRejected(t *testing.T) {
	removeOpenMLSSidecarState(t)

	addMemberEnvelope := setupOpenMLSTwoMemberConversation(t)

	message1ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0001", "hello bob 1")

	message1OpenEnvelope, message1OpenOutput := openOpenMLSSidecarMessage(t, "message-0001", message1ProtectEnvelope.Data.MessageArtifactPathHint)
	assertMessageOpenSuccess(t, message1OpenEnvelope, "message-0001", "hello bob 1", addMemberEnvelope.Data.GroupIDRef)
	assertNoSecretMaterialInStdout(t, message1OpenOutput)

	duplicateOpenOutput, duplicateOpenErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0001-duplicate",
		"--message", message1ProtectEnvelope.Data.MessageArtifactPathHint,
	)
	assertExitCode(t, duplicateOpenErr, 3)

	duplicateOpenEnvelope := parseSidecarEnvelope(t, duplicateOpenOutput)
	if duplicateOpenEnvelope.OK {
		t.Fatal("duplicate message-open ok = true, want false")
	}

	assertSidecarError(t, duplicateOpenEnvelope, "message_open_failed", "checkpoint.failed", "warning", false)

	if duplicateOpenEnvelope.Error == nil {
		t.Fatal("duplicate message-open should include error")
	}

	if !strings.Contains(duplicateOpenEnvelope.Error.Message, "SecretReuseError") {
		t.Fatalf("duplicate message-open error message = %q, want SecretReuseError", duplicateOpenEnvelope.Error.Message)
	}

	assertNoSecretMaterialInStdout(t, duplicateOpenOutput)
}

func TestOpenMLSSidecarMessageOpenCorruptArtifactRejected(t *testing.T) {
	removeOpenMLSSidecarState(t)

	setupOpenMLSTwoMemberConversation(t)

	message1ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0001", "hello bob 1")

	goodPath := filepath.Join(openMLSSidecarDir, message1ProtectEnvelope.Data.MessageArtifactPathHint)
	badPath := filepath.Join(filepath.Dir(goodPath), "corrupt-application-message.bin")
	badPathHint, relErr := filepath.Rel(openMLSSidecarDir, badPath)
	if relErr != nil {
		t.Fatalf("make corrupt message artifact relative path: %v", relErr)
	}
	badPathHint = "." + string(os.PathSeparator) + badPathHint

	goodBytes, readErr := os.ReadFile(filepath.Clean(goodPath))
	if readErr != nil {
		t.Fatalf("read good message artifact: %v", readErr)
	}

	if len(goodBytes) < 20 {
		t.Fatalf("message artifact too short to truncate safely: len=%d", len(goodBytes))
	}

	truncatedBytes := append([]byte(nil), goodBytes[:len(goodBytes)-10]...)
	if writeErr := os.WriteFile(filepath.Clean(badPath), truncatedBytes, 0o600); writeErr != nil {
		t.Fatalf("write corrupt message artifact: %v", writeErr)
	}

	corruptOpenOutput, corruptOpenErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "corrupt-message-0001",
		"--message", badPathHint,
	)
	assertExitCode(t, corruptOpenErr, 3)

	corruptOpenEnvelope := parseSidecarEnvelope(t, corruptOpenOutput)
	if corruptOpenEnvelope.OK {
		t.Fatal("corrupt message-open ok = true, want false")
	}

	assertSidecarError(t, corruptOpenEnvelope, "message_artifact_invalid", "provider.message.invalid", "warning", false)

	if corruptOpenEnvelope.Error == nil {
		t.Fatal("corrupt message-open should include error")
	}

	if !strings.Contains(corruptOpenEnvelope.Error.Message, "EndOfStream") {
		t.Fatalf("corrupt message-open error message = %q, want EndOfStream", corruptOpenEnvelope.Error.Message)
	}

	assertNoSecretMaterialInStdout(t, corruptOpenOutput)
}
