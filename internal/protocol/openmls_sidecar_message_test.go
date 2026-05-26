package protocol

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenMLSSidecarMessageProtectOpenOneWay(t *testing.T) {
	removeOpenMLSSidecarState(t)

	aliceIdentityOutput, aliceIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if aliceIdentityErr != nil {
		t.Fatalf("alice identity-create failed: %v\n%s", aliceIdentityErr, string(aliceIdentityOutput))
	}

	bobIdentityOutput, bobIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-bob-device")
	if bobIdentityErr != nil {
		t.Fatalf("bob identity-create failed: %v\n%s", bobIdentityErr, string(bobIdentityOutput))
	}

	bobBundleOutput, bobBundleErr := runOpenMLSSidecar("public-bundle-export", "--device-label", "carbonstack-bob-device", "--write-artifact")
	if bobBundleErr != nil {
		t.Fatalf("bob public-bundle-export failed: %v\n%s", bobBundleErr, string(bobBundleOutput))
	}

	bobBundleEnvelope := parseSidecarEnvelope(t, bobBundleOutput)
	if !bobBundleEnvelope.OK {
		t.Fatal("bob public-bundle-export ok = false, want true")
	}

	if !bobBundleEnvelope.Data.ProviderStorageWritten {
		t.Fatal("bob public-bundle-export should persist provider storage for later Welcome consumption")
	}

	if bobBundleEnvelope.Data.KeyPackageArtifactPathHint == "" {
		t.Fatal("bob public-bundle-export should return KeyPackage artifact path")
	}

	aliceConversationOutput, aliceConversationErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if aliceConversationErr != nil {
		t.Fatalf("alice conversation-create failed: %v\n%s", aliceConversationErr, string(aliceConversationOutput))
	}

	addMemberOutput, addMemberErr := runOpenMLSSidecar(
		"conversation-add-member",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--member-keypackage", bobBundleEnvelope.Data.KeyPackageArtifactPathHint,
	)
	if addMemberErr != nil {
		t.Fatalf("conversation-add-member failed: %v\n%s", addMemberErr, string(addMemberOutput))
	}

	addMemberEnvelope := parseSidecarEnvelope(t, addMemberOutput)
	if !addMemberEnvelope.OK {
		t.Fatal("conversation-add-member ok = false, want true")
	}

	if addMemberEnvelope.Data.WelcomeArtifactPathHint == "" {
		t.Fatal("conversation-add-member should return Welcome artifact path")
	}

	joinOutput, joinErr := runOpenMLSSidecar(
		"conversation-join",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--welcome", addMemberEnvelope.Data.WelcomeArtifactPathHint,
	)
	if joinErr != nil {
		t.Fatalf("conversation-join failed: %v\n%s", joinErr, string(joinOutput))
	}

	joinEnvelope := parseSidecarEnvelope(t, joinOutput)
	if !joinEnvelope.OK {
		t.Fatal("conversation-join ok = false, want true")
	}

	if !joinEnvelope.Data.Joined {
		t.Fatal("conversation-join should report joined=true")
	}

	if joinEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("join group_id_ref = %q, add-member group_id_ref = %q", joinEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}

	protectOutput, protectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--plaintext", "hello bob",
	)
	if protectErr != nil {
		t.Fatalf("message-protect failed: %v\n%s", protectErr, string(protectOutput))
	}

	protectEnvelope := parseSidecarEnvelope(t, protectOutput)
	if !protectEnvelope.OK {
		t.Fatal("message-protect ok = false, want true")
	}

	if protectEnvelope.Command != "message-protect" {
		t.Fatalf("command = %q, want message-protect", protectEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, protectEnvelope)

	if protectEnvelope.Phase != "phase2d-message-protect-dev" {
		t.Fatalf("phase = %q, want phase2d-message-protect-dev", protectEnvelope.Phase)
	}

	if protectEnvelope.PrivateMaterialIncluded {
		t.Fatal("message-protect must not include private material")
	}

	if !protectEnvelope.Data.MessageProtected {
		t.Fatal("message-protect should report message_protected=true")
	}

	if !protectEnvelope.Data.ProtectedMessageWritten {
		t.Fatal("message-protect should report protected_message_written=true")
	}

	if !protectEnvelope.Data.ProviderStorageLoaded {
		t.Fatal("message-protect should report provider_storage_loaded=true")
	}

	if !protectEnvelope.Data.ProviderStorageWritten {
		t.Fatal("message-protect should report provider_storage_written=true")
	}

	if !protectEnvelope.Data.GroupReloadable {
		t.Fatal("message-protect should report group_reloadable=true")
	}

	if protectEnvelope.Data.MessageArtifactPathHint == "" {
		t.Fatal("message-protect should return message artifact path")
	}

	if protectEnvelope.Data.MessageManifestPathHint == "" {
		t.Fatal("message-protect should return message manifest path")
	}

	if protectEnvelope.Data.MessageProtectSummaryPathHint == "" {
		t.Fatal("message-protect should return message protect summary path")
	}

	if protectEnvelope.Data.MessageArtifactSHA256 == "" {
		t.Fatal("message-protect should return message artifact sha256")
	}

	if protectEnvelope.Data.MessageArtifactSizeBytes <= 0 {
		t.Fatalf("message-protect message artifact size = %d, want > 0", protectEnvelope.Data.MessageArtifactSizeBytes)
	}

	if protectEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("protect group_id_ref = %q, add-member group_id_ref = %q", protectEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}

	if protectEnvelope.Data.MemberCount != 2 {
		t.Fatalf("message-protect member_count = %d, want 2", protectEnvelope.Data.MemberCount)
	}

	if protectEnvelope.Data.EpochBefore == "" {
		t.Fatal("message-protect should report epoch_before")
	}

	if protectEnvelope.Data.EpochAfter == "" {
		t.Fatal("message-protect should report epoch_after")
	}

	if len(protectEnvelope.Events) != 2 {
		t.Fatalf("message-protect event count = %d, want 2", len(protectEnvelope.Events))
	}

	assertNoSecretMaterialInStdout(t, protectOutput)

	assertFileExists(t, filepath.Join(openMLSSidecarDir, protectEnvelope.Data.MessageArtifactPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, protectEnvelope.Data.MessageManifestPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, protectEnvelope.Data.MessageProtectSummaryPathHint))

	openOutput, openErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message", protectEnvelope.Data.MessageArtifactPathHint,
	)
	if openErr != nil {
		t.Fatalf("message-open failed: %v\n%s", openErr, string(openOutput))
	}

	openEnvelope := parseSidecarEnvelope(t, openOutput)
	if !openEnvelope.OK {
		t.Fatal("message-open ok = false, want true")
	}

	if openEnvelope.Command != "message-open" {
		t.Fatalf("command = %q, want message-open", openEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, openEnvelope)

	if openEnvelope.Phase != "phase2d-message-open-dev" {
		t.Fatalf("phase = %q, want phase2d-message-open-dev", openEnvelope.Phase)
	}

	if openEnvelope.PrivateMaterialIncluded {
		t.Fatal("message-open must not include private material")
	}

	if !openEnvelope.Data.MessageOpened {
		t.Fatal("message-open should report message_opened=true")
	}

	if openEnvelope.Data.PlaintextUTF8 != "hello bob" {
		t.Fatalf("message-open plaintext_utf8 = %q, want hello bob", openEnvelope.Data.PlaintextUTF8)
	}

	if openEnvelope.Data.PlaintextLen != len("hello bob") {
		t.Fatalf("message-open plaintext_len = %d, want %d", openEnvelope.Data.PlaintextLen, len("hello bob"))
	}

	if !openEnvelope.Data.ProviderStorageLoaded {
		t.Fatal("message-open should report provider_storage_loaded=true")
	}

	if !openEnvelope.Data.ProviderStorageWritten {
		t.Fatal("message-open should report provider_storage_written=true")
	}

	if !openEnvelope.Data.GroupReloadable {
		t.Fatal("message-open should report group_reloadable=true")
	}

	if openEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("open group_id_ref = %q, add-member group_id_ref = %q", openEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}

	if openEnvelope.Data.MemberCount != 2 {
		t.Fatalf("message-open member_count = %d, want 2", openEnvelope.Data.MemberCount)
	}

	if openEnvelope.Data.MessageOpenSummaryPathHint == "" {
		t.Fatal("message-open should return message open summary path")
	}

	if len(openEnvelope.Events) != 2 {
		t.Fatalf("message-open event count = %d, want 2", len(openEnvelope.Events))
	}

	assertNoSecretMaterialInStdout(t, openOutput)

	assertFileExists(t, filepath.Join(openMLSSidecarDir, openEnvelope.Data.MessageOpenSummaryPathHint))

	duplicateProtectOutput, duplicateProtectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--plaintext", "hello bob again",
	)
	assertExitCode(t, duplicateProtectErr, 3)

	duplicateProtectEnvelope := parseSidecarEnvelope(t, duplicateProtectOutput)
	if duplicateProtectEnvelope.OK {
		t.Fatal("duplicate message-protect envelope ok = true, want false")
	}

	if duplicateProtectEnvelope.Error == nil {
		t.Fatal("duplicate message-protect should include error")
	}

	if duplicateProtectEnvelope.Error.Code != "message_artifact_exists" {
		t.Fatalf("duplicate message-protect error code = %q, want message_artifact_exists", duplicateProtectEnvelope.Error.Code)
	}

	assertNoSecretMaterialInStdout(t, duplicateProtectOutput)
}

func TestOpenMLSSidecarMessageProtectOpenTwoSequentialMessages(t *testing.T) {
	removeOpenMLSSidecarState(t)

	aliceIdentityOutput, aliceIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if aliceIdentityErr != nil {
		t.Fatalf("alice identity-create failed: %v\n%s", aliceIdentityErr, string(aliceIdentityOutput))
	}

	bobIdentityOutput, bobIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-bob-device")
	if bobIdentityErr != nil {
		t.Fatalf("bob identity-create failed: %v\n%s", bobIdentityErr, string(bobIdentityOutput))
	}

	bobBundleOutput, bobBundleErr := runOpenMLSSidecar("public-bundle-export", "--device-label", "carbonstack-bob-device", "--write-artifact")
	if bobBundleErr != nil {
		t.Fatalf("bob public-bundle-export failed: %v\n%s", bobBundleErr, string(bobBundleOutput))
	}

	bobBundleEnvelope := parseSidecarEnvelope(t, bobBundleOutput)
	if !bobBundleEnvelope.OK {
		t.Fatal("bob public-bundle-export ok = false, want true")
	}

	if !bobBundleEnvelope.Data.ProviderStorageWritten {
		t.Fatal("bob public-bundle-export should persist provider storage for later Welcome consumption")
	}

	aliceConversationOutput, aliceConversationErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if aliceConversationErr != nil {
		t.Fatalf("alice conversation-create failed: %v\n%s", aliceConversationErr, string(aliceConversationOutput))
	}

	addMemberOutput, addMemberErr := runOpenMLSSidecar(
		"conversation-add-member",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--member-keypackage", bobBundleEnvelope.Data.KeyPackageArtifactPathHint,
	)
	if addMemberErr != nil {
		t.Fatalf("conversation-add-member failed: %v\n%s", addMemberErr, string(addMemberOutput))
	}

	addMemberEnvelope := parseSidecarEnvelope(t, addMemberOutput)
	if !addMemberEnvelope.OK {
		t.Fatal("conversation-add-member ok = false, want true")
	}

	joinOutput, joinErr := runOpenMLSSidecar(
		"conversation-join",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--welcome", addMemberEnvelope.Data.WelcomeArtifactPathHint,
	)
	if joinErr != nil {
		t.Fatalf("conversation-join failed: %v\n%s", joinErr, string(joinOutput))
	}

	joinEnvelope := parseSidecarEnvelope(t, joinOutput)
	if !joinEnvelope.OK {
		t.Fatal("conversation-join ok = false, want true")
	}

	if joinEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("join group_id_ref = %q, add-member group_id_ref = %q", joinEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}

	message1ProtectOutput, message1ProtectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0001",
		"--plaintext", "hello bob 1",
	)
	if message1ProtectErr != nil {
		t.Fatalf("message-0001 protect failed: %v\n%s", message1ProtectErr, string(message1ProtectOutput))
	}

	message1ProtectEnvelope := parseSidecarEnvelope(t, message1ProtectOutput)
	assertMessageProtectSuccess(t, message1ProtectEnvelope, "message-0001", "phase2d-message-protect-dev", addMemberEnvelope.Data.GroupIDRef)

	message1OpenOutput, message1OpenErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0001",
		"--message", message1ProtectEnvelope.Data.MessageArtifactPathHint,
	)
	if message1OpenErr != nil {
		t.Fatalf("message-0001 open failed: %v\n%s", message1OpenErr, string(message1OpenOutput))
	}

	message1OpenEnvelope := parseSidecarEnvelope(t, message1OpenOutput)
	assertMessageOpenSuccess(t, message1OpenEnvelope, "message-0001", "hello bob 1", addMemberEnvelope.Data.GroupIDRef)

	message2ProtectOutput, message2ProtectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0002",
		"--plaintext", "hello bob 2",
	)
	if message2ProtectErr != nil {
		t.Fatalf("message-0002 protect failed: %v\n%s", message2ProtectErr, string(message2ProtectOutput))
	}

	message2ProtectEnvelope := parseSidecarEnvelope(t, message2ProtectOutput)
	assertMessageProtectSuccess(t, message2ProtectEnvelope, "message-0002", "phase2d-message-protect-dev", addMemberEnvelope.Data.GroupIDRef)

	if message2ProtectEnvelope.Data.MessageArtifactPathHint == message1ProtectEnvelope.Data.MessageArtifactPathHint {
		t.Fatal("message-0002 artifact path should differ from message-0001 artifact path")
	}

	if message2ProtectEnvelope.Data.MessageArtifactSHA256 == message1ProtectEnvelope.Data.MessageArtifactSHA256 {
		t.Fatal("message-0002 artifact hash should differ from message-0001 artifact hash")
	}

	message2OpenOutput, message2OpenErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0002",
		"--message", message2ProtectEnvelope.Data.MessageArtifactPathHint,
	)
	if message2OpenErr != nil {
		t.Fatalf("message-0002 open failed: %v\n%s", message2OpenErr, string(message2OpenOutput))
	}

	message2OpenEnvelope := parseSidecarEnvelope(t, message2OpenOutput)
	assertMessageOpenSuccess(t, message2OpenEnvelope, "message-0002", "hello bob 2", addMemberEnvelope.Data.GroupIDRef)

	assertNoSecretMaterialInStdout(t, message1ProtectOutput)
	assertNoSecretMaterialInStdout(t, message1OpenOutput)
	assertNoSecretMaterialInStdout(t, message2ProtectOutput)
	assertNoSecretMaterialInStdout(t, message2OpenOutput)

	assertFileExists(t, filepath.Join(openMLSSidecarDir, message1ProtectEnvelope.Data.MessageArtifactPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message1ProtectEnvelope.Data.MessageManifestPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message1ProtectEnvelope.Data.MessageProtectSummaryPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message1OpenEnvelope.Data.MessageOpenSummaryPathHint))

	assertFileExists(t, filepath.Join(openMLSSidecarDir, message2ProtectEnvelope.Data.MessageArtifactPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message2ProtectEnvelope.Data.MessageManifestPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message2ProtectEnvelope.Data.MessageProtectSummaryPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, message2OpenEnvelope.Data.MessageOpenSummaryPathHint))

	duplicateProtectOutput, duplicateProtectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "message-0002",
		"--plaintext", "hello bob 2 duplicate",
	)
	assertExitCode(t, duplicateProtectErr, 3)

	duplicateProtectEnvelope := parseSidecarEnvelope(t, duplicateProtectOutput)
	if duplicateProtectEnvelope.OK {
		t.Fatal("duplicate message-0002 protect envelope ok = true, want false")
	}

	if duplicateProtectEnvelope.Error == nil {
		t.Fatal("duplicate message-0002 protect should include error")
	}

	if duplicateProtectEnvelope.Error.Code != "message_artifact_exists" {
		t.Fatalf("duplicate message-0002 protect error code = %q, want message_artifact_exists", duplicateProtectEnvelope.Error.Code)
	}

	assertNoSecretMaterialInStdout(t, duplicateProtectOutput)
}

func TestOpenMLSSidecarMessageProtectOpenBidirectional(t *testing.T) {
	removeOpenMLSSidecarState(t)

	addMemberEnvelope := setupOpenMLSTwoMemberConversation(t)

	aliceToBobProtectEnvelope := protectOpenMLSSidecarMessage(t, "alice-message-0001", "hello bob from alice")

	aliceToBobOpenEnvelope, aliceToBobOpenOutput := openOpenMLSSidecarMessage(t, "alice-message-0001", aliceToBobProtectEnvelope.Data.MessageArtifactPathHint)
	assertMessageOpenSuccess(t, aliceToBobOpenEnvelope, "alice-message-0001", "hello bob from alice", addMemberEnvelope.Data.GroupIDRef)
	assertNoSecretMaterialInStdout(t, aliceToBobOpenOutput)

	bobProtectOutput, bobProtectErr := runOpenMLSSidecar(
		"message-protect",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "bob-message-0001",
		"--plaintext", "hello alice from bob",
	)
	if bobProtectErr != nil {
		t.Fatalf("bob message-protect failed: %v\n%s", bobProtectErr, string(bobProtectOutput))
	}

	bobProtectEnvelope := parseSidecarEnvelope(t, bobProtectOutput)
	assertMessageProtectSuccess(t, bobProtectEnvelope, "bob-message-0001", "phase2d-message-protect-dev", addMemberEnvelope.Data.GroupIDRef)

	if bobProtectEnvelope.Data.DeviceLabel != "carbonstack-bob-device" {
		t.Fatalf("bob protect device_label = %q, want carbonstack-bob-device", bobProtectEnvelope.Data.DeviceLabel)
	}

	if !strings.Contains(bobProtectEnvelope.Data.MessageArtifactPathHint, "carbonstack-bob-device") {
		t.Fatalf("bob protect artifact path = %q, want Bob device-scoped path", bobProtectEnvelope.Data.MessageArtifactPathHint)
	}

	assertNoSecretMaterialInStdout(t, bobProtectOutput)

	aliceOpenOutput, aliceOpenErr := runOpenMLSSidecar(
		"message-open",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--message-label", "bob-message-0001",
		"--message", bobProtectEnvelope.Data.MessageArtifactPathHint,
	)
	if aliceOpenErr != nil {
		t.Fatalf("alice message-open failed: %v\n%s", aliceOpenErr, string(aliceOpenOutput))
	}

	aliceOpenEnvelope := parseSidecarEnvelope(t, aliceOpenOutput)
	assertMessageOpenSuccess(t, aliceOpenEnvelope, "bob-message-0001", "hello alice from bob", addMemberEnvelope.Data.GroupIDRef)

	if aliceOpenEnvelope.Data.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("alice open device_label = %q, want carbonstack-alice-device", aliceOpenEnvelope.Data.DeviceLabel)
	}

	assertNoSecretMaterialInStdout(t, aliceOpenOutput)
}

func TestOpenMLSSidecarMessageOpenOutOfOrderTwoMessageDelivery(t *testing.T) {
	removeOpenMLSSidecarState(t)

	addMemberEnvelope := setupOpenMLSTwoMemberConversation(t)

	message1ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0001", "hello bob 1")
	message2ProtectEnvelope := protectOpenMLSSidecarMessage(t, "message-0002", "hello bob 2")

	message2OpenEnvelope, message2OpenOutput := openOpenMLSSidecarMessage(t, "message-0002", message2ProtectEnvelope.Data.MessageArtifactPathHint)
	assertMessageOpenSuccess(t, message2OpenEnvelope, "message-0002", "hello bob 2", addMemberEnvelope.Data.GroupIDRef)
	assertNoSecretMaterialInStdout(t, message2OpenOutput)

	message1OpenEnvelope, message1OpenOutput := openOpenMLSSidecarMessage(t, "message-0001", message1ProtectEnvelope.Data.MessageArtifactPathHint)
	assertMessageOpenSuccess(t, message1OpenEnvelope, "message-0001", "hello bob 1", addMemberEnvelope.Data.GroupIDRef)
	assertNoSecretMaterialInStdout(t, message1OpenOutput)
}
