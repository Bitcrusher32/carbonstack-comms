package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenMLSSidecarConversationCreate(t *testing.T) {
	removeOpenMLSSidecarState(t)

	missingOutput, missingErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	assertExitCode(t, missingErr, 3)

	missingEnvelope := parseSidecarEnvelope(t, missingOutput)

	if missingEnvelope.OK {
		t.Fatal("conversation-create without identity ok = true, want false")
	}

	assertSidecarError(t, missingEnvelope, "identity_missing", string(ProviderEventIdentityMissing), "warning", false)
	assertNoSecretMaterialInStdout(t, missingOutput)

	createOutput, createErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if createErr != nil {
		t.Fatalf("identity-create should exit 0 before conversation-create: %v\noutput:\n%s", createErr, string(createOutput))
	}

	conversationOutput, conversationErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if conversationErr != nil {
		t.Fatalf("conversation-create should exit 0 after identity-create: %v\noutput:\n%s", conversationErr, string(conversationOutput))
	}

	conversationEnvelope := parseSidecarEnvelope(t, conversationOutput)

	if !conversationEnvelope.OK {
		t.Fatal("conversation-create envelope ok = false, want true")
	}

	if conversationEnvelope.Command != "conversation-create" {
		t.Fatalf("command = %q, want conversation-create", conversationEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, conversationEnvelope)

	if conversationEnvelope.Phase != "phase2d-conversation-create-dev" {
		t.Fatalf("phase = %q, want phase2d-conversation-create-dev", conversationEnvelope.Phase)
	}

	if conversationEnvelope.PrivateMaterialIncluded {
		t.Fatal("conversation-create must not include private material")
	}

	if !conversationEnvelope.Data.IdentityExists {
		t.Fatal("conversation-create should report identity_exists=true")
	}

	if !conversationEnvelope.Data.IdentityLoadable {
		t.Fatal("conversation-create should report identity_loadable=true")
	}

	if !conversationEnvelope.Data.ConversationCreated {
		t.Fatal("conversation-create should report conversation_created=true")
	}

	if conversationEnvelope.Data.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("device label = %q, want carbonstack-alice-device", conversationEnvelope.Data.DeviceLabel)
	}

	if conversationEnvelope.Data.ConversationLabel != "carbonstack-test-conversation" {
		t.Fatalf("conversation label = %q, want carbonstack-test-conversation", conversationEnvelope.Data.ConversationLabel)
	}

	if conversationEnvelope.Data.StateScope != "dev-local-sidecar-state" {
		t.Fatalf("state scope = %q, want dev-local-sidecar-state", conversationEnvelope.Data.StateScope)
	}

	if conversationEnvelope.Data.ConversationStatePathHint == "" {
		t.Fatal("conversation-create should return conversation state path hint")
	}

	if conversationEnvelope.Data.ConversationSummaryPathHint == "" {
		t.Fatal("conversation-create should return conversation summary path hint")
	}

	if conversationEnvelope.Data.Ciphersuite != "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519" {
		t.Fatalf("ciphersuite = %q, want current Phase 2D ciphersuite", conversationEnvelope.Data.Ciphersuite)
	}

	if conversationEnvelope.Data.GroupIDRef == "" || !strings.HasPrefix(conversationEnvelope.Data.GroupIDRef, "sha256:") {
		t.Fatalf("group id ref = %q, want sha256 ref", conversationEnvelope.Data.GroupIDRef)
	}

	if conversationEnvelope.Data.GroupIDLen <= 0 {
		t.Fatalf("group id len = %d, want > 0", conversationEnvelope.Data.GroupIDLen)
	}

	if conversationEnvelope.Data.MemberCount != 1 {
		t.Fatalf("member count = %d, want 1", conversationEnvelope.Data.MemberCount)
	}

	if conversationEnvelope.Data.Epoch == "" {
		t.Fatal("conversation-create should return epoch")
	}
	if !conversationEnvelope.Data.ProviderStorageWritten {
		t.Fatal("conversation-create should report provider_storage_written=true after dev provider storage persistence repair")
	}

	if conversationEnvelope.Data.ProviderStoragePathHint == "" {
		t.Fatal("conversation-create should return provider storage path hint")
	}

	if !conversationEnvelope.Data.GroupReloadable {
		t.Fatal("conversation-create should report group_reloadable=true after MlsGroup::load proof")
	}

	if len(conversationEnvelope.Events) != 1 {
		t.Fatalf("conversation-create event count = %d, want 1", len(conversationEnvelope.Events))
	}

	if conversationEnvelope.Events[0].Event != string(ProviderEventConversationCreated) {
		t.Fatalf("conversation-create event = %q, want %q", conversationEnvelope.Events[0].Event, ProviderEventConversationCreated)
	}

	if conversationEnvelope.Events[0].TrustRelevant {
		t.Fatal("conversation-create event should not be trust relevant in this dev-sidecar rung")
	}

	assertNoSecretMaterialInStdout(t, conversationOutput)

	conversationSummaryPath := filepath.Join(openMLSSidecarDir, conversationEnvelope.Data.ConversationSummaryPathHint)
	providerStoragePath := filepath.Join(openMLSSidecarDir, conversationEnvelope.Data.ProviderStoragePathHint)
	signerPath := filepath.Join(openMLSSidecarDir, ".carbonstack-openmls-sidecar-state", "dev", "devices", "carbonstack-alice-device", "signer.json")

	assertFileExists(t, conversationSummaryPath)
	assertFileExists(t, providerStoragePath)
	assertFileExists(t, signerPath)

	var summary struct {
		SummaryVersion          string `json:"summary_version"`
		ConversationLabel       string `json:"conversation_label"`
		CreatorDeviceLabel      string `json:"creator_device_label"`
		StateScope              string `json:"state_scope"`
		Ciphersuite             string `json:"ciphersuite"`
		GroupIDRef              string `json:"group_id_ref"`
		GroupIDLen              int    `json:"group_id_len"`
		MemberCount             int    `json:"member_count"`
		Epoch                   string `json:"epoch"`
		ConversationCreated     bool   `json:"conversation_created"`
		ProviderStorageWritten  bool   `json:"provider_storage_written"`
		GroupReloadable         bool   `json:"group_reloadable"`
		ProviderStorageFile     string `json:"provider_storage_file"`
		PrivateMaterialIncluded bool   `json:"private_material_included"`
	}

	readJSONFile(t, conversationSummaryPath, &summary)

	if summary.SummaryVersion != "conversation-summary/v0" {
		t.Fatalf("summary version = %q, want conversation-summary/v0", summary.SummaryVersion)
	}

	if summary.ConversationLabel != conversationEnvelope.Data.ConversationLabel {
		t.Fatalf("summary conversation label = %q, want envelope label %q", summary.ConversationLabel, conversationEnvelope.Data.ConversationLabel)
	}

	if summary.CreatorDeviceLabel != conversationEnvelope.Data.DeviceLabel {
		t.Fatalf("summary creator device label = %q, want envelope label %q", summary.CreatorDeviceLabel, conversationEnvelope.Data.DeviceLabel)
	}

	if summary.GroupIDRef != conversationEnvelope.Data.GroupIDRef {
		t.Fatalf("summary group id ref = %q, want envelope ref %q", summary.GroupIDRef, conversationEnvelope.Data.GroupIDRef)
	}

	if summary.GroupIDLen != conversationEnvelope.Data.GroupIDLen {
		t.Fatalf("summary group id len = %d, want envelope len %d", summary.GroupIDLen, conversationEnvelope.Data.GroupIDLen)
	}

	if summary.MemberCount != conversationEnvelope.Data.MemberCount {
		t.Fatalf("summary member count = %d, want envelope count %d", summary.MemberCount, conversationEnvelope.Data.MemberCount)
	}

	if summary.Epoch != conversationEnvelope.Data.Epoch {
		t.Fatalf("summary epoch = %q, want envelope epoch %q", summary.Epoch, conversationEnvelope.Data.Epoch)
	}

	if !summary.ConversationCreated {
		t.Fatal("summary should report conversation_created=true")
	}
	if !summary.ProviderStorageWritten {
		t.Fatal("summary should report provider_storage_written=true after dev provider storage persistence repair")
	}

	if !summary.GroupReloadable {
		t.Fatal("summary should report group_reloadable=true after MlsGroup::load proof")
	}

	if summary.ProviderStorageFile != "provider-storage.json" {
		t.Fatalf("summary provider storage file = %q, want provider-storage.json", summary.ProviderStorageFile)
	}

	if summary.PrivateMaterialIncluded {
		t.Fatal("summary must not include private material")
	}

	duplicateOutput, duplicateErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	assertExitCode(t, duplicateErr, 3)

	duplicateEnvelope := parseSidecarEnvelope(t, duplicateOutput)

	if duplicateEnvelope.OK {
		t.Fatal("duplicate conversation-create envelope ok = true, want false")
	}

	assertSidecarError(t, duplicateEnvelope, "conversation_already_exists", string(ProviderEventConversationExists), "warning", false)
	assertNoSecretMaterialInStdout(t, duplicateOutput)

	invalidOutput, invalidErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "../bad")
	assertExitCode(t, invalidErr, 2)

	invalidEnvelope := parseSidecarEnvelope(t, invalidOutput)

	if invalidEnvelope.OK {
		t.Fatal("invalid conversation label envelope ok = true, want false")
	}

	assertSidecarError(t, invalidEnvelope, "invalid_conversation_label", string(ProviderEventCommandInvalid), "warning", false)
	assertNoSecretMaterialInStdout(t, invalidOutput)
}

func TestOpenMLSSidecarConversationLoadCheck(t *testing.T) {
	removeOpenMLSSidecarState(t)

	missingOutput, missingErr := runOpenMLSSidecar("conversation-load-check", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	assertExitCode(t, missingErr, 3)

	missingEnvelope := parseSidecarEnvelope(t, missingOutput)
	if missingEnvelope.OK {
		t.Fatal("missing conversation-load-check envelope ok = true, want false")
	}
	assertNoSecretMaterialInStdout(t, missingOutput)

	identityOutput, identityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if identityErr != nil {
		t.Fatalf("identity-create failed: %v\n%s", identityErr, string(identityOutput))
	}

	conversationOutput, conversationErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if conversationErr != nil {
		t.Fatalf("conversation-create failed: %v\n%s", conversationErr, string(conversationOutput))
	}

	loadOutput, loadErr := runOpenMLSSidecar("conversation-load-check", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if loadErr != nil {
		t.Fatalf("conversation-load-check failed: %v\n%s", loadErr, string(loadOutput))
	}

	loadEnvelope := parseSidecarEnvelope(t, loadOutput)

	if !loadEnvelope.OK {
		t.Fatal("conversation-load-check envelope ok = false, want true")
	}

	if loadEnvelope.Command != "conversation-load-check" {
		t.Fatalf("command = %q, want conversation-load-check", loadEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, loadEnvelope)

	if loadEnvelope.Phase != "phase2d-conversation-load-check-dev" {
		t.Fatalf("phase = %q, want phase2d-conversation-load-check-dev", loadEnvelope.Phase)
	}

	if loadEnvelope.PrivateMaterialIncluded {
		t.Fatal("conversation-load-check must not include private material")
	}

	if loadEnvelope.Data.DeviceLabel != "carbonstack-alice-device" {
		t.Fatalf("device label = %q, want carbonstack-alice-device", loadEnvelope.Data.DeviceLabel)
	}

	if loadEnvelope.Data.ConversationLabel != "carbonstack-test-conversation" {
		t.Fatalf("conversation label = %q, want carbonstack-test-conversation", loadEnvelope.Data.ConversationLabel)
	}

	if loadEnvelope.Data.ProviderStoragePathHint == "" {
		t.Fatal("conversation-load-check should return provider storage path hint")
	}

	if !loadEnvelope.Data.ProviderStorageLoaded {
		t.Fatal("conversation-load-check should report provider_storage_loaded=true")
	}

	if !loadEnvelope.Data.GroupReloadable {
		t.Fatal("conversation-load-check should report group_reloadable=true")
	}

	if loadEnvelope.Data.MemberCount != 1 {
		t.Fatalf("member count = %d, want 1", loadEnvelope.Data.MemberCount)
	}

	if loadEnvelope.Data.Epoch == "" {
		t.Fatal("conversation-load-check should return epoch")
	}

	if len(loadEnvelope.Events) != 1 {
		t.Fatalf("conversation-load-check event count = %d, want 1", len(loadEnvelope.Events))
	}

	if loadEnvelope.Events[0].Event != string(ProviderEventConversationLoaded) {
		t.Fatalf("conversation-load-check event = %q, want %q", loadEnvelope.Events[0].Event, ProviderEventConversationLoaded)
	}

	if loadEnvelope.Events[0].TrustRelevant {
		t.Fatal("conversation-load-check event should not be trust relevant")
	}

	assertNoSecretMaterialInStdout(t, loadOutput)
}

func TestOpenMLSSidecarConversationAddMemberWelcomeExport(t *testing.T) {
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

	if bobBundleEnvelope.Data.KeyPackageArtifactPathHint == "" {
		t.Fatal("bob public-bundle-export should return key package artifact path hint")
	}

	aliceConversationOutput, aliceConversationErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if aliceConversationErr != nil {
		t.Fatalf("alice conversation-create failed: %v\n%s", aliceConversationErr, string(aliceConversationOutput))
	}

	beforeLoadOutput, beforeLoadErr := runOpenMLSSidecar("conversation-load-check", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if beforeLoadErr != nil {
		t.Fatalf("before add-member conversation-load-check failed: %v\n%s", beforeLoadErr, string(beforeLoadOutput))
	}

	beforeLoadEnvelope := parseSidecarEnvelope(t, beforeLoadOutput)
	if beforeLoadEnvelope.Data.MemberCount != 1 {
		t.Fatalf("before add-member member count = %d, want 1", beforeLoadEnvelope.Data.MemberCount)
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
		t.Fatal("conversation-add-member envelope ok = false, want true")
	}

	if addMemberEnvelope.Command != "conversation-add-member" {
		t.Fatalf("command = %q, want conversation-add-member", addMemberEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, addMemberEnvelope)

	if addMemberEnvelope.Phase != "phase2d-conversation-add-member-dev" {
		t.Fatalf("phase = %q, want phase2d-conversation-add-member-dev", addMemberEnvelope.Phase)
	}

	if addMemberEnvelope.PrivateMaterialIncluded {
		t.Fatal("conversation-add-member must not include private material")
	}

	if !addMemberEnvelope.Data.MemberAdded {
		t.Fatal("conversation-add-member should report member_added=true")
	}

	if !addMemberEnvelope.Data.WelcomeArtifactWritten {
		t.Fatal("conversation-add-member should report welcome_artifact_written=true")
	}

	if !addMemberEnvelope.Data.ProviderStorageLoaded {
		t.Fatal("conversation-add-member should report provider_storage_loaded=true")
	}

	if !addMemberEnvelope.Data.ProviderStorageWritten {
		t.Fatal("conversation-add-member should report provider_storage_written=true")
	}

	if !addMemberEnvelope.Data.GroupReloadable {
		t.Fatal("conversation-add-member should report group_reloadable=true")
	}

	if !addMemberEnvelope.Data.PendingCommitMerged {
		t.Fatal("conversation-add-member should report pending_commit_merged=true")
	}

	if addMemberEnvelope.Data.MemberCountBefore != 1 {
		t.Fatalf("member_count_before = %d, want 1", addMemberEnvelope.Data.MemberCountBefore)
	}

	if addMemberEnvelope.Data.MemberCountAfter != 2 {
		t.Fatalf("member_count_after = %d, want 2", addMemberEnvelope.Data.MemberCountAfter)
	}

	if addMemberEnvelope.Data.EpochBefore == "" {
		t.Fatal("conversation-add-member should report epoch_before")
	}

	if addMemberEnvelope.Data.EpochAfter == "" {
		t.Fatal("conversation-add-member should report epoch_after")
	}

	if addMemberEnvelope.Data.WelcomeArtifactPathHint == "" {
		t.Fatal("conversation-add-member should return welcome artifact path hint")
	}

	if addMemberEnvelope.Data.WelcomeManifestPathHint == "" {
		t.Fatal("conversation-add-member should return welcome manifest path hint")
	}

	if addMemberEnvelope.Data.AddMemberSummaryPathHint == "" {
		t.Fatal("conversation-add-member should return add-member summary path hint")
	}

	if addMemberEnvelope.Data.WelcomeArtifactSHA256 == "" {
		t.Fatal("conversation-add-member should return welcome artifact sha256")
	}

	if addMemberEnvelope.Data.WelcomeArtifactSizeBytes <= 0 {
		t.Fatalf("welcome artifact size = %d, want > 0", addMemberEnvelope.Data.WelcomeArtifactSizeBytes)
	}

	if len(addMemberEnvelope.Events) != 2 {
		t.Fatalf("conversation-add-member event count = %d, want 2", len(addMemberEnvelope.Events))
	}

	assertNoSecretMaterialInStdout(t, addMemberOutput)

	assertFileExists(t, filepath.Join(openMLSSidecarDir, addMemberEnvelope.Data.WelcomeArtifactPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, addMemberEnvelope.Data.WelcomeManifestPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, addMemberEnvelope.Data.AddMemberSummaryPathHint))

	afterLoadOutput, afterLoadErr := runOpenMLSSidecar("conversation-load-check", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if afterLoadErr != nil {
		t.Fatalf("after add-member conversation-load-check failed: %v\n%s", afterLoadErr, string(afterLoadOutput))
	}

	afterLoadEnvelope := parseSidecarEnvelope(t, afterLoadOutput)

	if afterLoadEnvelope.Data.MemberCount != 2 {
		t.Fatalf("after add-member member count = %d, want 2", afterLoadEnvelope.Data.MemberCount)
	}

	if !afterLoadEnvelope.Data.GroupReloadable {
		t.Fatal("after add-member conversation-load-check should report group_reloadable=true")
	}

	duplicateOutput, duplicateErr := runOpenMLSSidecar(
		"conversation-add-member",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--member-keypackage", bobBundleEnvelope.Data.KeyPackageArtifactPathHint,
	)
	assertExitCode(t, duplicateErr, 3)

	duplicateEnvelope := parseSidecarEnvelope(t, duplicateOutput)
	if duplicateEnvelope.OK {
		t.Fatal("duplicate conversation-add-member envelope ok = true, want false")
	}

	if duplicateEnvelope.Error == nil {
		t.Fatal("duplicate conversation-add-member should include error")
	}

	if duplicateEnvelope.Error.Code != "add_member_artifact_exists" {
		t.Fatalf("duplicate error code = %q, want add_member_artifact_exists", duplicateEnvelope.Error.Code)
	}

	assertNoSecretMaterialInStdout(t, duplicateOutput)
}

func TestOpenMLSSidecarConversationJoinWelcomeConsume(t *testing.T) {
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

	addMemberOutput, addMemberErr := runOpenMLSSidecar("conversation-create", "--device-label", "carbonstack-alice-device", "--conversation-label", "carbonstack-test-conversation")
	if addMemberErr != nil {
		t.Fatalf("alice conversation-create failed: %v\n%s", addMemberErr, string(addMemberOutput))
	}

	addMemberOutput, addMemberErr = runOpenMLSSidecar(
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

	if joinEnvelope.Command != "conversation-join" {
		t.Fatalf("command = %q, want conversation-join", joinEnvelope.Command)
	}

	assertProviderEnvelopeBase(t, joinEnvelope)

	if joinEnvelope.Phase != "phase2d-conversation-join-dev" {
		t.Fatalf("phase = %q, want phase2d-conversation-join-dev", joinEnvelope.Phase)
	}

	if joinEnvelope.PrivateMaterialIncluded {
		t.Fatal("conversation-join must not include private material")
	}

	if !joinEnvelope.Data.Joined {
		t.Fatal("conversation-join should report joined=true")
	}

	if !joinEnvelope.Data.ProviderStorageWritten {
		t.Fatal("conversation-join should report provider_storage_written=true")
	}

	if !joinEnvelope.Data.ProviderStorageLoaded {
		t.Fatal("conversation-join should report provider_storage_loaded=true")
	}

	if !joinEnvelope.Data.GroupReloadable {
		t.Fatal("conversation-join should report group_reloadable=true")
	}

	if joinEnvelope.Data.MemberCount != 2 {
		t.Fatalf("conversation-join member_count = %d, want 2", joinEnvelope.Data.MemberCount)
	}

	if joinEnvelope.Data.Epoch == "" {
		t.Fatal("conversation-join should report epoch")
	}

	if joinEnvelope.Data.GroupIDRef == "" {
		t.Fatal("conversation-join should report group_id_ref")
	}

	if joinEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("join group_id_ref = %q, add-member group_id_ref = %q", joinEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}

	if joinEnvelope.Data.ConversationStatePathHint == "" {
		t.Fatal("conversation-join should return device-scoped conversation state path hint")
	}

	if joinEnvelope.Data.ConversationSummaryPathHint == "" {
		t.Fatal("conversation-join should return conversation summary path hint")
	}

	if joinEnvelope.Data.ProviderStoragePathHint == "" {
		t.Fatal("conversation-join should return provider storage path hint")
	}

	if joinEnvelope.Data.JoinSummaryPathHint == "" {
		t.Fatal("conversation-join should return join summary path hint")
	}

	if len(joinEnvelope.Events) != 2 {
		t.Fatalf("conversation-join event count = %d, want 2", len(joinEnvelope.Events))
	}

	assertNoSecretMaterialInStdout(t, joinOutput)

	joinedConversationStatePath := filepath.Join(openMLSSidecarDir, joinEnvelope.Data.ConversationStatePathHint)
	joinedConversationStateInfo, joinedConversationStateErr := os.Stat(filepath.Clean(joinedConversationStatePath))
	if joinedConversationStateErr != nil {
		t.Fatalf("expected joined conversation state directory %s: %v", joinedConversationStatePath, joinedConversationStateErr)
	}
	if !joinedConversationStateInfo.IsDir() {
		t.Fatalf("expected joined conversation state path %s to be a directory", joinedConversationStatePath)
	}
	assertFileExists(t, filepath.Join(openMLSSidecarDir, joinEnvelope.Data.ConversationSummaryPathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, joinEnvelope.Data.ProviderStoragePathHint))
	assertFileExists(t, filepath.Join(openMLSSidecarDir, joinEnvelope.Data.JoinSummaryPathHint))

	duplicateOutput, duplicateErr := runOpenMLSSidecar(
		"conversation-join",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--welcome", addMemberEnvelope.Data.WelcomeArtifactPathHint,
	)
	assertExitCode(t, duplicateErr, 3)

	duplicateEnvelope := parseSidecarEnvelope(t, duplicateOutput)
	if duplicateEnvelope.OK {
		t.Fatal("duplicate conversation-join envelope ok = true, want false")
	}

	if duplicateEnvelope.Error == nil {
		t.Fatal("duplicate conversation-join should include error")
	}

	if duplicateEnvelope.Error.Code != "conversation_already_exists" {
		t.Fatalf("duplicate error code = %q, want conversation_already_exists", duplicateEnvelope.Error.Code)
	}

	assertNoSecretMaterialInStdout(t, duplicateOutput)
}
