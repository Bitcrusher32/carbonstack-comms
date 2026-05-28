package protocol

import (
	"path/filepath"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
)

func TestOpenMLSSidecarApplicationMessageRelayThroughCypherEnvelope(t *testing.T) {
	removeOpenMLSSidecarState(t)

	tc := newProtocolTestCypherServer(t)
	cypherClient := client.New(tc.URL())

	setupEnvelope := setupOpenMLSTwoMemberConversation(t)

	messageLabel := "relay-message-0001"
	plaintext := "hello bob through cypher relay"

	protectEnvelope := protectOpenMLSSidecarMessage(t, messageLabel, plaintext)

	if protectEnvelope.Data.MessageArtifactPathHint == "" {
		t.Fatal("message artifact path hint is empty")
	}

	artifactPath := filepath.Join(openMLSSidecarDir, protectEnvelope.Data.MessageArtifactPathHint)

	submitResp, err := relay.SubmitOpenMLSArtifactEnvelope(
		cypherClient,
		"alice-cypher-device-id",
		"bob-cypher-device-id",
		relay.ArtifactKindApplicationMessage,
		artifactPath,
		"2026-05-27T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("SubmitOpenMLSArtifactEnvelope failed: %v", err)
	}

	if submitResp.DeliveryState != "queued" {
		t.Fatalf("delivery state = %q, want queued", submitResp.DeliveryState)
	}

	inbox, err := cypherClient.Inbox("bob-cypher-device-id")
	if err != nil {
		t.Fatalf("Cypher inbox failed: %v", err)
	}

	if len(inbox.Envelopes) != 1 {
		t.Fatalf("expected 1 relay envelope, got %d", len(inbox.Envelopes))
	}

	envelope := inbox.Envelopes[0]
	if envelope.ContentType != relay.ContentTypeOpenMLSApplicationMessage {
		t.Fatalf("content type = %q, want %q", envelope.ContentType, relay.ContentTypeOpenMLSApplicationMessage)
	}

	if envelope.ProtocolVersion != relay.ProtocolVersionOpenMLSSidecar {
		t.Fatalf("protocol version = %q, want %q", envelope.ProtocolVersion, relay.ProtocolVersionOpenMLSSidecar)
	}

	downloadedArtifactPath := filepath.Join(t.TempDir(), "downloaded-application-message.bin")
	if err := relay.WriteOpenMLSArtifactFromEnvelope(downloadedArtifactPath, envelope); err != nil {
		t.Fatalf("WriteOpenMLSArtifactFromEnvelope failed: %v", err)
	}
	openEnvelope, openOutput := openOpenMLSSidecarMessage(t, messageLabel, downloadedArtifactPath)
	assertMessageOpenSuccess(t, openEnvelope, messageLabel, plaintext, setupEnvelope.Data.GroupIDRef)
	assertNoSecretMaterialInStdout(t, openOutput)
}

func TestOpenMLSSidecarKeyPackageWelcomeRelayThroughCypherEnvelope(t *testing.T) {
	removeOpenMLSSidecarState(t)

	tc := newProtocolTestCypherServer(t)
	cypherClient := client.New(tc.URL())

	aliceIdentityOutput, aliceIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if aliceIdentityErr != nil {
		t.Fatalf("alice identity-create failed: %v\n%s", aliceIdentityErr, string(aliceIdentityOutput))
	}
	assertNoSecretMaterialInStdout(t, aliceIdentityOutput)

	bobIdentityOutput, bobIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-bob-device")
	if bobIdentityErr != nil {
		t.Fatalf("bob identity-create failed: %v\n%s", bobIdentityErr, string(bobIdentityOutput))
	}
	assertNoSecretMaterialInStdout(t, bobIdentityOutput)

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
	assertNoSecretMaterialInStdout(t, bobBundleOutput)

	keyPackageArtifactPath := filepath.Join(openMLSSidecarDir, bobBundleEnvelope.Data.KeyPackageArtifactPathHint)

	keyPackageSubmitResp, err := relay.SubmitOpenMLSArtifactEnvelope(
		cypherClient,
		"bob-cypher-device-id",
		"alice-cypher-device-id",
		relay.ArtifactKindKeyPackage,
		keyPackageArtifactPath,
		"2026-05-27T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("SubmitOpenMLSArtifactEnvelope keypackage failed: %v", err)
	}
	if keyPackageSubmitResp.DeliveryState != "queued" {
		t.Fatalf("keypackage delivery state = %q, want queued", keyPackageSubmitResp.DeliveryState)
	}

	aliceInbox, err := cypherClient.Inbox("alice-cypher-device-id")
	if err != nil {
		t.Fatalf("alice Cypher inbox failed: %v", err)
	}
	if len(aliceInbox.Envelopes) != 1 {
		t.Fatalf("expected 1 keypackage relay envelope for Alice, got %d", len(aliceInbox.Envelopes))
	}

	keyPackageEnvelope := aliceInbox.Envelopes[0]
	if keyPackageEnvelope.ContentType != relay.ContentTypeOpenMLSKeyPackage {
		t.Fatalf("keypackage content type = %q, want %q", keyPackageEnvelope.ContentType, relay.ContentTypeOpenMLSKeyPackage)
	}
	if keyPackageEnvelope.ProtocolVersion != relay.ProtocolVersionOpenMLSSidecar {
		t.Fatalf("keypackage protocol version = %q, want %q", keyPackageEnvelope.ProtocolVersion, relay.ProtocolVersionOpenMLSSidecar)
	}

	downloadedKeyPackagePath := filepath.Join(t.TempDir(), "downloaded-public-bundle.keypackage.bin")
	if err := relay.WriteOpenMLSArtifactFromEnvelope(downloadedKeyPackagePath, keyPackageEnvelope); err != nil {
		t.Fatalf("WriteOpenMLSArtifactFromEnvelope keypackage failed: %v", err)
	}

	aliceConversationOutput, aliceConversationErr := runOpenMLSSidecar(
		"conversation-create",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
	)
	if aliceConversationErr != nil {
		t.Fatalf("alice conversation-create failed: %v\n%s", aliceConversationErr, string(aliceConversationOutput))
	}

	aliceConversationEnvelope := parseSidecarEnvelope(t, aliceConversationOutput)
	if !aliceConversationEnvelope.OK {
		t.Fatal("alice conversation-create ok = false, want true")
	}
	assertNoSecretMaterialInStdout(t, aliceConversationOutput)

	addMemberOutput, addMemberErr := runOpenMLSSidecar(
		"conversation-add-member",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--member-keypackage", downloadedKeyPackagePath,
	)
	if addMemberErr != nil {
		t.Fatalf("conversation-add-member with relayed keypackage failed: %v\n%s", addMemberErr, string(addMemberOutput))
	}

	addMemberEnvelope := parseSidecarEnvelope(t, addMemberOutput)
	if !addMemberEnvelope.OK {
		t.Fatal("conversation-add-member ok = false, want true")
	}
	if !addMemberEnvelope.Data.MemberAdded {
		t.Fatal("conversation-add-member should report member_added=true")
	}
	if !addMemberEnvelope.Data.WelcomeArtifactWritten {
		t.Fatal("conversation-add-member should report welcome_artifact_written=true")
	}
	if addMemberEnvelope.Data.WelcomeArtifactPathHint == "" {
		t.Fatal("conversation-add-member should return welcome artifact path hint")
	}
	if addMemberEnvelope.Data.GroupIDRef != aliceConversationEnvelope.Data.GroupIDRef {
		t.Fatalf("add-member group_id_ref = %q, conversation group_id_ref = %q", addMemberEnvelope.Data.GroupIDRef, aliceConversationEnvelope.Data.GroupIDRef)
	}
	assertNoSecretMaterialInStdout(t, addMemberOutput)

	welcomeArtifactPath := filepath.Join(openMLSSidecarDir, addMemberEnvelope.Data.WelcomeArtifactPathHint)

	welcomeSubmitResp, err := relay.SubmitOpenMLSArtifactEnvelope(
		cypherClient,
		"alice-cypher-device-id",
		"bob-cypher-device-id",
		relay.ArtifactKindWelcome,
		welcomeArtifactPath,
		"2026-05-27T00:01:00Z",
	)
	if err != nil {
		t.Fatalf("SubmitOpenMLSArtifactEnvelope welcome failed: %v", err)
	}
	if welcomeSubmitResp.DeliveryState != "queued" {
		t.Fatalf("welcome delivery state = %q, want queued", welcomeSubmitResp.DeliveryState)
	}

	bobInbox, err := cypherClient.Inbox("bob-cypher-device-id")
	if err != nil {
		t.Fatalf("bob Cypher inbox failed: %v", err)
	}
	if len(bobInbox.Envelopes) != 1 {
		t.Fatalf("expected 1 welcome relay envelope for Bob, got %d", len(bobInbox.Envelopes))
	}

	welcomeEnvelope := bobInbox.Envelopes[0]
	if welcomeEnvelope.ContentType != relay.ContentTypeOpenMLSWelcome {
		t.Fatalf("welcome content type = %q, want %q", welcomeEnvelope.ContentType, relay.ContentTypeOpenMLSWelcome)
	}
	if welcomeEnvelope.ProtocolVersion != relay.ProtocolVersionOpenMLSSidecar {
		t.Fatalf("welcome protocol version = %q, want %q", welcomeEnvelope.ProtocolVersion, relay.ProtocolVersionOpenMLSSidecar)
	}

	downloadedWelcomePath := filepath.Join(t.TempDir(), "downloaded-welcome.bin")
	if err := relay.WriteOpenMLSArtifactFromEnvelope(downloadedWelcomePath, welcomeEnvelope); err != nil {
		t.Fatalf("WriteOpenMLSArtifactFromEnvelope welcome failed: %v", err)
	}

	joinOutput, joinErr := runOpenMLSSidecar(
		"conversation-join",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--welcome", downloadedWelcomePath,
	)
	if joinErr != nil {
		t.Fatalf("conversation-join with relayed welcome failed: %v\n%s", joinErr, string(joinOutput))
	}

	joinEnvelope := parseSidecarEnvelope(t, joinOutput)
	if !joinEnvelope.OK {
		t.Fatal("conversation-join ok = false, want true")
	}
	if !joinEnvelope.Data.GroupReloadable {
		t.Fatal("conversation-join should report group_reloadable=true")
	}
	if joinEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("join group_id_ref = %q, add-member group_id_ref = %q", joinEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}
	if joinEnvelope.Data.MemberCount != 2 {
		t.Fatalf("join member_count = %d, want 2", joinEnvelope.Data.MemberCount)
	}
	assertNoSecretMaterialInStdout(t, joinOutput)
}

func TestOpenMLSSidecarFullLifecycleRelayThroughCypherEnvelope(t *testing.T) {
	removeOpenMLSSidecarState(t)

	tc := newProtocolTestCypherServer(t)
	cypherClient := client.New(tc.URL())

	aliceIdentityOutput, aliceIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-alice-device")
	if aliceIdentityErr != nil {
		t.Fatalf("alice identity-create failed: %v\n%s", aliceIdentityErr, string(aliceIdentityOutput))
	}
	assertNoSecretMaterialInStdout(t, aliceIdentityOutput)

	bobIdentityOutput, bobIdentityErr := runOpenMLSSidecar("identity-create", "--device-label", "carbonstack-bob-device")
	if bobIdentityErr != nil {
		t.Fatalf("bob identity-create failed: %v\n%s", bobIdentityErr, string(bobIdentityOutput))
	}
	assertNoSecretMaterialInStdout(t, bobIdentityOutput)

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
	assertNoSecretMaterialInStdout(t, bobBundleOutput)

	keyPackageArtifactPath := filepath.Join(openMLSSidecarDir, bobBundleEnvelope.Data.KeyPackageArtifactPathHint)

	if _, err := relay.SubmitOpenMLSArtifactEnvelope(
		cypherClient,
		"bob-cypher-device-id",
		"alice-cypher-device-id",
		relay.ArtifactKindKeyPackage,
		keyPackageArtifactPath,
		"2026-05-27T00:00:00Z",
	); err != nil {
		t.Fatalf("SubmitOpenMLSArtifactEnvelope keypackage failed: %v", err)
	}

	aliceInbox, err := cypherClient.Inbox("alice-cypher-device-id")
	if err != nil {
		t.Fatalf("alice Cypher inbox failed: %v", err)
	}
	if len(aliceInbox.Envelopes) != 1 {
		t.Fatalf("expected 1 keypackage relay envelope for Alice, got %d", len(aliceInbox.Envelopes))
	}

	keyPackageEnvelope := aliceInbox.Envelopes[0]
	if keyPackageEnvelope.ContentType != relay.ContentTypeOpenMLSKeyPackage {
		t.Fatalf("keypackage content type = %q, want %q", keyPackageEnvelope.ContentType, relay.ContentTypeOpenMLSKeyPackage)
	}

	downloadedKeyPackagePath := filepath.Join(t.TempDir(), "downloaded-public-bundle.keypackage.bin")
	if err := relay.WriteOpenMLSArtifactFromEnvelope(downloadedKeyPackagePath, keyPackageEnvelope); err != nil {
		t.Fatalf("WriteOpenMLSArtifactFromEnvelope keypackage failed: %v", err)
	}

	aliceConversationOutput, aliceConversationErr := runOpenMLSSidecar(
		"conversation-create",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
	)
	if aliceConversationErr != nil {
		t.Fatalf("alice conversation-create failed: %v\n%s", aliceConversationErr, string(aliceConversationOutput))
	}

	aliceConversationEnvelope := parseSidecarEnvelope(t, aliceConversationOutput)
	if !aliceConversationEnvelope.OK {
		t.Fatal("alice conversation-create ok = false, want true")
	}
	assertNoSecretMaterialInStdout(t, aliceConversationOutput)

	addMemberOutput, addMemberErr := runOpenMLSSidecar(
		"conversation-add-member",
		"--device-label", "carbonstack-alice-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--member-keypackage", downloadedKeyPackagePath,
	)
	if addMemberErr != nil {
		t.Fatalf("conversation-add-member with relayed keypackage failed: %v\n%s", addMemberErr, string(addMemberOutput))
	}

	addMemberEnvelope := parseSidecarEnvelope(t, addMemberOutput)
	if !addMemberEnvelope.OK {
		t.Fatal("conversation-add-member ok = false, want true")
	}
	if !addMemberEnvelope.Data.MemberAdded {
		t.Fatal("conversation-add-member should report member_added=true")
	}
	if addMemberEnvelope.Data.WelcomeArtifactPathHint == "" {
		t.Fatal("conversation-add-member should return welcome artifact path hint")
	}
	if addMemberEnvelope.Data.GroupIDRef != aliceConversationEnvelope.Data.GroupIDRef {
		t.Fatalf("add-member group_id_ref = %q, conversation group_id_ref = %q", addMemberEnvelope.Data.GroupIDRef, aliceConversationEnvelope.Data.GroupIDRef)
	}
	assertNoSecretMaterialInStdout(t, addMemberOutput)

	welcomeArtifactPath := filepath.Join(openMLSSidecarDir, addMemberEnvelope.Data.WelcomeArtifactPathHint)

	if _, err := relay.SubmitOpenMLSArtifactEnvelope(
		cypherClient,
		"alice-cypher-device-id",
		"bob-cypher-device-id",
		relay.ArtifactKindWelcome,
		welcomeArtifactPath,
		"2026-05-27T00:01:00Z",
	); err != nil {
		t.Fatalf("SubmitOpenMLSArtifactEnvelope welcome failed: %v", err)
	}

	bobWelcomeInbox, err := cypherClient.Inbox("bob-cypher-device-id")
	if err != nil {
		t.Fatalf("bob Cypher inbox for welcome failed: %v", err)
	}
	if len(bobWelcomeInbox.Envelopes) != 1 {
		t.Fatalf("expected 1 welcome relay envelope for Bob, got %d", len(bobWelcomeInbox.Envelopes))
	}

	welcomeEnvelope := bobWelcomeInbox.Envelopes[0]
	if welcomeEnvelope.ContentType != relay.ContentTypeOpenMLSWelcome {
		t.Fatalf("welcome content type = %q, want %q", welcomeEnvelope.ContentType, relay.ContentTypeOpenMLSWelcome)
	}

	downloadedWelcomePath := filepath.Join(t.TempDir(), "downloaded-welcome.bin")
	if err := relay.WriteOpenMLSArtifactFromEnvelope(downloadedWelcomePath, welcomeEnvelope); err != nil {
		t.Fatalf("WriteOpenMLSArtifactFromEnvelope welcome failed: %v", err)
	}

	joinOutput, joinErr := runOpenMLSSidecar(
		"conversation-join",
		"--device-label", "carbonstack-bob-device",
		"--conversation-label", "carbonstack-test-conversation",
		"--welcome", downloadedWelcomePath,
	)
	if joinErr != nil {
		t.Fatalf("conversation-join with relayed welcome failed: %v\n%s", joinErr, string(joinOutput))
	}

	joinEnvelope := parseSidecarEnvelope(t, joinOutput)
	if !joinEnvelope.OK {
		t.Fatal("conversation-join ok = false, want true")
	}
	if joinEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("join group_id_ref = %q, add-member group_id_ref = %q", joinEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}
	if joinEnvelope.Data.MemberCount != 2 {
		t.Fatalf("join member_count = %d, want 2", joinEnvelope.Data.MemberCount)
	}
	assertNoSecretMaterialInStdout(t, joinOutput)

	messageLabel := "full-lifecycle-message-0001"
	plaintext := "hello bob through full cypher lifecycle"

	protectEnvelope := protectOpenMLSSidecarMessage(t, messageLabel, plaintext)
	if protectEnvelope.Data.MessageArtifactPathHint == "" {
		t.Fatal("message-protect should return message artifact path hint")
	}
	if protectEnvelope.Data.GroupIDRef != addMemberEnvelope.Data.GroupIDRef {
		t.Fatalf("protect group_id_ref = %q, add-member group_id_ref = %q", protectEnvelope.Data.GroupIDRef, addMemberEnvelope.Data.GroupIDRef)
	}

	messageArtifactPath := filepath.Join(openMLSSidecarDir, protectEnvelope.Data.MessageArtifactPathHint)

	if _, err := relay.SubmitOpenMLSArtifactEnvelope(
		cypherClient,
		"alice-cypher-device-id",
		"bob-cypher-device-id",
		relay.ArtifactKindApplicationMessage,
		messageArtifactPath,
		"2026-05-27T00:02:00Z",
	); err != nil {
		t.Fatalf("SubmitOpenMLSArtifactEnvelope application message failed: %v", err)
	}

	bobMessageInbox, err := cypherClient.Inbox("bob-cypher-device-id")
	if err != nil {
		t.Fatalf("bob Cypher inbox for application message failed: %v", err)
	}
	if len(bobMessageInbox.Envelopes) != 2 {
		t.Fatalf("expected 2 queued envelopes for Bob before ack support, got %d", len(bobMessageInbox.Envelopes))
	}

	var messageEnvelopeFound bool
	var messageEnvelopeIndex int
	for i, envelope := range bobMessageInbox.Envelopes {
		if envelope.ContentType == relay.ContentTypeOpenMLSApplicationMessage {
			messageEnvelopeFound = true
			messageEnvelopeIndex = i
			break
		}
	}
	if !messageEnvelopeFound {
		t.Fatal("expected application-message relay envelope in Bob inbox")
	}

	messageEnvelope := bobMessageInbox.Envelopes[messageEnvelopeIndex]

	downloadedMessagePath := filepath.Join(t.TempDir(), "downloaded-application-message.bin")
	if err := relay.WriteOpenMLSArtifactFromEnvelope(downloadedMessagePath, messageEnvelope); err != nil {
		t.Fatalf("WriteOpenMLSArtifactFromEnvelope application message failed: %v", err)
	}

	openEnvelope, openOutput := openOpenMLSSidecarMessage(t, messageLabel, downloadedMessagePath)
	assertMessageOpenSuccess(t, openEnvelope, messageLabel, plaintext, addMemberEnvelope.Data.GroupIDRef)
	assertNoSecretMaterialInStdout(t, openOutput)
}
