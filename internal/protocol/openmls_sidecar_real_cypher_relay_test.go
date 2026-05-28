package protocol

import (
	"path/filepath"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/relay"
)

func TestOpenMLSSidecarFullLifecycleRelayThroughRealCypherServer(t *testing.T) {
	removeOpenMLSSidecarState(t)

	server := startRealCypherTestServer(t)
	cypherClient := client.New(server.URL())

	aliceAccount, err := cypherClient.ClaimInvite("dev-invite", "alice-real-cypher-smoke")
	if err != nil {
		t.Fatalf("claim Alice invite against real Cypher server: %v", err)
	}

	bobInvite, err := cypherClient.CreateDevInvite("bob-real-cypher-smoke-invite")
	if err != nil {
		t.Fatalf("create Bob invite against real Cypher server: %v", err)
	}

	bobAccount, err := cypherClient.ClaimInvite(bobInvite.InviteCode, "bob-real-cypher-smoke")
	if err != nil {
		t.Fatalf("claim Bob invite against real Cypher server: %v", err)
	}

	aliceCypherDevice, err := cypherClient.RegisterDevice(
		aliceAccount.AccountID,
		"alice-real-cypher-device",
		"stub-alice-real-cypher-public-identity-key",
		"stub-alice-real-cypher-prekey-bundle",
	)
	if err != nil {
		t.Fatalf("register Alice Cypher device: %v", err)
	}

	bobCypherDevice, err := cypherClient.RegisterDevice(
		bobAccount.AccountID,
		"bob-real-cypher-device",
		"stub-bob-real-cypher-public-identity-key",
		"stub-bob-real-cypher-prekey-bundle",
	)
	if err != nil {
		t.Fatalf("register Bob Cypher device: %v", err)
	}

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
		bobCypherDevice.DeviceID,
		aliceCypherDevice.DeviceID,
		relay.ArtifactKindKeyPackage,
		keyPackageArtifactPath,
		"2026-05-27T00:00:00Z",
	); err != nil {
		t.Fatalf("SubmitOpenMLSArtifactEnvelope keypackage through real Cypher failed: %v", err)
	}

	aliceInbox, err := cypherClient.Inbox(aliceCypherDevice.DeviceID)
	if err != nil {
		t.Fatalf("alice real Cypher inbox failed: %v", err)
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

	if _, err := cypherClient.AckEnvelope(keyPackageEnvelope.EnvelopeID, aliceCypherDevice.DeviceID); err != nil {
		t.Fatalf("ack keypackage envelope after successful conversation-add-member failed: %v", err)
	}

	aliceInboxAfterAck, err := cypherClient.Inbox(aliceCypherDevice.DeviceID)
	if err != nil {
		t.Fatalf("alice real Cypher inbox after keypackage ack failed: %v", err)
	}
	if len(aliceInboxAfterAck.Envelopes) != 0 {
		t.Fatalf("expected Alice inbox to be empty after keypackage ack, got %d envelopes", len(aliceInboxAfterAck.Envelopes))
	}

	welcomeArtifactPath := filepath.Join(openMLSSidecarDir, addMemberEnvelope.Data.WelcomeArtifactPathHint)

	if _, err := relay.SubmitOpenMLSArtifactEnvelope(
		cypherClient,
		aliceCypherDevice.DeviceID,
		bobCypherDevice.DeviceID,
		relay.ArtifactKindWelcome,
		welcomeArtifactPath,
		"2026-05-27T00:01:00Z",
	); err != nil {
		t.Fatalf("SubmitOpenMLSArtifactEnvelope welcome through real Cypher failed: %v", err)
	}

	bobWelcomeInbox, err := cypherClient.Inbox(bobCypherDevice.DeviceID)
	if err != nil {
		t.Fatalf("bob real Cypher inbox for welcome failed: %v", err)
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

	if _, err := cypherClient.AckEnvelope(welcomeEnvelope.EnvelopeID, bobCypherDevice.DeviceID); err != nil {
		t.Fatalf("ack welcome envelope after successful conversation-join failed: %v", err)
	}

	bobInboxAfterWelcomeAck, err := cypherClient.Inbox(bobCypherDevice.DeviceID)
	if err != nil {
		t.Fatalf("bob real Cypher inbox after welcome ack failed: %v", err)
	}
	if len(bobInboxAfterWelcomeAck.Envelopes) != 0 {
		t.Fatalf("expected Bob inbox to be empty after welcome ack, got %d envelopes", len(bobInboxAfterWelcomeAck.Envelopes))
	}

	messageLabel := "real-cypher-full-lifecycle-message-0001"
	plaintext := "hello bob through real cypher server lifecycle"

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
		aliceCypherDevice.DeviceID,
		bobCypherDevice.DeviceID,
		relay.ArtifactKindApplicationMessage,
		messageArtifactPath,
		"2026-05-27T00:02:00Z",
	); err != nil {
		t.Fatalf("SubmitOpenMLSArtifactEnvelope application message through real Cypher failed: %v", err)
	}

	bobMessageInbox, err := cypherClient.Inbox(bobCypherDevice.DeviceID)
	if err != nil {
		t.Fatalf("bob real Cypher inbox for application message failed: %v", err)
	}
	if len(bobMessageInbox.Envelopes) != 1 {
		t.Fatalf("expected 1 queued application-message envelope for Bob after welcome ack, got %d", len(bobMessageInbox.Envelopes))
	}

	var messageEnvelopeFound bool
	var messageEnvelope client.EnvelopeRecord
	for _, envelope := range bobMessageInbox.Envelopes {
		if envelope.ContentType == relay.ContentTypeOpenMLSApplicationMessage {
			messageEnvelopeFound = true
			messageEnvelope = envelope
			break
		}
	}
	if !messageEnvelopeFound {
		t.Fatal("expected application-message relay envelope in Bob inbox")
	}

	downloadedMessagePath := filepath.Join(t.TempDir(), "downloaded-application-message.bin")
	if err := relay.WriteOpenMLSArtifactFromEnvelope(downloadedMessagePath, messageEnvelope); err != nil {
		t.Fatalf("WriteOpenMLSArtifactFromEnvelope application message failed: %v", err)
	}

	openEnvelope, openOutput := openOpenMLSSidecarMessage(t, messageLabel, downloadedMessagePath)
	assertMessageOpenSuccess(t, openEnvelope, messageLabel, plaintext, addMemberEnvelope.Data.GroupIDRef)
	assertNoSecretMaterialInStdout(t, openOutput)

	if _, err := cypherClient.AckEnvelope(messageEnvelope.EnvelopeID, bobCypherDevice.DeviceID); err != nil {
		t.Fatalf("ack application-message envelope after successful message-open failed: %v", err)
	}

	bobInboxAfterMessageAck, err := cypherClient.Inbox(bobCypherDevice.DeviceID)
	if err != nil {
		t.Fatalf("bob real Cypher inbox after application-message ack failed: %v", err)
	}
	if len(bobInboxAfterMessageAck.Envelopes) != 0 {
		t.Fatalf("expected Bob inbox to be empty after application-message ack, got %d envelopes", len(bobInboxAfterMessageAck.Envelopes))
	}
}
