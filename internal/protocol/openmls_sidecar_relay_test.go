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
