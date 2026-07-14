package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func TestOpenMLSRelayWelcomeConsumeDevPersistsJoinBeforeAck(t *testing.T) {
	payload := []byte("deterministic-welcome-bytes")
	sum := sha256.Sum256(payload)
	payloadSHA := hex.EncodeToString(sum[:])

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	receiptRoot := filepath.Join(tmp, "welcome-receipts")
	envelopeID := "welcome-env-1"
	relaySpaceID := "rs-welcome"
	deviceID := "recipient-device"
	senderID := "sender-device"

	oldRunner := runOpenMLSBootstrapSidecarForCommand
	defer func() { runOpenMLSBootstrapSidecarForCommand = oldRunner }()

	joinCalled := false
	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, command string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		if command != "conversation-join" {
			t.Fatalf("sidecar command=%q", command)
		}
		if _, err := os.Stat(welcomeConsumeReceiptManifestPath(receiptRoot, envelopeID)); err != nil {
			t.Fatalf("receipt manifest was not persisted before join: %v", err)
		}
		if _, err := os.Stat(welcomeConsumeReceiptArtifactPath(receiptRoot, envelopeID)); err != nil {
			t.Fatalf("Welcome artifact was not persisted before join: %v", err)
		}
		joinCalled = true
		return openMLSSidecarBootstrapEnvelope{
			OK:      true,
			Command: "conversation-join",
			Data: map[string]any{
				"device_label":                   "bob-sidecar",
				"conversation_label":             "conv-a",
				"joined":                         true,
				"group_reloadable":               true,
				"join_summary_path_hint":         "devices/bob/conversations/conv-a/join-summary.json",
				"conversation_state_path_hint":   "devices/bob/conversations/conv-a/conversation-state.json",
				"conversation_summary_path_hint": "devices/bob/conversations/conv-a/conversation-summary.json",
				"provider_storage_path_hint":     "devices/bob/provider-storage.json",
			},
		}, nil
	}

	ackCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v0/relay-spaces/"+relaySpaceID+"/devices/"+deviceID+"/envelopes":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"relay_space_id": relaySpaceID,
				"device_id":      deviceID,
				"envelopes": []map[string]any{
					{
						"envelope_id":         envelopeID,
						"relay_space_id":      relaySpaceID,
						"sender_device_id":    senderID,
						"recipient_device_id": deviceID,
						"content_type":        "carbonstack.mls.welcome.v0",
						"protocol_version":    "carbonstack-openmls-sidecar-v0",
						"ciphertext_b64":      base64.StdEncoding.EncodeToString(payload),
						"payload_sha256":      payloadSHA,
						"payload_size_bytes":  len(payload),
						"delivery_state":      "queued",
						"server_received_at":  "2026-07-14T11:00:00Z",
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v0/relay-spaces/"+relaySpaceID+"/envelopes/"+envelopeID+"/ack":
			receipt, ok, err := loadWelcomeConsumeReceipt(welcomeConsumeReceiptManifestPath(receiptRoot, envelopeID))
			if err != nil || !ok {
				t.Fatalf("receipt missing before ACK ok=%v err=%v", ok, err)
			}
			if !receipt.LocalWelcomePersisted || !receipt.Joined {
				t.Fatalf("ACK happened before persisted join evidence: %+v", receipt)
			}
			ackCalled = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"envelope_id":     envelopeID,
				"relay_space_id":  relaySpaceID,
				"delivery_state":  "acknowledged",
				"acknowledged_at": "2026-07-14T11:01:00Z",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if err := state.Save(statePath, state.State{
		ServerURL: server.URL,
		AccountID: "acct",
		DeviceID:  deviceID,
	}); err != nil {
		t.Fatal(err)
	}

	err := cmdOpenMLSRelayWelcomeConsumeDev([]string{
		"--state", statePath,
		"--relay-space", relaySpaceID,
		"--envelope-id", envelopeID,
		"--sidecar-device-label", "bob-sidecar",
		"--conversation", "conv-a",
		"--receipt-root", receiptRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !joinCalled {
		t.Fatal("join was not called")
	}
	if !ackCalled {
		t.Fatal("ACK was not called")
	}

	receipt, ok, err := loadWelcomeConsumeReceipt(welcomeConsumeReceiptManifestPath(receiptRoot, envelopeID))
	if err != nil || !ok {
		t.Fatalf("load receipt ok=%v err=%v", ok, err)
	}
	if !receipt.LocalWelcomePersisted || !receipt.Joined || !receipt.WelcomeAcked {
		t.Fatalf("receipt not fully closed: %+v", receipt)
	}
	if receipt.TrustOrCandidateStateMutated || receipt.VerifiedIdentityClaimed || receipt.CypherMLSReconciled || receipt.PublicDirectoryMutated {
		t.Fatalf("B6 nonclaim mutated unexpectedly: %+v", receipt)
	}
}

func TestOpenMLSRelayWelcomeConsumeDevExactReplayUsesLocalReceipt(t *testing.T) {
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	receiptRoot := filepath.Join(tmp, "welcome-receipts")
	envelopeID := "welcome-replay"
	relaySpaceID := "rs-replay"
	deviceID := "dev-replay"

	if err := state.Save(statePath, state.State{
		ServerURL: "http://127.0.0.1:1",
		AccountID: "acct",
		DeviceID:  deviceID,
	}); err != nil {
		t.Fatal(err)
	}

	receipt := welcomeConsumeReceipt{
		SchemaVersion:                welcomeConsumeReceiptSchema,
		Command:                      "openmls-relay-welcome-consume-dev",
		JoinClassification:           "joined_and_acked",
		EnvelopeID:                   envelopeID,
		RelaySpaceID:                 relaySpaceID,
		SenderDeviceID:               "sender",
		RecipientDeviceID:            deviceID,
		ContentType:                  "carbonstack.mls.welcome.v0",
		ProtocolVersion:              "carbonstack-openmls-sidecar-v0",
		PayloadSHA256:                "abc",
		ArtifactSHA256:               "abc",
		SidecarDeviceLabel:           "bob",
		ConversationLabel:            "conv",
		WelcomeArtifactPath:          welcomeConsumeReceiptArtifactPath(receiptRoot, envelopeID),
		ReceiptManifestPath:          welcomeConsumeReceiptManifestPath(receiptRoot, envelopeID),
		WelcomePersistedAt:           "2026-07-14T11:00:00Z",
		JoinedAt:                     "2026-07-14T11:00:30Z",
		AckedAt:                      "2026-07-14T11:01:00Z",
		AckDeliveryState:             "acknowledged",
		Joined:                       true,
		LocalWelcomePersisted:        true,
		WelcomeAcked:                 true,
		AckAfterJoin:                 true,
		AddMemberRun:                 false,
		TrustOrCandidateStateMutated: false,
		VerifiedIdentityClaimed:      false,
		CypherMLSReconciled:          false,
		PublicDirectoryMutated:       false,
	}
	if err := writeWelcomeConsumeReceiptAtomic(welcomeConsumeReceiptManifestPath(receiptRoot, envelopeID), receipt); err != nil {
		t.Fatal(err)
	}

	err := cmdOpenMLSRelayWelcomeConsumeDev([]string{
		"--state", statePath,
		"--relay-space", relaySpaceID,
		"--envelope-id", envelopeID,
		"--sidecar-device-label", "bob",
		"--conversation", "conv",
		"--receipt-root", receiptRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	replayed, _, err := loadWelcomeConsumeReceipt(welcomeConsumeReceiptManifestPath(receiptRoot, envelopeID))
	if err != nil {
		t.Fatal(err)
	}
	if replayed.JoinClassification != "joined_and_acked" {
		t.Fatalf("persisted classification=%q", replayed.JoinClassification)
	}
}

func TestOpenMLSRelayWelcomeConsumeDevJoinFailureLeavesPersistedUnackedReceipt(t *testing.T) {
	payload := []byte("welcome-before-join-failure")
	sum := sha256.Sum256(payload)
	payloadSHA := hex.EncodeToString(sum[:])

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	receiptRoot := filepath.Join(tmp, "welcome-receipts")
	envelopeID := "welcome-join-fail"
	relaySpaceID := "rs-join-fail"
	deviceID := "dev-join-fail"

	oldRunner := runOpenMLSBootstrapSidecarForCommand
	defer func() { runOpenMLSBootstrapSidecarForCommand = oldRunner }()
	runOpenMLSBootstrapSidecarForCommand = func(sidecarDir string, command string, args ...string) (openMLSSidecarBootstrapEnvelope, error) {
		return openMLSSidecarBootstrapEnvelope{}, errors.New("forced join failure")
	}

	ackCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"relay_space_id": relaySpaceID,
				"device_id":      deviceID,
				"envelopes": []map[string]any{
					{
						"envelope_id":         envelopeID,
						"relay_space_id":      relaySpaceID,
						"sender_device_id":    "sender",
						"recipient_device_id": deviceID,
						"content_type":        "carbonstack.mls.welcome.v0",
						"protocol_version":    "carbonstack-openmls-sidecar-v0",
						"ciphertext_b64":      base64.StdEncoding.EncodeToString(payload),
						"payload_sha256":      payloadSHA,
						"payload_size_bytes":  len(payload),
						"delivery_state":      "queued",
					},
				},
			})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/ack"):
			ackCalled = true
			http.Error(w, `{"error":{"code":"unexpected_ack","message":"unexpected"}}`, http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	if err := state.Save(statePath, state.State{
		ServerURL: server.URL,
		AccountID: "acct",
		DeviceID:  deviceID,
	}); err != nil {
		t.Fatal(err)
	}

	err := cmdOpenMLSRelayWelcomeConsumeDev([]string{
		"--state", statePath,
		"--relay-space", relaySpaceID,
		"--envelope-id", envelopeID,
		"--sidecar-device-label", "bob",
		"--conversation", "conv",
		"--receipt-root", receiptRoot,
	})
	if err == nil {
		t.Fatal("expected join failure")
	}
	if ackCalled {
		t.Fatal("ACK was called after join failure")
	}

	receipt, ok, loadErr := loadWelcomeConsumeReceipt(welcomeConsumeReceiptManifestPath(receiptRoot, envelopeID))
	if loadErr != nil || !ok {
		t.Fatalf("receipt missing after join failure ok=%v err=%v", ok, loadErr)
	}
	if !receipt.LocalWelcomePersisted {
		t.Fatal("Welcome was not persisted before join failure")
	}
	if receipt.Joined || receipt.WelcomeAcked || receipt.AckedAt != "" {
		t.Fatalf("receipt should not be joined/acked after forced failure: %+v", receipt)
	}
}
