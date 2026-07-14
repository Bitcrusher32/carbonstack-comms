package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func TestOpenMLSRelayKeyPackageConsumeDevPersistsReceiptBeforeAck(t *testing.T) {
	payload := []byte("deterministic-keypackage-bytes")
	sum := sha256.Sum256(payload)
	payloadSHA := hex.EncodeToString(sum[:])

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	receiptRoot := filepath.Join(tmp, "receipts")
	envelopeID := "env-b5d-1"
	relaySpaceID := "rs-b5d"
	deviceID := "recipient-device"
	senderID := "sender-device"

	ackCalled := false
	var serverURL string
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
						"content_type":        "carbonstack.mls.keypackage.v0",
						"protocol_version":    "carbonstack-openmls-sidecar-v0",
						"ciphertext_b64":      base64.StdEncoding.EncodeToString(payload),
						"payload_sha256":      payloadSHA,
						"payload_size_bytes":  len(payload),
						"delivery_state":      "queued",
						"server_received_at":  "2026-07-14T10:00:00Z",
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v0/relay-spaces/"+relaySpaceID+"/envelopes/"+envelopeID+"/ack":
			if _, err := os.Stat(keyPackageConsumeReceiptManifestPath(receiptRoot, envelopeID)); err != nil {
				t.Fatalf("receipt manifest was not persisted before ACK: %v", err)
			}
			if _, err := os.Stat(keyPackageConsumeReceiptArtifactPath(receiptRoot, envelopeID)); err != nil {
				t.Fatalf("receipt artifact was not persisted before ACK: %v", err)
			}
			ackCalled = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"envelope_id":     envelopeID,
				"relay_space_id":  relaySpaceID,
				"delivery_state":  "acknowledged",
				"acknowledged_at": "2026-07-14T10:01:00Z",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	if err := state.Save(statePath, state.State{
		ServerURL: serverURL,
		AccountID: "acct",
		DeviceID:  deviceID,
	}); err != nil {
		t.Fatal(err)
	}

	err := cmdOpenMLSRelayKeyPackageConsumeDev([]string{
		"--state", statePath,
		"--relay-space", relaySpaceID,
		"--envelope-id", envelopeID,
		"--receipt-root", receiptRoot,
		"--expected-payload-sha256", payloadSHA,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ackCalled {
		t.Fatal("ACK was not called")
	}

	receipt, ok, err := loadKeyPackageConsumeReceipt(keyPackageConsumeReceiptManifestPath(receiptRoot, envelopeID))
	if err != nil || !ok {
		t.Fatalf("load receipt ok=%v err=%v", ok, err)
	}
	if !receipt.LocalReceiptPersisted || !receipt.KeyPackageAcked {
		t.Fatalf("receipt persisted=%v acked=%v", receipt.LocalReceiptPersisted, receipt.KeyPackageAcked)
	}
	if receipt.AddMemberRun || receipt.WelcomeSubmitted || receipt.TrustOrCandidateStateMutated || receipt.PublicDirectoryMutated {
		t.Fatalf("B5d nonclaim mutated unexpectedly: %+v", receipt)
	}
}

func TestOpenMLSRelayKeyPackageConsumeDevExactReplayUsesLocalReceipt(t *testing.T) {
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	receiptRoot := filepath.Join(tmp, "receipts")
	envelopeID := "env-replay"
	relaySpaceID := "rs-replay"
	deviceID := "dev-replay"

	if err := state.Save(statePath, state.State{
		ServerURL: "http://127.0.0.1:1",
		AccountID: "acct",
		DeviceID:  deviceID,
	}); err != nil {
		t.Fatal(err)
	}

	receipt := keyPackageConsumeReceipt{
		SchemaVersion:                keyPackageConsumeReceiptSchema,
		Command:                      "openmls-relay-keypackage-consume-dev",
		ConsumeClassification:        "consumed_and_acked",
		EnvelopeID:                   envelopeID,
		RelaySpaceID:                 relaySpaceID,
		SenderDeviceID:               "sender",
		RecipientDeviceID:            deviceID,
		ContentType:                  "carbonstack.mls.keypackage.v0",
		ProtocolVersion:              "carbonstack-openmls-sidecar-v0",
		PayloadSHA256:                "abc",
		ArtifactSHA256:               "abc",
		ArtifactPath:                 keyPackageConsumeReceiptArtifactPath(receiptRoot, envelopeID),
		ReceiptManifestPath:          keyPackageConsumeReceiptManifestPath(receiptRoot, envelopeID),
		ConsumedAt:                   "2026-07-14T10:00:00Z",
		AckedAt:                      "2026-07-14T10:01:00Z",
		AckDeliveryState:             "acknowledged",
		LocalReceiptPersisted:        true,
		KeyPackageAcked:              true,
		AddMemberRun:                 false,
		WelcomeSubmitted:             false,
		TrustOrCandidateStateMutated: false,
		PublicDirectoryMutated:       false,
	}
	if err := writeKeyPackageConsumeReceiptAtomic(keyPackageConsumeReceiptManifestPath(receiptRoot, envelopeID), receipt); err != nil {
		t.Fatal(err)
	}

	err := cmdOpenMLSRelayKeyPackageConsumeDev([]string{
		"--state", statePath,
		"--relay-space", relaySpaceID,
		"--envelope-id", envelopeID,
		"--receipt-root", receiptRoot,
	})
	if err != nil {
		t.Fatal(err)
	}

	replayed, _, err := loadKeyPackageConsumeReceipt(keyPackageConsumeReceiptManifestPath(receiptRoot, envelopeID))
	if err != nil {
		t.Fatal(err)
	}
	// The command returns the transient replay classification in stdout, but
	// the durable manifest remains the original consume/ACK history. Exact
	// replay must not rewrite receipt state just to record that it was replayed.
	if replayed.ConsumeClassification != "consumed_and_acked" {
		t.Fatalf("persisted classification=%q", replayed.ConsumeClassification)
	}
}

func TestOpenMLSRelayKeyPackageConsumeDevAckFailureLeavesPersistedReceipt(t *testing.T) {
	payload := []byte("keypackage-before-ack-failure")
	sum := sha256.Sum256(payload)
	payloadSHA := hex.EncodeToString(sum[:])

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	receiptRoot := filepath.Join(tmp, "receipts")
	envelopeID := "env-ack-fail"
	relaySpaceID := "rs-ack-fail"
	deviceID := "dev-ack-fail"

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
						"content_type":        "carbonstack.mls.keypackage.v0",
						"protocol_version":    "carbonstack-openmls-sidecar-v0",
						"ciphertext_b64":      base64.StdEncoding.EncodeToString(payload),
						"payload_sha256":      payloadSHA,
						"payload_size_bytes":  len(payload),
						"delivery_state":      "queued",
					},
				},
			})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/ack"):
			http.Error(w, `{"error":{"code":"forced_ack_failure","message":"forced"}}`, http.StatusInternalServerError)
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

	err := cmdOpenMLSRelayKeyPackageConsumeDev([]string{
		"--state", statePath,
		"--relay-space", relaySpaceID,
		"--envelope-id", envelopeID,
		"--receipt-root", receiptRoot,
	})
	if err == nil {
		t.Fatal("expected ACK failure")
	}

	receipt, ok, loadErr := loadKeyPackageConsumeReceipt(keyPackageConsumeReceiptManifestPath(receiptRoot, envelopeID))
	if loadErr != nil || !ok {
		t.Fatalf("receipt missing after ACK failure ok=%v err=%v", ok, loadErr)
	}
	if !receipt.LocalReceiptPersisted {
		t.Fatal("receipt was not marked persisted")
	}
	if receipt.KeyPackageAcked || receipt.AckedAt != "" {
		t.Fatalf("receipt should not be acked after forced failure: %+v", receipt)
	}
}
