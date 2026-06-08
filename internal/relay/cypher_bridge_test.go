package relay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
)

func TestWriteOpenMLSArtifactFromEnvelope(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "downloaded", "application-message.bin")

	want := []byte{0x00, 0x01, 0x02, 0xfe, 0xff, 'm', 'l', 's'}
	payloadSHA256, payloadSizeBytes := payloadMetadataForTest(want)
	envelope := client.EnvelopeRecord{
		ContentType:      ContentTypeOpenMLSApplicationMessage,
		ProtocolVersion:  ProtocolVersionOpenMLSSidecar,
		CiphertextB64:    EncodePayloadBase64(want),
		PayloadSHA256:    payloadSHA256,
		PayloadSizeBytes: payloadSizeBytes,
	}

	if err := WriteOpenMLSArtifactFromEnvelope(outputPath, envelope); err != nil {
		t.Fatalf("WriteOpenMLSArtifactFromEnvelope: %v", err)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read written artifact: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("artifact bytes = %x, want %x", got, want)
	}
}

func TestSubmitOpenMLSArtifactEnvelopeUsesCypherEnvelopeContract(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "application-message.bin")
	payload := []byte{0x10, 0x20, 0x30, 0x40, 0xfe, 0xff}

	if err := os.WriteFile(artifactPath, payload, 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	var captured map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}

		if r.URL.Path != "/v0/envelopes" {
			t.Fatalf("path = %s, want /v0/envelopes", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}

		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("decode request body: %v\n%s", err, string(body))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
"envelope_id":"test-envelope-id",
"server_received_at":"2026-05-27T00:00:00Z",
"delivery_state":"queued"
}`))
	}))
	defer server.Close()

	c := client.New(strings.TrimRight(server.URL, "/"))

	resp, err := SubmitOpenMLSArtifactEnvelope(
		c,
		"alice-device-id",
		"bob-device-id",
		ArtifactKindApplicationMessage,
		artifactPath,
		"2026-05-27T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("SubmitOpenMLSArtifactEnvelope: %v", err)
	}

	if resp.EnvelopeID != "test-envelope-id" {
		t.Fatalf("envelope_id = %q, want test-envelope-id", resp.EnvelopeID)
	}

	if captured["sender_device_id"] != "alice-device-id" {
		t.Fatalf("sender_device_id = %q", captured["sender_device_id"])
	}
	if captured["recipient_device_id"] != "bob-device-id" {
		t.Fatalf("recipient_device_id = %q", captured["recipient_device_id"])
	}
	if captured["content_type"] != ContentTypeOpenMLSApplicationMessage {
		t.Fatalf("content_type = %q, want %q", captured["content_type"], ContentTypeOpenMLSApplicationMessage)
	}
	if captured["protocol_version"] != ProtocolVersionOpenMLSSidecar {
		t.Fatalf("protocol_version = %q, want %q", captured["protocol_version"], ProtocolVersionOpenMLSSidecar)
	}
	if captured["ciphertext_b64"] != EncodePayloadBase64(payload) {
		t.Fatalf("ciphertext_b64 did not match encoded artifact payload")
	}
	if captured["client_created_at"] != "2026-05-27T00:00:00Z" {
		t.Fatalf("client_created_at = %q", captured["client_created_at"])
	}
}

func TestSubmitOpenMLSArtifactEnvelopeRejectsUnsupportedKind(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "signer.json")

	if err := os.WriteFile(artifactPath, []byte("do not relay"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	c := client.New("http://127.0.0.1:1")

	_, err := SubmitOpenMLSArtifactEnvelope(
		c,
		"alice-device-id",
		"bob-device-id",
		"signer.json",
		artifactPath,
		"2026-05-27T00:00:00Z",
	)
	if err == nil {
		t.Fatal("expected unsupported artifact kind error")
	}
}
func payloadMetadataForTest(payload []byte) (string, int64) {
	hash := sha256.Sum256(payload)
	return hex.EncodeToString(hash[:]), int64(len(payload))
}

func TestWriteOpenMLSArtifactFromEnvelopeRejectsPayloadSizeMismatch(t *testing.T) {
	payload := []byte("metadata size mismatch")
	payloadSHA256, _ := payloadMetadataForTest(payload)

	envelope := client.EnvelopeRecord{
		ContentType:      ContentTypeOpenMLSApplicationMessage,
		ProtocolVersion:  ProtocolVersionOpenMLSSidecar,
		CiphertextB64:    EncodePayloadBase64(payload),
		PayloadSHA256:    payloadSHA256,
		PayloadSizeBytes: int64(len(payload) + 1),
	}

	err := WriteOpenMLSArtifactFromEnvelope(filepath.Join(t.TempDir(), "artifact.bin"), envelope)
	if err == nil {
		t.Fatal("expected payload_size_bytes mismatch error")
	}
	if !strings.Contains(err.Error(), "payload_size_bytes mismatch") {
		t.Fatalf("expected payload_size_bytes mismatch error, got %v", err)
	}
}

func TestWriteOpenMLSArtifactFromEnvelopeRejectsPayloadSHA256Mismatch(t *testing.T) {
	payload := []byte("metadata hash mismatch")

	envelope := client.EnvelopeRecord{
		ContentType:      ContentTypeOpenMLSApplicationMessage,
		ProtocolVersion:  ProtocolVersionOpenMLSSidecar,
		CiphertextB64:    EncodePayloadBase64(payload),
		PayloadSHA256:    strings.Repeat("0", 64),
		PayloadSizeBytes: int64(len(payload)),
	}

	err := WriteOpenMLSArtifactFromEnvelope(filepath.Join(t.TempDir(), "artifact.bin"), envelope)
	if err == nil {
		t.Fatal("expected payload_sha256 mismatch error")
	}
	if !strings.Contains(err.Error(), "payload_sha256 mismatch") {
		t.Fatalf("expected payload_sha256 mismatch error, got %v", err)
	}
}

func TestSubmitRelaySpaceOpenMLSArtifactEnvelopeUsesScopedCypherEnvelopeContract(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "application-message.bin")
	payload := []byte{0x10, 0x20, 0x30, 0x40, 0xfe, 0xff, 'r', 's'}

	if err := os.WriteFile(artifactPath, payload, 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	var captured map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}

		if r.URL.Path != "/v0/relay-spaces/relay-space-1/envelopes" {
			t.Fatalf("path = %s, want /v0/relay-spaces/relay-space-1/envelopes", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}

		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("decode request body: %v\\n%s", err, string(body))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{
"envelope_id":"relay-space-envelope-1",
"relay_space_id":"relay-space-1",
"server_received_at":"2026-06-08T00:00:00Z",
"delivery_state":"queued",
"payload_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
"payload_size_bytes":8
}`))
	}))
	defer server.Close()

	c := client.New(strings.TrimRight(server.URL, "/"))

	resp, err := SubmitRelaySpaceOpenMLSArtifactEnvelope(
		c,
		"relay-space-1",
		"alice-device-id",
		"bob-device-id",
		ArtifactKindApplicationMessage,
		artifactPath,
		"2026-06-08T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("SubmitRelaySpaceOpenMLSArtifactEnvelope: %v", err)
	}

	if resp.EnvelopeID != "relay-space-envelope-1" {
		t.Fatalf("envelope_id = %q, want relay-space-envelope-1", resp.EnvelopeID)
	}
	if resp.RelaySpaceID != "relay-space-1" {
		t.Fatalf("relay_space_id = %q, want relay-space-1", resp.RelaySpaceID)
	}

	if captured["sender_device_id"] != "alice-device-id" {
		t.Fatalf("sender_device_id = %q", captured["sender_device_id"])
	}
	if captured["recipient_device_id"] != "bob-device-id" {
		t.Fatalf("recipient_device_id = %q", captured["recipient_device_id"])
	}
	if captured["content_type"] != ContentTypeOpenMLSApplicationMessage {
		t.Fatalf("content_type = %q, want %q", captured["content_type"], ContentTypeOpenMLSApplicationMessage)
	}
	if captured["protocol_version"] != ProtocolVersionOpenMLSSidecar {
		t.Fatalf("protocol_version = %q, want %q", captured["protocol_version"], ProtocolVersionOpenMLSSidecar)
	}
	if captured["ciphertext_b64"] != EncodePayloadBase64(payload) {
		t.Fatalf("ciphertext_b64 did not match encoded artifact payload")
	}
	if captured["client_created_at"] != "2026-06-08T00:00:00Z" {
		t.Fatalf("client_created_at = %q", captured["client_created_at"])
	}
}

func TestSubmitRelaySpaceOpenMLSArtifactEnvelopeRejectsMissingRelaySpaceID(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "application-message.bin")

	if err := os.WriteFile(artifactPath, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	c := client.New("http://127.0.0.1:1")

	_, err := SubmitRelaySpaceOpenMLSArtifactEnvelope(
		c,
		"",
		"alice-device-id",
		"bob-device-id",
		ArtifactKindApplicationMessage,
		artifactPath,
		"2026-06-08T00:00:00Z",
	)
	if err == nil {
		t.Fatal("expected relay_space_id required error")
	}
	if !strings.Contains(err.Error(), "relay_space_id is required") {
		t.Fatalf("expected relay_space_id required error, got %v", err)
	}
}

func TestSubmitRelaySpaceOpenMLSArtifactEnvelopeRejectsUnsupportedKind(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "signer.json")

	if err := os.WriteFile(artifactPath, []byte("do not relay"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}

	c := client.New("http://127.0.0.1:1")

	_, err := SubmitRelaySpaceOpenMLSArtifactEnvelope(
		c,
		"relay-space-1",
		"alice-device-id",
		"bob-device-id",
		"signer.json",
		artifactPath,
		"2026-06-08T00:00:00Z",
	)
	if err == nil {
		t.Fatal("expected unsupported artifact kind error")
	}
	if !strings.Contains(err.Error(), ErrUnsupportedArtifactKind.Error()) {
		t.Fatalf("expected unsupported artifact kind error, got %v", err)
	}
}

func TestWriteOpenMLSArtifactFromRelaySpaceEnvelope(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "downloaded", "application-message.bin")

	want := []byte{0x00, 0x01, 0x02, 0xfe, 0xff, 'm', 'l', 's', 'r', 's'}
	payloadSHA256, payloadSizeBytes := payloadMetadataForTest(want)
	envelope := client.RelaySpaceEnvelopeRecord{
		EnvelopeID:        "relay-space-envelope-1",
		RelaySpaceID:      "relay-space-1",
		SenderDeviceID:    "alice-device-id",
		RecipientDeviceID: "bob-device-id",
		ContentType:       ContentTypeOpenMLSApplicationMessage,
		ProtocolVersion:   ProtocolVersionOpenMLSSidecar,
		CiphertextB64:     EncodePayloadBase64(want),
		PayloadSHA256:     payloadSHA256,
		PayloadSizeBytes:  payloadSizeBytes,
		DeliveryState:     "queued",
	}

	if err := WriteOpenMLSArtifactFromRelaySpaceEnvelope(outputPath, envelope); err != nil {
		t.Fatalf("WriteOpenMLSArtifactFromRelaySpaceEnvelope: %v", err)
	}

	got, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read written artifact: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("artifact bytes = %x, want %x", got, want)
	}
}

func TestWriteOpenMLSArtifactFromRelaySpaceEnvelopeRejectsMissingRelaySpaceID(t *testing.T) {
	payload := []byte("missing relay space id")
	payloadSHA256, payloadSizeBytes := payloadMetadataForTest(payload)

	envelope := client.RelaySpaceEnvelopeRecord{
		ContentType:      ContentTypeOpenMLSApplicationMessage,
		ProtocolVersion:  ProtocolVersionOpenMLSSidecar,
		CiphertextB64:    EncodePayloadBase64(payload),
		PayloadSHA256:    payloadSHA256,
		PayloadSizeBytes: payloadSizeBytes,
	}

	err := WriteOpenMLSArtifactFromRelaySpaceEnvelope(filepath.Join(t.TempDir(), "artifact.bin"), envelope)
	if err == nil {
		t.Fatal("expected relay_space_id required error")
	}
	if !strings.Contains(err.Error(), "relay_space_id is required") {
		t.Fatalf("expected relay_space_id required error, got %v", err)
	}
}

func TestRelaySpaceKeyPackageAndWelcomeTransportHelpers(t *testing.T) {
	dir := t.TempDir()

	keyPackagePath := filepath.Join(dir, "public-bundle.keypackage.bin")
	keyPackagePayload := []byte("stub-keypackage-payload")
	if err := os.WriteFile(keyPackagePath, keyPackagePayload, 0o600); err != nil {
		t.Fatalf("write keypackage artifact: %v", err)
	}

	welcomePath := filepath.Join(dir, "welcome.bin")
	welcomePayload := []byte("stub-welcome-payload")
	if err := os.WriteFile(welcomePath, welcomePayload, 0o600); err != nil {
		t.Fatalf("write welcome artifact: %v", err)
	}

	var captured []map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v0/relay-spaces/relay-space-1/envelopes":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}

			var req map[string]string
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatalf("decode request body: %v\n%s", err, string(body))
			}
			captured = append(captured, req)

			contentType := req["content_type"]
			envelopeID := "envelope-keypackage"
			payloadSize := len(keyPackagePayload)
			if contentType == ContentTypeOpenMLSWelcome {
				envelopeID = "envelope-welcome"
				payloadSize = len(welcomePayload)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(client.SubmitRelaySpaceEnvelopeResponse{
				EnvelopeID:       envelopeID,
				RelaySpaceID:     "relay-space-1",
				DeliveryState:    "queued",
				ServerReceivedAt: "2026-06-08T00:00:00Z",
				PayloadSHA256:    strings.Repeat("a", 64),
				PayloadSizeBytes: int64(payloadSize),
			})

		case r.Method == http.MethodGet && r.URL.Path == "/v0/relay-spaces/relay-space-1/devices/bob-device/envelopes":
			keyPackageSHA256, keyPackageSize := payloadMetadataForTest(keyPackagePayload)
			welcomeSHA256, welcomeSize := payloadMetadataForTest(welcomePayload)

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(client.RelaySpaceInboxResponse{
				RelaySpaceID: "relay-space-1",
				DeviceID:     "bob-device",
				Envelopes: []client.RelaySpaceEnvelopeRecord{
					{
						EnvelopeID:        "envelope-keypackage",
						RelaySpaceID:      "relay-space-1",
						SenderDeviceID:    "bob-device",
						RecipientDeviceID: "alice-device",
						ContentType:       ContentTypeOpenMLSKeyPackage,
						ProtocolVersion:   ProtocolVersionOpenMLSSidecar,
						CiphertextB64:     EncodePayloadBase64(keyPackagePayload),
						PayloadSHA256:     keyPackageSHA256,
						PayloadSizeBytes:  keyPackageSize,
						DeliveryState:     "queued",
					},
					{
						EnvelopeID:        "envelope-welcome",
						RelaySpaceID:      "relay-space-1",
						SenderDeviceID:    "alice-device",
						RecipientDeviceID: "bob-device",
						ContentType:       ContentTypeOpenMLSWelcome,
						ProtocolVersion:   ProtocolVersionOpenMLSSidecar,
						CiphertextB64:     EncodePayloadBase64(welcomePayload),
						PayloadSHA256:     welcomeSHA256,
						PayloadSizeBytes:  welcomeSize,
						DeliveryState:     "queued",
					},
				},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	c := client.New(strings.TrimRight(server.URL, "/"))

	keyPackageResp, err := SubmitRelaySpaceKeyPackageEnvelope(
		c,
		"relay-space-1",
		"bob-device",
		"alice-device",
		keyPackagePath,
		"2026-06-08T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("SubmitRelaySpaceKeyPackageEnvelope: %v", err)
	}
	if keyPackageResp.EnvelopeID != "envelope-keypackage" {
		t.Fatalf("keypackage envelope_id = %q", keyPackageResp.EnvelopeID)
	}

	welcomeResp, err := SubmitRelaySpaceWelcomeEnvelope(
		c,
		"relay-space-1",
		"alice-device",
		"bob-device",
		welcomePath,
		"2026-06-08T00:00:01Z",
	)
	if err != nil {
		t.Fatalf("SubmitRelaySpaceWelcomeEnvelope: %v", err)
	}
	if welcomeResp.EnvelopeID != "envelope-welcome" {
		t.Fatalf("welcome envelope_id = %q", welcomeResp.EnvelopeID)
	}

	if len(captured) != 2 {
		t.Fatalf("captured request count = %d, want 2", len(captured))
	}
	if captured[0]["content_type"] != ContentTypeOpenMLSKeyPackage {
		t.Fatalf("first content_type = %q, want %q", captured[0]["content_type"], ContentTypeOpenMLSKeyPackage)
	}
	if captured[0]["ciphertext_b64"] != EncodePayloadBase64(keyPackagePayload) {
		t.Fatalf("first ciphertext_b64 did not match keypackage payload")
	}
	if captured[1]["content_type"] != ContentTypeOpenMLSWelcome {
		t.Fatalf("second content_type = %q, want %q", captured[1]["content_type"], ContentTypeOpenMLSWelcome)
	}
	if captured[1]["ciphertext_b64"] != EncodePayloadBase64(welcomePayload) {
		t.Fatalf("second ciphertext_b64 did not match welcome payload")
	}

	keyPackages, err := RelaySpaceOpenMLSArtifactInbox(c, "relay-space-1", "bob-device", ArtifactKindKeyPackage)
	if err != nil {
		t.Fatalf("RelaySpaceOpenMLSArtifactInbox keypackage: %v", err)
	}
	if len(keyPackages) != 1 {
		t.Fatalf("keypackage filtered inbox len = %d, want 1", len(keyPackages))
	}
	if keyPackages[0].ContentType != ContentTypeOpenMLSKeyPackage {
		t.Fatalf("keypackage filtered content_type = %q", keyPackages[0].ContentType)
	}

	welcomes, err := RelaySpaceOpenMLSArtifactInbox(c, "relay-space-1", "bob-device", ArtifactKindWelcome)
	if err != nil {
		t.Fatalf("RelaySpaceOpenMLSArtifactInbox welcome: %v", err)
	}
	if len(welcomes) != 1 {
		t.Fatalf("welcome filtered inbox len = %d, want 1", len(welcomes))
	}
	if welcomes[0].ContentType != ContentTypeOpenMLSWelcome {
		t.Fatalf("welcome filtered content_type = %q", welcomes[0].ContentType)
	}

	keyPackageOut := filepath.Join(dir, "downloaded", "public-bundle.keypackage.bin")
	if err := WriteRelaySpaceKeyPackageFromEnvelope(keyPackageOut, keyPackages[0]); err != nil {
		t.Fatalf("WriteRelaySpaceKeyPackageFromEnvelope: %v", err)
	}
	gotKeyPackage, err := os.ReadFile(keyPackageOut)
	if err != nil {
		t.Fatalf("read keypackage output: %v", err)
	}
	if !bytes.Equal(gotKeyPackage, keyPackagePayload) {
		t.Fatalf("keypackage output = %x, want %x", gotKeyPackage, keyPackagePayload)
	}

	welcomeOut := filepath.Join(dir, "downloaded", "welcome.bin")
	if err := WriteRelaySpaceWelcomeFromEnvelope(welcomeOut, welcomes[0]); err != nil {
		t.Fatalf("WriteRelaySpaceWelcomeFromEnvelope: %v", err)
	}
	gotWelcome, err := os.ReadFile(welcomeOut)
	if err != nil {
		t.Fatalf("read welcome output: %v", err)
	}
	if !bytes.Equal(gotWelcome, welcomePayload) {
		t.Fatalf("welcome output = %x, want %x", gotWelcome, welcomePayload)
	}
}

func TestRelaySpaceOpenMLSArtifactInboxRejectsInvalidInputs(t *testing.T) {
	c := client.New("http://127.0.0.1:1")

	_, err := RelaySpaceOpenMLSArtifactInbox(c, "", "device-1", ArtifactKindKeyPackage)
	if err == nil {
		t.Fatal("expected missing relay_space_id error")
	}
	if !strings.Contains(err.Error(), "relay_space_id is required") {
		t.Fatalf("expected relay_space_id error, got %v", err)
	}

	_, err = RelaySpaceOpenMLSArtifactInbox(c, "relay-space-1", "", ArtifactKindKeyPackage)
	if err == nil {
		t.Fatal("expected missing device_id error")
	}
	if !strings.Contains(err.Error(), "device_id is required") {
		t.Fatalf("expected device_id error, got %v", err)
	}

	_, err = RelaySpaceOpenMLSArtifactInbox(c, "relay-space-1", "device-1", "signer.json")
	if err == nil {
		t.Fatal("expected unsupported artifact kind error")
	}
	if !strings.Contains(err.Error(), ErrUnsupportedArtifactKind.Error()) {
		t.Fatalf("expected unsupported artifact kind error, got %v", err)
	}
}

func TestRelaySpaceSpecificWritersRejectWrongContentType(t *testing.T) {
	payload := []byte("wrong content type")
	payloadSHA256, payloadSizeBytes := payloadMetadataForTest(payload)

	keyPackageErr := WriteRelaySpaceKeyPackageFromEnvelope(filepath.Join(t.TempDir(), "artifact.bin"), client.RelaySpaceEnvelopeRecord{
		EnvelopeID:       "envelope-1",
		RelaySpaceID:     "relay-space-1",
		ContentType:      ContentTypeOpenMLSWelcome,
		ProtocolVersion:  ProtocolVersionOpenMLSSidecar,
		CiphertextB64:    EncodePayloadBase64(payload),
		PayloadSHA256:    payloadSHA256,
		PayloadSizeBytes: payloadSizeBytes,
	})
	if keyPackageErr == nil {
		t.Fatal("expected KeyPackage writer wrong content type error")
	}
	if !strings.Contains(keyPackageErr.Error(), "unsupported KeyPackage content_type") {
		t.Fatalf("expected KeyPackage content_type error, got %v", keyPackageErr)
	}

	welcomeErr := WriteRelaySpaceWelcomeFromEnvelope(filepath.Join(t.TempDir(), "artifact.bin"), client.RelaySpaceEnvelopeRecord{
		EnvelopeID:       "envelope-1",
		RelaySpaceID:     "relay-space-1",
		ContentType:      ContentTypeOpenMLSKeyPackage,
		ProtocolVersion:  ProtocolVersionOpenMLSSidecar,
		CiphertextB64:    EncodePayloadBase64(payload),
		PayloadSHA256:    payloadSHA256,
		PayloadSizeBytes: payloadSizeBytes,
	})
	if welcomeErr == nil {
		t.Fatal("expected Welcome writer wrong content type error")
	}
	if !strings.Contains(welcomeErr.Error(), "unsupported Welcome content_type") {
		t.Fatalf("expected Welcome content_type error, got %v", welcomeErr)
	}
}
