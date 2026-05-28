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
