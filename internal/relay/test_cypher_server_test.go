package relay

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type testCypherEnvelope struct {
	EnvelopeID        string `json:"envelope_id"`
	SenderDeviceID    string `json:"sender_device_id"`
	RecipientDeviceID string `json:"recipient_device_id"`
	ContentType       string `json:"content_type"`
	ProtocolVersion   string `json:"protocol_version"`
	CiphertextB64     string `json:"ciphertext_b64"`
	PayloadSHA256     string `json:"payload_sha256"`
	PayloadSizeBytes  int64  `json:"payload_size_bytes"`
	ClientCreatedAt   string `json:"client_created_at"`
	ServerReceivedAt  string `json:"server_received_at"`
	DeliveryState     string `json:"delivery_state"`
	AcknowledgedAt    string `json:"acknowledged_at,omitempty"`
}

type testCypherServer struct {
	server    *httptest.Server
	mu        sync.Mutex
	envelopes []testCypherEnvelope
}

func newTestCypherServer(t *testing.T) *testCypherServer {
	t.Helper()

	tc := &testCypherServer{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v0/envelopes", tc.handleSubmitEnvelope)
	mux.HandleFunc("/v0/envelopes/", tc.handleEnvelopeRoutes)
	mux.HandleFunc("/v0/devices/", tc.handleDeviceRoutes)

	tc.server = httptest.NewServer(mux)
	t.Cleanup(tc.server.Close)

	return tc
}

func (tc *testCypherServer) URL() string {
	return strings.TrimRight(tc.server.URL, "/")
}

func (tc *testCypherServer) handleSubmitEnvelope(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	var req struct {
		SenderDeviceID    string `json:"sender_device_id"`
		RecipientDeviceID string `json:"recipient_device_id"`
		ContentType       string `json:"content_type"`
		ProtocolVersion   string `json:"protocol_version"`
		CiphertextB64     string `json:"ciphertext_b64"`
		ClientCreatedAt   string `json:"client_created_at"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeTestError(w, http.StatusBadRequest, "invalid_json", "invalid JSON")
		return
	}

	if req.ContentType != ContentTypeOpenMLSApplicationMessage {
		writeTestError(w, http.StatusBadRequest, "unsupported_content_type", "unsupported content_type")
		return
	}

	if req.ProtocolVersion != ProtocolVersionOpenMLSSidecar {
		writeTestError(w, http.StatusBadRequest, "unsupported_protocol_version", "unsupported protocol_version")
		return
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(req.CiphertextB64)
	if err != nil {
		writeTestError(w, http.StatusBadRequest, "invalid_ciphertext", "ciphertext_b64 must be valid base64")
		return
	}
	payloadHash := sha256.Sum256(decodedPayload)
	payloadSHA256 := hex.EncodeToString(payloadHash[:])
	payloadSizeBytes := int64(len(decodedPayload))

	env := testCypherEnvelope{
		EnvelopeID:        "test-envelope-0001",
		SenderDeviceID:    req.SenderDeviceID,
		RecipientDeviceID: req.RecipientDeviceID,
		ContentType:       req.ContentType,
		ProtocolVersion:   req.ProtocolVersion,
		CiphertextB64:     req.CiphertextB64,
		PayloadSHA256:     payloadSHA256,
		PayloadSizeBytes:  payloadSizeBytes,
		ClientCreatedAt:   req.ClientCreatedAt,
		ServerReceivedAt:  "2026-05-27T00:00:00Z",
		DeliveryState:     "queued",
	}

	tc.mu.Lock()
	tc.envelopes = append(tc.envelopes, env)
	tc.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"envelope_id":        env.EnvelopeID,
		"server_received_at": env.ServerReceivedAt,
		"delivery_state":     env.DeliveryState,
		"payload_sha256":     env.PayloadSHA256,
		"payload_size_bytes": env.PayloadSizeBytes,
	})
}

func (tc *testCypherServer) handleEnvelopeRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	const prefix = "/v0/envelopes/"
	const suffix = "/ack"

	if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, suffix) {
		http.NotFound(w, r)
		return
	}

	envelopeID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), suffix)

	var req struct {
		RecipientDeviceID string `json:"recipient_device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeTestError(w, http.StatusBadRequest, "invalid_json", "invalid JSON")
		return
	}
	req.RecipientDeviceID = strings.TrimSpace(req.RecipientDeviceID)
	if req.RecipientDeviceID == "" {
		writeTestError(w, http.StatusBadRequest, "invalid_request", "recipient_device_id is required")
		return
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	for i := range tc.envelopes {
		env := &tc.envelopes[i]
		if env.EnvelopeID != envelopeID {
			continue
		}
		if env.RecipientDeviceID != req.RecipientDeviceID {
			writeTestError(w, http.StatusForbidden, "recipient_mismatch", "recipient_device_id does not match envelope recipient")
			return
		}
		if env.AcknowledgedAt == "" {
			env.AcknowledgedAt = "2026-05-27T00:10:00Z"
		}
		env.DeliveryState = "acknowledged"

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"envelope_id":     env.EnvelopeID,
			"delivery_state":  env.DeliveryState,
			"acknowledged_at": env.AcknowledgedAt,
		})
		return
	}

	writeTestError(w, http.StatusNotFound, "envelope_not_found", "envelope not found")
}

func (tc *testCypherServer) handleDeviceRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	prefix := "/v0/devices/"
	suffix := "/envelopes"

	if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, suffix) {
		http.NotFound(w, r)
		return
	}

	deviceID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), suffix)

	tc.mu.Lock()
	defer tc.mu.Unlock()

	var pending []testCypherEnvelope
	for _, env := range tc.envelopes {
		if env.RecipientDeviceID == deviceID && env.DeliveryState == "queued" {
			pending = append(pending, env)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_id": deviceID,
		"envelopes": pending,
	})
}

func writeTestError(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
