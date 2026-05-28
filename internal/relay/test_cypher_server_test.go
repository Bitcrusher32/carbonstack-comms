package relay

import (
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
	ClientCreatedAt   string `json:"client_created_at"`
	ServerReceivedAt  string `json:"server_received_at"`
	DeliveryState     string `json:"delivery_state"`
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

	env := testCypherEnvelope{
		EnvelopeID:        "test-envelope-0001",
		SenderDeviceID:    req.SenderDeviceID,
		RecipientDeviceID: req.RecipientDeviceID,
		ContentType:       req.ContentType,
		ProtocolVersion:   req.ProtocolVersion,
		CiphertextB64:     req.CiphertextB64,
		ClientCreatedAt:   req.ClientCreatedAt,
		ServerReceivedAt:  "2026-05-27T00:00:00Z",
		DeliveryState:     "queued",
	}

	tc.mu.Lock()
	tc.envelopes = append(tc.envelopes, env)
	tc.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"envelope_id":        env.EnvelopeID,
		"server_received_at": env.ServerReceivedAt,
		"delivery_state":     env.DeliveryState,
	})
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
