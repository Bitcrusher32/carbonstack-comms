package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCypherClientLifecycleMethods(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/v0/dev/invites", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodPost)

		var req map[string]string
		decodeRequest(t, r, &req)

		if req["invite_code"] != "test-invite" {
			t.Fatalf("expected invite code test-invite, got %q", req["invite_code"])
		}

		writeJSON(t, w, http.StatusCreated, DevInviteResponse{
			InviteID:   "invite-1",
			InviteCode: "test-invite",
			CreatedAt:  "2026-05-21T00:00:00Z",
		})
	})

	mux.HandleFunc("/v0/invites/claim", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodPost)

		var req map[string]string
		decodeRequest(t, r, &req)

		if req["invite_code"] != "test-invite" {
			t.Fatalf("expected invite code test-invite, got %q", req["invite_code"])
		}
		if req["display_name"] != "alice" {
			t.Fatalf("expected display name alice, got %q", req["display_name"])
		}

		writeJSON(t, w, http.StatusCreated, ClaimInviteResponse{
			AccountID: "account-1",
			CreatedAt: "2026-05-21T00:00:00Z",
		})
	})

	mux.HandleFunc("/v0/devices/register", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodPost)

		var req map[string]string
		decodeRequest(t, r, &req)

		if req["account_id"] != "account-1" {
			t.Fatalf("expected account-1, got %q", req["account_id"])
		}

		writeJSON(t, w, http.StatusCreated, RegisterDeviceResponse{
			DeviceID:  "device-1",
			AccountID: "account-1",
			CreatedAt: "2026-05-21T00:00:00Z",
		})
	})

	mux.HandleFunc("/v0/accounts/account-1/devices", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodGet)

		writeJSON(t, w, http.StatusOK, ListDevicesResponse{
			AccountID: "account-1",
			Devices: []DeviceRecord{
				{
					DeviceID:           "device-1",
					DeviceLabel:        "alice-cli-1",
					PublicIdentityKey:  "stub-public-key",
					PublicPrekeyBundle: "stub-prekey",
					CreatedAt:          "2026-05-21T00:00:00Z",
				},
			},
		})
	})

	mux.HandleFunc("/v0/envelopes", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodPost)

		var req map[string]string
		decodeRequest(t, r, &req)

		if req["sender_device_id"] != "device-1" {
			t.Fatalf("expected sender device-1, got %q", req["sender_device_id"])
		}
		if req["recipient_device_id"] != "device-2" {
			t.Fatalf("expected recipient device-2, got %q", req["recipient_device_id"])
		}

		writeJSON(t, w, http.StatusCreated, SubmitEnvelopeResponse{
			EnvelopeID:       "envelope-1",
			DeliveryState:    "queued",
			ServerReceivedAt: "2026-05-21T00:00:00Z",
		})
	})

	mux.HandleFunc("/v0/devices/device-2/envelopes", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodGet)

		writeJSON(t, w, http.StatusOK, InboxResponse{
			DeviceID: "device-2",
			Envelopes: []EnvelopeRecord{
				{
					EnvelopeID:        "envelope-1",
					SenderDeviceID:    "device-1",
					RecipientDeviceID: "device-2",
					ContentType:       "carbonstack.message.text.stub.v0",
					ProtocolVersion:   "stub-v0",
					CiphertextB64:     "aGVsbG8=",
					ServerReceivedAt:  "2026-05-21T00:00:00Z",
					DeliveryState:     "queued",
				},
			},
		})
	})

	mux.HandleFunc("/v0/envelopes/envelope-1/ack", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodPost)

		var req map[string]string
		decodeRequest(t, r, &req)

		if req["recipient_device_id"] != "device-2" {
			t.Fatalf("expected recipient device-2, got %q", req["recipient_device_id"])
		}

		writeJSON(t, w, http.StatusOK, AckEnvelopeResponse{
			EnvelopeID:     "envelope-1",
			DeliveryState:  "acknowledged",
			AcknowledgedAt: "2026-05-21T00:00:00Z",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	c := New(server.URL)

	invite, err := c.CreateDevInvite("test-invite")
	if err != nil {
		t.Fatalf("create dev invite: %v", err)
	}
	if invite.InviteID != "invite-1" {
		t.Fatalf("unexpected invite id: %s", invite.InviteID)
	}

	account, err := c.ClaimInvite("test-invite", "alice")
	if err != nil {
		t.Fatalf("claim invite: %v", err)
	}
	if account.AccountID != "account-1" {
		t.Fatalf("unexpected account id: %s", account.AccountID)
	}

	device, err := c.RegisterDevice("account-1", "alice-cli-1", "stub-public-key", "stub-prekey")
	if err != nil {
		t.Fatalf("register device: %v", err)
	}
	if device.DeviceID != "device-1" {
		t.Fatalf("unexpected device id: %s", device.DeviceID)
	}

	devices, err := c.ListDevices("account-1")
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices.Devices))
	}

	envelope, err := c.SubmitEnvelope("device-1", "device-2", "carbonstack.message.text.stub.v0", "stub-v0", "aGVsbG8=", "2026-05-21T00:00:00Z")
	if err != nil {
		t.Fatalf("submit envelope: %v", err)
	}
	if envelope.EnvelopeID != "envelope-1" {
		t.Fatalf("unexpected envelope id: %s", envelope.EnvelopeID)
	}

	inbox, err := c.Inbox("device-2")
	if err != nil {
		t.Fatalf("inbox: %v", err)
	}
	if len(inbox.Envelopes) != 1 {
		t.Fatalf("expected 1 envelope, got %d", len(inbox.Envelopes))
	}

	ack, err := c.AckEnvelope("envelope-1", "device-2")
	if err != nil {
		t.Fatalf("ack envelope: %v", err)
	}
	if ack.DeliveryState != "acknowledged" {
		t.Fatalf("unexpected ack state: %s", ack.DeliveryState)
	}
}

func TestCypherClientErrorResponse(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/v0/dev/invites", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusConflict, map[string]any{
			"error": map[string]string{
				"code":    "invite_exists",
				"message": "invite code already exists",
			},
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	c := New(server.URL)

	_, err := c.CreateDevInvite("duplicate")
	if err == nil {
		t.Fatalf("expected error")
	}

	if !strings.Contains(err.Error(), "invite_exists") {
		t.Fatalf("expected invite_exists error, got %v", err)
	}
}

func requireMethod(t *testing.T, r *http.Request, method string) {
	t.Helper()

	if r.Method != method {
		t.Fatalf("expected method %s, got %s", method, r.Method)
	}
}

func decodeRequest(t *testing.T, r *http.Request, out any) {
	t.Helper()

	defer r.Body.Close()

	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		t.Fatalf("decode request: %v", err)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, payload any) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		t.Fatalf("write json: %v", err)
	}
}
