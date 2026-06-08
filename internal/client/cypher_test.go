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

func TestCypherClientRelaySpaceMethods(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/v0/relay-spaces", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var req map[string]string
			decodeRequest(t, r, &req)

			if req["relay_space_id"] != "relay-space-1" {
				t.Fatalf("relay_space_id = %q, want relay-space-1", req["relay_space_id"])
			}
			if req["display_label"] != "test relay space" {
				t.Fatalf("display_label = %q, want test relay space", req["display_label"])
			}

			writeJSON(t, w, http.StatusCreated, RelaySpaceResponse{
				RelaySpaceID:       "relay-space-1",
				DisplayLabel:       "test relay space",
				CreatedByAccountID: "account-1",
				CreatedByDeviceID:  "device-1",
				CreatedAt:          "2026-06-08T00:00:00Z",
			})
		case http.MethodGet:
			writeJSON(t, w, http.StatusOK, ListRelaySpacesResponse{
				RelaySpaces: []RelaySpaceResponse{
					{
						RelaySpaceID: "relay-space-1",
						DisplayLabel: "test relay space",
						CreatedAt:    "2026-06-08T00:00:00Z",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/v0/relay-spaces/relay-space-1", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodGet)

		writeJSON(t, w, http.StatusOK, RelaySpaceResponse{
			RelaySpaceID: "relay-space-1",
			DisplayLabel: "test relay space",
			CreatedAt:    "2026-06-08T00:00:00Z",
		})
	})

	mux.HandleFunc("/v0/relay-spaces/relay-space-1/invites", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodPost)

		var req CreateRelaySpaceInviteInput
		decodeRequest(t, r, &req)

		if req.InviteToken != "secret relay space invite token" {
			t.Fatalf("invite_token = %q", req.InviteToken)
		}
		if req.DisplayCode != "8F3A-C91B-2D44" {
			t.Fatalf("display_code = %q", req.DisplayCode)
		}

		maxClaims := 1
		writeJSON(t, w, http.StatusCreated, CreateRelaySpaceInviteResponse{
			InviteToken: "secret relay space invite token",
			RelaySpaceInvite: RelaySpaceInviteResponse{
				RelaySpaceInviteID: "relay-space-invite-1",
				RelaySpaceID:       "relay-space-1",
				InviteTokenHash:    "hash-secret-relay-space-invite-token",
				DisplayCode:        "8F3A-C91B-2D44",
				WordCode:           "banana-wall-red-applesauce",
				CreatedByMemberID:  "routing-member-1",
				CreatedAt:          "2026-06-08T00:00:00Z",
				MaxClaims:          &maxClaims,
				ClaimCount:         0,
				State:              "active",
				Note:               "routing-only invite",
			},
		})
	})

	mux.HandleFunc("/v0/relay-spaces/relay-space-1/members", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var req RegisterRelaySpaceMemberInput
			decodeRequest(t, r, &req)

			if req.AccountID != "account-1" {
				t.Fatalf("account_id = %q, want account-1", req.AccountID)
			}
			if req.DeviceID != "device-1" {
				t.Fatalf("device_id = %q, want device-1", req.DeviceID)
			}

			writeJSON(t, w, http.StatusCreated, RelaySpaceMemberResponse{
				RoutingMemberID: "routing-member-1",
				RelaySpaceID:    "relay-space-1",
				AccountID:       "account-1",
				DeviceID:        "device-1",
				DisplayLabel:    "alice routing member",
				State:           "active",
				JoinedAt:        "2026-06-08T00:00:00Z",
			})
		case http.MethodGet:
			writeJSON(t, w, http.StatusOK, ListRelaySpaceMembersResponse{
				RelaySpaceID: "relay-space-1",
				Members: []RelaySpaceMemberResponse{
					{
						RoutingMemberID: "routing-member-1",
						RelaySpaceID:    "relay-space-1",
						AccountID:       "account-1",
						DeviceID:        "device-1",
						State:           "active",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/v0/relay-spaces/relay-space-1/envelopes", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodPost)

		var req map[string]string
		decodeRequest(t, r, &req)

		if req["sender_device_id"] != "device-1" {
			t.Fatalf("sender_device_id = %q, want device-1", req["sender_device_id"])
		}
		if req["recipient_device_id"] != "device-2" {
			t.Fatalf("recipient_device_id = %q, want device-2", req["recipient_device_id"])
		}

		writeJSON(t, w, http.StatusCreated, SubmitRelaySpaceEnvelopeResponse{
			EnvelopeID:       "envelope-1",
			RelaySpaceID:     "relay-space-1",
			DeliveryState:    "queued",
			ServerReceivedAt: "2026-06-08T00:00:00Z",
			PayloadSHA256:    strings.Repeat("a", 64),
			PayloadSizeBytes: 5,
		})
	})

	mux.HandleFunc("/v0/relay-spaces/relay-space-1/devices/device-2/envelopes", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodGet)

		writeJSON(t, w, http.StatusOK, RelaySpaceInboxResponse{
			RelaySpaceID: "relay-space-1",
			DeviceID:     "device-2",
			Envelopes: []RelaySpaceEnvelopeRecord{
				{
					EnvelopeID:        "envelope-1",
					RelaySpaceID:      "relay-space-1",
					SenderDeviceID:    "device-1",
					RecipientDeviceID: "device-2",
					ContentType:       "carbonstack.message.text.stub.v0",
					ProtocolVersion:   "stub-v0",
					CiphertextB64:     "aGVsbG8=",
					PayloadSHA256:     strings.Repeat("a", 64),
					PayloadSizeBytes:  5,
					ServerReceivedAt:  "2026-06-08T00:00:00Z",
					DeliveryState:     "queued",
				},
			},
		})
	})

	mux.HandleFunc("/v0/relay-spaces/relay-space-1/envelopes/envelope-1/ack", func(w http.ResponseWriter, r *http.Request) {
		requireMethod(t, r, http.MethodPost)

		var req map[string]string
		decodeRequest(t, r, &req)

		if req["recipient_device_id"] != "device-2" {
			t.Fatalf("recipient_device_id = %q, want device-2", req["recipient_device_id"])
		}

		writeJSON(t, w, http.StatusOK, AckRelaySpaceEnvelopeResponse{
			EnvelopeID:     "envelope-1",
			RelaySpaceID:   "relay-space-1",
			DeliveryState:  "acknowledged",
			AcknowledgedAt: "2026-06-08T00:01:00Z",
		})
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	c := New(server.URL + "/")

	space, err := c.CreateRelaySpace("relay-space-1", "test relay space", "account-1", "device-1")
	if err != nil {
		t.Fatalf("create relay space: %v", err)
	}
	if space.RelaySpaceID != "relay-space-1" {
		t.Fatalf("relay_space_id = %q", space.RelaySpaceID)
	}

	spaces, err := c.ListRelaySpaces()
	if err != nil {
		t.Fatalf("list relay spaces: %v", err)
	}
	if len(spaces.RelaySpaces) != 1 {
		t.Fatalf("len(relay_spaces) = %d, want 1", len(spaces.RelaySpaces))
	}

	gotSpace, err := c.GetRelaySpace("relay-space-1")
	if err != nil {
		t.Fatalf("get relay space: %v", err)
	}
	if gotSpace.DisplayLabel != "test relay space" {
		t.Fatalf("display_label = %q", gotSpace.DisplayLabel)
	}

	maxClaims := 1
	invite, err := c.CreateRelaySpaceInvite("relay-space-1", CreateRelaySpaceInviteInput{
		InviteToken:       "secret relay space invite token",
		DisplayCode:       "8F3A-C91B-2D44",
		WordCode:          "banana-wall-red-applesauce",
		CreatedByMemberID: "routing-member-1",
		MaxClaims:         &maxClaims,
		Note:              "routing-only invite",
	})
	if err != nil {
		t.Fatalf("create relay space invite: %v", err)
	}
	if invite.RelaySpaceInvite.RelaySpaceID != "relay-space-1" {
		t.Fatalf("invite relay_space_id = %q", invite.RelaySpaceInvite.RelaySpaceID)
	}
	if invite.InviteToken != "secret relay space invite token" {
		t.Fatalf("invite_token = %q", invite.InviteToken)
	}

	member, err := c.RegisterRelaySpaceMember("relay-space-1", RegisterRelaySpaceMemberInput{
		AccountID:    "account-1",
		DeviceID:     "device-1",
		DisplayLabel: "alice routing member",
	})
	if err != nil {
		t.Fatalf("register relay space member: %v", err)
	}
	if member.RoutingMemberID != "routing-member-1" {
		t.Fatalf("routing_member_id = %q", member.RoutingMemberID)
	}

	members, err := c.ListRelaySpaceMembers("relay-space-1")
	if err != nil {
		t.Fatalf("list relay space members: %v", err)
	}
	if len(members.Members) != 1 {
		t.Fatalf("len(members) = %d, want 1", len(members.Members))
	}

	envelope, err := c.SubmitRelaySpaceEnvelope("relay-space-1", "device-1", "device-2", "carbonstack.message.text.stub.v0", "stub-v0", "aGVsbG8=", "2026-06-08T00:00:00Z")
	if err != nil {
		t.Fatalf("submit relay space envelope: %v", err)
	}
	if envelope.RelaySpaceID != "relay-space-1" {
		t.Fatalf("envelope relay_space_id = %q", envelope.RelaySpaceID)
	}

	inbox, err := c.RelaySpaceInbox("relay-space-1", "device-2")
	if err != nil {
		t.Fatalf("relay space inbox: %v", err)
	}
	if len(inbox.Envelopes) != 1 {
		t.Fatalf("len(envelopes) = %d, want 1", len(inbox.Envelopes))
	}
	if inbox.Envelopes[0].RelaySpaceID != "relay-space-1" {
		t.Fatalf("inbox envelope relay_space_id = %q", inbox.Envelopes[0].RelaySpaceID)
	}

	ack, err := c.AckRelaySpaceEnvelope("relay-space-1", "envelope-1", "device-2")
	if err != nil {
		t.Fatalf("ack relay space envelope: %v", err)
	}
	if ack.RelaySpaceID != "relay-space-1" {
		t.Fatalf("ack relay_space_id = %q", ack.RelaySpaceID)
	}
	if ack.DeliveryState != "acknowledged" {
		t.Fatalf("ack delivery_state = %q", ack.DeliveryState)
	}

	payload, err := json.Marshal(space)
	if err != nil {
		t.Fatalf("marshal relay space response: %v", err)
	}
	lower := strings.ToLower(string(payload))
	if strings.Contains(lower, "trust") {
		t.Fatalf("relay space client response must not expose trust authority fields: %s", string(payload))
	}
	if strings.Contains(lower, "verified") {
		t.Fatalf("relay space client response must not expose verified authority fields: %s", string(payload))
	}
}
