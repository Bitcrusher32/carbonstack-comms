package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClaimRelaySpaceInviteClientRequestAndResponse(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			if r.URL.Path != "/v0/relay-spaces/invites/claim" {
				t.Fatalf("path = %q", r.URL.Path)
			}

			var input ClaimRelaySpaceInviteInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Fatalf("decode request: %v", err)
			}

			if input.InviteToken != "full-secret-token" ||
				input.AccountID != "account-2" ||
				input.DeviceID != "device-2" ||
				input.DisplayLabel != "Bob routing member" {
				t.Fatalf("unexpected request: %+v", input)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			if err := json.NewEncoder(w).Encode(
				ClaimRelaySpaceInviteResponse{
					RelaySpace: RelaySpaceResponse{
						RelaySpaceID: "relay-space-1",
						DisplayLabel: "test space",
					},
					RoutingMember: RelaySpaceMemberResponse{
						RoutingMemberID: "routing-member-2",
						RelaySpaceID:    "relay-space-1",
						AccountID:       "account-2",
						DeviceID:        "device-2",
						DisplayLabel:    "Bob routing member",
						State:           "active",
					},
					RelaySpaceInvite: RelaySpaceInviteResponse{
						RelaySpaceInviteID: "relay-invite-1",
						RelaySpaceID:       "relay-space-1",
						ClaimCount:         1,
						State:              "claimed",
					},
					ClaimClassification: "created",
					Idempotent:          false,
					ClaimConsumed:       true,
				},
			); err != nil {
				t.Fatalf("encode response: %v", err)
			}
		}),
	)
	defer server.Close()

	c := New(server.URL)
	resp, err := c.ClaimRelaySpaceInvite(
		ClaimRelaySpaceInviteInput{
			InviteToken:  "full-secret-token",
			AccountID:    "account-2",
			DeviceID:     "device-2",
			DisplayLabel: "Bob routing member",
		},
	)
	if err != nil {
		t.Fatalf("claim relay space invite: %v", err)
	}

	if resp.ClaimClassification != "created" ||
		resp.Idempotent ||
		!resp.ClaimConsumed ||
		resp.RelaySpace.RelaySpaceID != "relay-space-1" ||
		resp.RoutingMember.RoutingMemberID != "routing-member-2" ||
		resp.RelaySpaceInvite.ClaimCount != 1 ||
		resp.RelaySpaceInvite.State != "claimed" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
