package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpdateRelaySpaceMemberStateClientRequestAndResponse(t *testing.T) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			if r.URL.EscapedPath() !=
				"/v0/relay-spaces/space%20one/members/member%20two/state" {
				t.Fatalf("escaped path = %q", r.URL.EscapedPath())
			}

			var input UpdateRelaySpaceMemberStateInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if input.TargetState != "disabled" {
				t.Fatalf(
					"target_state = %q, want disabled",
					input.TargetState,
				)
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(
				RelaySpaceMemberStateResponse{
					RoutingMember: RelaySpaceMemberResponse{
						RoutingMemberID: "member-2",
						RelaySpaceID:    "space-1",
						AccountID:       "account-2",
						DeviceID:        "device-2",
						State:           "disabled",
						DisabledAt:      "2026-07-13T02:00:00Z",
					},
					PreviousState:            "active",
					CurrentState:             "disabled",
					TransitionClassification: "transitioned",
					Idempotent:               false,
					TransitionedAt:           "2026-07-13T02:00:00Z",
				},
			); err != nil {
				t.Fatalf("encode response: %v", err)
			}
		}),
	)
	defer server.Close()

	c := New(server.URL)
	resp, err := c.UpdateRelaySpaceMemberState(
		"space one",
		"member two",
		UpdateRelaySpaceMemberStateInput{
			TargetState: "disabled",
		},
	)
	if err != nil {
		t.Fatalf("update member state: %v", err)
	}

	if resp.TransitionClassification != "transitioned" ||
		resp.Idempotent ||
		resp.PreviousState != "active" ||
		resp.CurrentState != "disabled" ||
		resp.RoutingMember.RoutingMemberID != "member-2" ||
		resp.RoutingMember.DisabledAt == "" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}
