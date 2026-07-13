package app

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func TestRelaySpaceInviteClaimDevUsesExplicitStateAndDoesNotMutateIt(
	t *testing.T,
) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost ||
				r.URL.Path != "/v0/relay-spaces/invites/claim" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}

			var input client.ClaimRelaySpaceInviteInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Fatalf("decode request: %v", err)
			}

			if input.InviteToken != "full-secret-token" ||
				input.AccountID != "account-2" ||
				input.DeviceID != "device-2" ||
				input.DisplayLabel != "Bob device" {
				t.Fatalf("unexpected request: %+v", input)
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(
				client.ClaimRelaySpaceInviteResponse{
					RelaySpace: client.RelaySpaceResponse{
						RelaySpaceID: "relay-space-1",
					},
					RoutingMember: client.RelaySpaceMemberResponse{
						RoutingMemberID: "routing-member-2",
						RelaySpaceID:    "relay-space-1",
						AccountID:       "account-2",
						DeviceID:        "device-2",
						State:           "active",
					},
					RelaySpaceInvite: client.RelaySpaceInviteResponse{
						RelaySpaceInviteID: "relay-invite-1",
						RelaySpaceID:       "relay-space-1",
						ClaimCount:         1,
						State:              "claimed",
					},
					ClaimClassification: "created",
					Idempotent:          false,
					ClaimConsumed:       true,
				},
			)
		}),
	)
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(
		statePath,
		state.State{
			ServerURL:   server.URL,
			AccountID:   "account-2",
			DeviceID:    "device-2",
			DeviceLabel: "Bob device",
		},
	); err != nil {
		t.Fatalf("save state: %v", err)
	}

	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state before: %v", err)
	}

	output, commandErr := captureRelaySpaceInviteClaimStdout(func() error {
		return cmdRelaySpaceInviteClaimDev(
			[]string{
				"--state",
				statePath,
				"--invite-token",
				"full-secret-token",
			},
		)
	})
	if commandErr != nil {
		t.Fatalf("claim command: %v", commandErr)
	}

	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("claim command mutated local state")
	}

	for _, expected := range []string{
		"command: relay-space-invite-claim-dev",
		"claim_classification: created",
		"idempotent: false",
		"claim_consumed: true",
		"relay_space_id: relay-space-1",
		"routing_member_id: routing-member-2",
		"invite_state: claimed",
		"invite_claim_count: 1",
		"local_state_mutated: false",
		"routing and coordination authority only",
		"not identity verification",
		"not OpenMLS group membership",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output missing %q:\n%s", expected, output)
		}
	}
}

func TestRelaySpaceInviteClaimDevRequiresExplicitState(t *testing.T) {
	err := cmdRelaySpaceInviteClaimDev(
		[]string{
			"--invite-token",
			"full-secret-token",
		},
	)
	if err == nil ||
		!strings.Contains(err.Error(), "--state and --invite-token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func captureRelaySpaceInviteClaimStdout(
	fn func() error,
) (string, error) {
	old := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		return "", err
	}

	os.Stdout = writer
	commandErr := fn()
	_ = writer.Close()
	os.Stdout = old

	output, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if readErr != nil {
		return "", readErr
	}

	return string(output), commandErr
}
