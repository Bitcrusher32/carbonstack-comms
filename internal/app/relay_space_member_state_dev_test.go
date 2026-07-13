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

func TestRelaySpaceMemberStateDevUsesExplicitStateAndDoesNotMutateIt(
	t *testing.T,
) {
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost ||
				r.URL.Path !=
					"/v0/relay-spaces/space-1/members/member-2/state" {
				t.Fatalf(
					"unexpected request: %s %s",
					r.Method,
					r.URL.Path,
				)
			}

			var input client.UpdateRelaySpaceMemberStateInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if input.TargetState != "disabled" {
				t.Fatalf("unexpected request: %+v", input)
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(
				client.RelaySpaceMemberStateResponse{
					RoutingMember: client.RelaySpaceMemberResponse{
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
			)
		}),
	)
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "operator-state.json")
	if err := state.Save(
		statePath,
		state.State{
			ServerURL:   server.URL,
			AccountID:   "operator-account",
			DeviceID:    "operator-device",
			DeviceLabel: "operator device",
		},
	); err != nil {
		t.Fatalf("save state: %v", err)
	}

	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state before: %v", err)
	}

	output, commandErr := captureRelaySpaceMemberStateStdout(
		func() error {
			return cmdRelaySpaceMemberStateDev(
				[]string{
					"--state",
					statePath,
					"--relay-space-id",
					"space-1",
					"--routing-member-id",
					"member-2",
					"--target-state",
					"disabled",
				},
			)
		},
	)
	if commandErr != nil {
		t.Fatalf("member-state command: %v", commandErr)
	}

	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("member-state command mutated local state")
	}

	for _, expected := range []string{
		"command: relay-space-member-state-dev",
		"transition_classification: transitioned",
		"idempotent: false",
		"previous_state: active",
		"current_state: disabled",
		"relay_space_id: space-1",
		"routing_member_id: member-2",
		"account_id: account-2",
		"device_id: device-2",
		"disabled_at: 2026-07-13T02:00:00Z",
		"local_state_mutated: false",
		"not authenticated administration",
		"not production authorization",
		"not identity verification",
		"not trust promotion",
		"not OpenMLS group membership",
		"not an explicit rejoin workflow",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output missing %q:\n%s", expected, output)
		}
	}
}

func TestRelaySpaceMemberStateDevRejectsMissingAndUnsupportedInputs(
	t *testing.T,
) {
	err := cmdRelaySpaceMemberStateDev(
		[]string{
			"--relay-space-id",
			"space-1",
			"--routing-member-id",
			"member-2",
			"--target-state",
			"disabled",
		},
	)
	if err == nil || !strings.Contains(err.Error(), "--state") {
		t.Fatalf("unexpected missing-state error: %v", err)
	}

	err = cmdRelaySpaceMemberStateDev(
		[]string{
			"--state",
			"unused",
			"--relay-space-id",
			"space-1",
			"--routing-member-id",
			"member-2",
			"--target-state",
			"removed",
		},
	)
	if err == nil ||
		!strings.Contains(err.Error(), "active, disabled, or left") {
		t.Fatalf("unexpected target-state error: %v", err)
	}
}

func captureRelaySpaceMemberStateStdout(
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
