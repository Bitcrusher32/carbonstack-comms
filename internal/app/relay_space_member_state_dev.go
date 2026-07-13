package app

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func cmdRelaySpaceMemberStateDev(args []string) error {
	fs := flag.NewFlagSet(
		"relay-space-member-state-dev",
		flag.ContinueOnError,
	)
	statePath := fs.String(
		"state",
		"",
		"explicit local Comms state path controlling server context",
	)
	serverURL := fs.String(
		"server",
		"",
		"CarbonStackCypher server URL override",
	)
	relaySpaceID := fs.String(
		"relay-space-id",
		"",
		"authoritative Relay Space ID",
	)
	routingMemberID := fs.String(
		"routing-member-id",
		"",
		"routing member ID to transition",
	)
	targetState := fs.String(
		"target-state",
		"",
		"target routing-member state: active, disabled, or left",
	)

	if err := fs.Parse(args); err != nil {
		return err
	}

	*statePath = strings.TrimSpace(*statePath)
	*serverURL = strings.TrimSpace(*serverURL)
	*relaySpaceID = strings.TrimSpace(*relaySpaceID)
	*routingMemberID = strings.TrimSpace(*routingMemberID)
	*targetState = strings.TrimSpace(*targetState)

	if *statePath == "" ||
		*relaySpaceID == "" ||
		*routingMemberID == "" ||
		*targetState == "" {
		return errors.New(
			"--state, --relay-space-id, --routing-member-id, " +
				"and --target-state are required",
		)
	}

	switch *targetState {
	case "active", "disabled", "left":
	default:
		return errors.New(
			"--target-state must be active, disabled, or left",
		)
	}

	if _, err := state.Require(*statePath); err != nil {
		return err
	}

	server := state.ServerFromStateOrFlag(*statePath, *serverURL)
	c := client.New(server)

	resp, err := c.UpdateRelaySpaceMemberState(
		*relaySpaceID,
		*routingMemberID,
		client.UpdateRelaySpaceMemberStateInput{
			TargetState: *targetState,
		},
	)
	if err != nil {
		return err
	}

	fmt.Println("relay space member state transition")
	fmt.Println("command: relay-space-member-state-dev")
	fmt.Printf(
		"transition_classification: %s\n",
		resp.TransitionClassification,
	)
	fmt.Printf("idempotent: %t\n", resp.Idempotent)
	fmt.Printf("previous_state: %s\n", resp.PreviousState)
	fmt.Printf("current_state: %s\n", resp.CurrentState)
	if resp.TransitionedAt != "" {
		fmt.Printf("transitioned_at: %s\n", resp.TransitionedAt)
	}
	fmt.Printf(
		"relay_space_id: %s\n",
		resp.RoutingMember.RelaySpaceID,
	)
	fmt.Printf(
		"routing_member_id: %s\n",
		resp.RoutingMember.RoutingMemberID,
	)
	fmt.Printf("account_id: %s\n", resp.RoutingMember.AccountID)
	fmt.Printf("device_id: %s\n", resp.RoutingMember.DeviceID)
	fmt.Printf("disabled_at: %s\n", resp.RoutingMember.DisabledAt)
	fmt.Println("local_state_mutated: false")
	fmt.Println(
		"warning: dev/operator routing-state mutation only; not " +
			"authenticated administration, not production authorization, " +
			"not identity verification, not trust promotion, not OpenMLS " +
			"group membership, and not an explicit rejoin workflow",
	)

	return nil
}
