package app

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func cmdRelaySpaceInviteClaimDev(args []string) error {
	fs := flag.NewFlagSet(
		"relay-space-invite-claim-dev",
		flag.ContinueOnError,
	)
	statePath := fs.String(
		"state",
		"",
		"explicit local Comms state file path",
	)
	serverURL := fs.String(
		"server",
		"",
		"CarbonStackCypher server URL override",
	)
	inviteToken := fs.String(
		"invite-token",
		"",
		"full Relay Space invite token",
	)
	displayLabel := fs.String(
		"display-label",
		"",
		"routing-member display label; defaults to local device label",
	)

	if err := fs.Parse(args); err != nil {
		return err
	}

	*statePath = strings.TrimSpace(*statePath)
	*inviteToken = strings.TrimSpace(*inviteToken)
	*displayLabel = strings.TrimSpace(*displayLabel)

	if *statePath == "" || *inviteToken == "" {
		return errors.New("--state and --invite-token are required")
	}

	s, err := state.Require(*statePath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(s.AccountID) == "" {
		return errors.New(
			"state has no account_id; complete account bootstrap first",
		)
	}
	if strings.TrimSpace(s.DeviceID) == "" {
		return errors.New(
			"state has no device_id; register a device first",
		)
	}

	if *displayLabel == "" {
		*displayLabel = strings.TrimSpace(s.DeviceLabel)
	}

	server := state.ServerFromStateOrFlag(*statePath, *serverURL)
	c := client.New(server)

	resp, err := c.ClaimRelaySpaceInvite(
		client.ClaimRelaySpaceInviteInput{
			InviteToken:  *inviteToken,
			AccountID:    s.AccountID,
			DeviceID:     s.DeviceID,
			DisplayLabel: *displayLabel,
		},
	)
	if err != nil {
		return err
	}

	fmt.Println("relay space invite claim")
	fmt.Println("command: relay-space-invite-claim-dev")
	fmt.Printf(
		"claim_classification: %s\n",
		resp.ClaimClassification,
	)
	fmt.Printf("idempotent: %t\n", resp.Idempotent)
	fmt.Printf("claim_consumed: %t\n", resp.ClaimConsumed)
	fmt.Printf(
		"relay_space_id: %s\n",
		resp.RelaySpace.RelaySpaceID,
	)
	fmt.Printf(
		"routing_member_id: %s\n",
		resp.RoutingMember.RoutingMemberID,
	)
	fmt.Printf("account_id: %s\n", resp.RoutingMember.AccountID)
	fmt.Printf("device_id: %s\n", resp.RoutingMember.DeviceID)
	fmt.Printf(
		"relay_space_invite_id: %s\n",
		resp.RelaySpaceInvite.RelaySpaceInviteID,
	)
	fmt.Printf(
		"invite_state: %s\n",
		resp.RelaySpaceInvite.State,
	)
	fmt.Printf(
		"invite_claim_count: %d\n",
		resp.RelaySpaceInvite.ClaimCount,
	)
	fmt.Println("local_state_mutated: false")
	fmt.Println(
		"warning: Relay Space membership is routing and coordination " +
			"authority only; not identity verification, not trust promotion, " +
			"and not OpenMLS group membership",
	)

	return nil
}
