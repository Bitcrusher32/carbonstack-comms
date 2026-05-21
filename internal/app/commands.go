package app

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/client"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/crypto"
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/state"
)

func Run(args []string) error {
	if len(args) < 1 {
		usage()
		return errors.New("no command provided")
	}

	switch args[0] {
	case "init":
		return cmdInit(args[1:])
	case "dev-create-invite":
		return cmdDevCreateInvite(args[1:])
	case "claim-invite":
		return cmdClaimInvite(args[1:])
	case "register-device":
		return cmdRegisterDevice(args[1:])
	case "list-devices":
		return cmdListDevices(args[1:])
	case "send":
		return cmdSend(args[1:])
	case "inbox":
		return cmdInbox(args[1:])
	case "ack":
		return cmdAck(args[1:])
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func usage() {
	fmt.Println("CarbonStackComms Phase 1 CLI")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  init")
	fmt.Println("  dev-create-invite")
	fmt.Println("  claim-invite")
	fmt.Println("  register-device")
	fmt.Println("  list-devices")
	fmt.Println("  send")
	fmt.Println("  inbox")
	fmt.Println("  ack")
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	serverURL := fs.String("server", state.DefaultServerURL, "CarbonStackCypher server URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s := state.State{
		ServerURL:       strings.TrimRight(*serverURL, "/"),
		ProtocolVersion: crypto.ProtocolVersionStub,
	}

	if err := state.Save(*statePath, s); err != nil {
		return err
	}

	fmt.Printf("initialized state: %s\n", *statePath)
	fmt.Printf("server: %s\n", s.ServerURL)
	return nil
}

func cmdDevCreateInvite(args []string) error {
	fs := flag.NewFlagSet("dev-create-invite", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	serverURL := fs.String("server", "", "CarbonStackCypher server URL override")
	inviteCode := fs.String("invite", "", "invite code to create")
	if err := fs.Parse(args); err != nil {
		return err
	}

	server := state.ServerFromStateOrFlag(*statePath, *serverURL)
	c := client.New(server)

	resp, err := c.CreateDevInvite(*inviteCode)
	if err != nil {
		return err
	}

	fmt.Println("dev invite created")
	fmt.Printf("invite_id: %s\n", resp.InviteID)
	fmt.Printf("invite_code: %s\n", resp.InviteCode)
	fmt.Printf("created_at: %s\n", resp.CreatedAt)
	return nil
}

func cmdClaimInvite(args []string) error {
	fs := flag.NewFlagSet("claim-invite", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	serverURL := fs.String("server", "", "CarbonStackCypher server URL override")
	inviteCode := fs.String("invite", "", "invite code")
	displayName := fs.String("name", "", "display name")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *inviteCode == "" || *displayName == "" {
		return errors.New("--invite and --name are required")
	}

	s, _ := state.Load(*statePath)
	server := state.ServerFromStateOrFlag(*statePath, *serverURL)
	c := client.New(server)

	resp, err := c.ClaimInvite(*inviteCode, *displayName)
	if err != nil {
		return err
	}

	s.ServerURL = server
	s.AccountID = resp.AccountID
	s.DisplayName = *displayName
	s.ProtocolVersion = crypto.ProtocolVersionStub

	if err := state.Save(*statePath, s); err != nil {
		return err
	}

	fmt.Println("invite claimed")
	fmt.Printf("account_id: %s\n", resp.AccountID)
	fmt.Printf("created_at: %s\n", resp.CreatedAt)
	return nil
}

func cmdRegisterDevice(args []string) error {
	fs := flag.NewFlagSet("register-device", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	label := fs.String("label", "", "device label")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *label == "" {
		return errors.New("--label is required")
	}

	s, err := state.Require(*statePath)
	if err != nil {
		return err
	}
	if s.AccountID == "" {
		return errors.New("state has no account_id; run claim-invite first")
	}

	publicIdentityKey := "stub-public-identity-key-" + sanitizeLabel(*label)
	publicPrekeyBundle := "stub-prekey-bundle-" + sanitizeLabel(*label)

	c := client.New(s.ServerURL)
	resp, err := c.RegisterDevice(s.AccountID, *label, publicIdentityKey, publicPrekeyBundle)
	if err != nil {
		return err
	}

	s.DeviceID = resp.DeviceID
	s.DeviceLabel = *label
	s.PublicIdentityKey = publicIdentityKey
	s.PublicPrekeyBundle = publicPrekeyBundle
	s.ProtocolVersion = crypto.ProtocolVersionStub

	if err := state.Save(*statePath, s); err != nil {
		return err
	}

	fmt.Println("device registered")
	fmt.Printf("device_id: %s\n", resp.DeviceID)
	fmt.Printf("account_id: %s\n", resp.AccountID)
	fmt.Printf("created_at: %s\n", resp.CreatedAt)
	return nil
}

func cmdListDevices(args []string) error {
	fs := flag.NewFlagSet("list-devices", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	accountID := fs.String("account", "", "account ID to list")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := state.Require(*statePath)
	if err != nil {
		return err
	}

	targetAccountID := *accountID
	if targetAccountID == "" {
		targetAccountID = s.AccountID
	}
	if targetAccountID == "" {
		return errors.New("no account specified and state has no account_id")
	}

	c := client.New(s.ServerURL)
	resp, err := c.ListDevices(targetAccountID)
	if err != nil {
		return err
	}

	fmt.Printf("account_id: %s\n", resp.AccountID)
	for _, d := range resp.Devices {
		fmt.Println()
		fmt.Printf("device_id: %s\n", d.DeviceID)
		fmt.Printf("label: %s\n", d.DeviceLabel)
		fmt.Printf("public_identity_key: %s\n", d.PublicIdentityKey)
		fmt.Printf("created_at: %s\n", d.CreatedAt)
	}
	return nil
}

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	toDevice := fs.String("to-device", "", "recipient device ID")
	message := fs.String("message", "", "message text")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *toDevice == "" || *message == "" {
		return errors.New("--to-device and --message are required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	provider := crypto.MockCryptoProvider{}
	ciphertextB64 := provider.Encrypt(*message)

	c := client.New(s.ServerURL)
	resp, err := c.SubmitEnvelope(
		s.DeviceID,
		*toDevice,
		crypto.ContentTypeTextStub,
		crypto.ProtocolVersionStub,
		ciphertextB64,
		time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return err
	}

	fmt.Println("envelope sent")
	fmt.Printf("envelope_id: %s\n", resp.EnvelopeID)
	fmt.Printf("delivery_state: %s\n", resp.DeliveryState)
	fmt.Printf("server_received_at: %s\n", resp.ServerReceivedAt)
	return nil
}

func cmdInbox(args []string) error {
	fs := flag.NewFlagSet("inbox", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	c := client.New(s.ServerURL)
	resp, err := c.Inbox(s.DeviceID)
	if err != nil {
		return err
	}

	provider := crypto.MockCryptoProvider{}

	fmt.Printf("device_id: %s\n", resp.DeviceID)
	fmt.Printf("queued_envelopes: %d\n", len(resp.Envelopes))

	for _, e := range resp.Envelopes {
		fmt.Println()
		fmt.Printf("envelope_id: %s\n", e.EnvelopeID)
		fmt.Printf("from_device: %s\n", e.SenderDeviceID)
		fmt.Printf("state: %s\n", e.DeliveryState)
		fmt.Printf("server_received_at: %s\n", e.ServerReceivedAt)
		fmt.Printf("stub_plaintext: %s\n", provider.Decrypt(e.CiphertextB64))
	}

	return nil
}

func cmdAck(args []string) error {
	fs := flag.NewFlagSet("ack", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	envelopeID := fs.String("envelope", "", "envelope ID to acknowledge")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *envelopeID == "" {
		return errors.New("--envelope is required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	c := client.New(s.ServerURL)
	resp, err := c.AckEnvelope(*envelopeID, s.DeviceID)
	if err != nil {
		return err
	}

	fmt.Println("envelope acknowledged")
	fmt.Printf("envelope_id: %s\n", resp.EnvelopeID)
	fmt.Printf("delivery_state: %s\n", resp.DeliveryState)
	fmt.Printf("acknowledged_at: %s\n", resp.AcknowledgedAt)
	return nil
}

func sanitizeLabel(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, " ", "-")
	if value == "" {
		return "device"
	}
	return value
}
