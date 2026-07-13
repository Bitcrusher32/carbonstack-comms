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
	"git.bitcrusher32.win/bitcrusher32/carbonstack-comms/internal/trust"
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
	case "fingerprint":
		return cmdFingerprint(args[1:])
	case "verify-device":
		return cmdVerifyDevice(args[1:])
	case "trust-history":
		return cmdTrustHistory(args[1:])
	case "trust-list":
		return cmdTrustList(args[1:])
	case "simulate-key-change":
		return cmdSimulateKeyChange(args[1:])
	case "revoke-device":
		return cmdRevokeDevice(args[1:])
	case "send":
		return cmdSend(args[1:])
	case "inbox":
		return cmdInbox(args[1:])
	case "ack":
		return cmdAck(args[1:])
	case "state-audit-dev":
		return cmdStateAuditDev(args[1:])
	case "message-send-dev":
		return cmdMessageSendDev(args[1:])
	case "openmls-send-dev":
		return cmdOpenMLSSendDev(args[1:])
	case "message-inbox-dev":
		return cmdMessageInboxDev(args[1:])
	case "openmls-inbox-dev":
		return cmdOpenMLSInboxDev(args[1:])
	case "openmls-identity-create-dev":
		return cmdOpenMLSIdentityCreateDev(args[1:])
	case "openmls-identity-status-dev":
		return cmdOpenMLSIdentityStatusDev(args[1:])
	case "openmls-bundle-export-dev":
		return cmdOpenMLSBundleExportDev(args[1:])
	case "openmls-conversation-create-dev":
		return cmdOpenMLSConversationCreateDev(args[1:])
	case "openmls-conversation-load-check-dev":
		return cmdOpenMLSConversationLoadCheckDev(args[1:])
	case "openmls-conversation-add-member-dev":
		return cmdOpenMLSConversationAddMemberDev(args[1:])
	case "openmls-conversation-join-dev":
		return cmdOpenMLSConversationJoinDev(args[1:])
	case "relay-space-invite-claim-dev":
		return cmdRelaySpaceInviteClaimDev(args[1:])
	case "openmls-relay-keypackage-submit-dev":
		return cmdOpenMLSRelayKeyPackageSubmitDev(args[1:])
	case "openmls-relay-keypackage-inbox-dev":
		return cmdOpenMLSRelayKeyPackageInboxDev(args[1:])
	case "openmls-relay-welcome-submit-dev":
		return cmdOpenMLSRelayWelcomeSubmitDev(args[1:])
	case "openmls-relay-welcome-inbox-dev":
		return cmdOpenMLSRelayWelcomeInboxDev(args[1:])
	case "openmls-relay-add-member-dev":
		return cmdOpenMLSRelayAddMemberDev(args[1:])
	case "openmls-relay-join-dev":
		return cmdOpenMLSRelayJoinDev(args[1:])
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func usage() {
	fmt.Println("CarbonStackComms Phase 2A CLI")
	fmt.Println("")
	fmt.Println("Recommended dev/pre-alpha normal-message wrappers:")
	fmt.Println("  message-send-dev")
	fmt.Println("  message-inbox-dev")
	fmt.Println("")
	fmt.Println("Lower-level direct OpenMLS implementation/proof paths:")
	fmt.Println("  openmls-send-dev")
	fmt.Println("  openmls-inbox-dev")
	fmt.Println("")
	fmt.Println("OpenMLS identity/conversation bootstrap:")
	fmt.Println("  openmls-identity-create-dev")
	fmt.Println("  openmls-identity-status-dev")
	fmt.Println("  openmls-bundle-export-dev")
	fmt.Println("  openmls-conversation-create-dev")
	fmt.Println("  openmls-conversation-load-check-dev")
	fmt.Println("  openmls-conversation-add-member-dev")
	fmt.Println("  openmls-conversation-join-dev")
	fmt.Println("")
	fmt.Println("Relay Space onboarding/artifact dev paths:")
	fmt.Println("  relay-space-invite-claim-dev")
	fmt.Println("  openmls-relay-keypackage-submit-dev")
	fmt.Println("  openmls-relay-keypackage-inbox-dev")
	fmt.Println("  openmls-relay-welcome-submit-dev")
	fmt.Println("  openmls-relay-welcome-inbox-dev")
	fmt.Println("  openmls-relay-add-member-dev")
	fmt.Println("  openmls-relay-join-dev")
	fmt.Println("")
	fmt.Println("Local identity/trust/device helpers:")
	fmt.Println("  init")
	fmt.Println("  dev-create-invite")
	fmt.Println("  claim-invite")
	fmt.Println("  register-device")
	fmt.Println("  list-devices")
	fmt.Println("  fingerprint")
	fmt.Println("  verify-device")
	fmt.Println("  trust-history")
	fmt.Println("  trust-list")
	fmt.Println("  simulate-key-change")
	fmt.Println("  revoke-device")
	fmt.Println("  state-audit-dev")
	fmt.Println("")
	fmt.Println("Legacy stub-era continuity surfaces; require --allow-legacy-stub:")
	fmt.Println("  send")
	fmt.Println("  inbox")
	fmt.Println("  ack")
	fmt.Println("")
	fmt.Println("Boundary: dev/pre-alpha command surface; not production secure messaging, not hostile-server safety, not mature messenger UX.")
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
	fmt.Printf("dev_fingerprint: %s\n", trust.Fingerprint(publicIdentityKey))
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

	commandPaths, err := resolveCommandStatePaths(*statePath)
	if err != nil {
		return err
	}
	paths := commandPaths.TrustPaths

	fmt.Printf("account_id: %s\n", resp.AccountID)
	for _, d := range resp.Devices {
		trustState := trust.StateUnknown
		if record, ok, err := trust.LookupDevice(paths, d.DeviceID); err == nil && ok {
			trustState = record.TrustState
		}

		fmt.Println()
		fmt.Printf("device_id: %s\n", d.DeviceID)
		fmt.Printf("label: %s\n", d.DeviceLabel)
		fmt.Printf("public_identity_key: %s\n", d.PublicIdentityKey)
		fmt.Printf("dev_fingerprint: %s\n", trust.Fingerprint(d.PublicIdentityKey))
		fmt.Printf("trust_state: %s\n", trustState)
		fmt.Printf("created_at: %s\n", d.CreatedAt)
	}
	return nil
}

func cmdFingerprint(args []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	publicKey := fs.String("public-key", "", "public identity key to fingerprint")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *publicKey != "" {
		fmt.Printf("dev_fingerprint: %s\n", trust.Fingerprint(*publicKey))
		return nil
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	fmt.Printf("device_id: %s\n", s.DeviceID)
	fmt.Printf("device_label: %s\n", s.DeviceLabel)
	fmt.Printf("public_identity_key: %s\n", s.PublicIdentityKey)
	fmt.Printf("dev_fingerprint: %s\n", trust.Fingerprint(s.PublicIdentityKey))
	return nil
}

func cmdVerifyDevice(args []string) error {
	fs := flag.NewFlagSet("verify-device", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	accountID := fs.String("account", "", "account ID for the device")
	deviceID := fs.String("device", "", "device ID to verify")
	label := fs.String("label", "", "display label")
	publicKey := fs.String("public-key", "", "public identity key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *deviceID == "" || *publicKey == "" {
		return errors.New("--device and --public-key are required")
	}

	commandPaths, err := resolveCommandStatePaths(*statePath)
	if err != nil {
		return err
	}
	paths := commandPaths.TrustPaths
	record, err := trust.VerifyDevice(paths, *accountID, *deviceID, *label, *publicKey, "cli")
	if err != nil {
		return err
	}

	fmt.Println("device verified")
	fmt.Printf("device_id: %s\n", record.DeviceID)
	fmt.Printf("trust_state: %s\n", record.TrustState)
	fmt.Printf("dev_fingerprint: %s\n", record.Fingerprint)
	return nil
}

func cmdTrustHistory(args []string) error {
	fs := flag.NewFlagSet("trust-history", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	commandPaths, err := resolveCommandStatePaths(*statePath)
	if err != nil {
		return err
	}
	paths := commandPaths.TrustPaths
	events, err := trust.LoadEvents(paths.EventsPath)
	if err != nil {
		return err
	}

	fmt.Printf("trust_events: %d\n", len(events))
	for _, event := range events {
		fmt.Println()
		fmt.Printf("event_id: %s\n", event.EventID)
		fmt.Printf("event_type: %s\n", event.EventType)
		fmt.Printf("device_id: %s\n", event.DeviceID)
		fmt.Printf("previous_state: %s\n", event.PreviousTrustState)
		fmt.Printf("new_state: %s\n", event.NewTrustState)
		fmt.Printf("fingerprint: %s\n", event.Fingerprint)
		fmt.Printf("event_time: %s\n", event.EventTime)
		fmt.Printf("note: %s\n", event.Note)
	}

	return nil
}

func cmdTrustList(args []string) error {
	fs := flag.NewFlagSet("trust-list", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	commandPaths, err := resolveCommandStatePaths(*statePath)
	if err != nil {
		return err
	}
	paths := commandPaths.TrustPaths
	store, err := trust.LoadStore(paths.TrustPath)
	if err != nil {
		return err
	}

	fmt.Printf("trusted_devices: %d\n", len(store.TrustedDevices))
	for _, record := range store.TrustedDevices {
		fmt.Println()
		fmt.Printf("device_id: %s\n", record.DeviceID)
		fmt.Printf("account_id: %s\n", record.AccountID)
		fmt.Printf("label: %s\n", record.DisplayLabel)
		fmt.Printf("trust_state: %s\n", record.TrustState)
		fmt.Printf("fingerprint: %s\n", record.Fingerprint)
		fmt.Printf("first_seen_at: %s\n", record.FirstSeenAt)
		fmt.Printf("last_seen_at: %s\n", record.LastSeenAt)
	}

	return nil
}

func cmdSimulateKeyChange(args []string) error {
	fs := flag.NewFlagSet("simulate-key-change", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	deviceID := fs.String("device", "", "device ID to mark changed")
	publicKey := fs.String("new-public-key", "", "new public identity key")
	if err := fs.Parse(args); err != nil {
		return err
	}

	commandPaths, err := resolveCommandStatePaths(*statePath)
	if err != nil {
		return err
	}
	paths := commandPaths.TrustPaths
	record, err := trust.MarkDeviceChanged(paths, *deviceID, *publicKey, "cli")
	if err != nil {
		return err
	}

	fmt.Println("device marked changed")
	fmt.Printf("device_id: %s\n", record.DeviceID)
	fmt.Printf("trust_state: %s\n", record.TrustState)
	fmt.Printf("dev_fingerprint: %s\n", record.Fingerprint)
	return nil
}

func cmdRevokeDevice(args []string) error {
	fs := flag.NewFlagSet("revoke-device", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	deviceID := fs.String("device", "", "device ID to revoke")
	if err := fs.Parse(args); err != nil {
		return err
	}

	commandPaths, err := resolveCommandStatePaths(*statePath)
	if err != nil {
		return err
	}
	paths := commandPaths.TrustPaths
	record, err := trust.RevokeDevice(paths, *deviceID, "cli")
	if err != nil {
		return err
	}

	fmt.Println("device revoked")
	fmt.Printf("device_id: %s\n", record.DeviceID)
	fmt.Printf("trust_state: %s\n", record.TrustState)
	return nil
}

func printLegacyStubWarning(command string) {
	switch command {
	case "send":
		fmt.Println("warning: legacy/stub-era send path; uses mock/stub message encryption and is not the mature OpenMLS-backed send UX")
		fmt.Println("warning_replaced_by: message-send-dev for recommended dev/pre-alpha normal-message wrapper; openmls-send-dev remains lower-level direct proof")
	case "inbox":
		fmt.Println("warning: legacy/stub-era inbox path; may print stub_plaintext and is not the mature OpenMLS-backed inbox UX")
		fmt.Println("warning_replaced_by: message-inbox-dev for recommended dev/pre-alpha normal-message wrapper; openmls-inbox-dev remains lower-level direct proof")
	case "ack":
		fmt.Println("warning: legacy ack helper; acknowledges a Cypher envelope but is not a standalone secure receive proof")
		fmt.Println("warning_scope: delivery/local-processing state only; not trust, identity verification, hostile-server safety, or production security")
	}
}

func legacyStubOptInError(command string, replacement string) error {
	return fmt.Errorf("legacy/stub-era %s path requires --allow-legacy-stub; use %s for the recommended dev/pre-alpha normal-message path where applicable", command, replacement)
}

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	statePath := fs.String("state", state.DefaultStatePath, "local state file path")
	toDevice := fs.String("to-device", "", "recipient device ID")
	message := fs.String("message", "", "message text")
	strict := fs.Bool("strict", false, "block sending to unknown, unverified, or changed devices")
	allowLegacyStub := fs.Bool("allow-legacy-stub", false, "explicitly allow the legacy mock/stub send path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	printLegacyStubWarning("send")
	if !*allowLegacyStub {
		return legacyStubOptInError("send", "message-send-dev")
	}

	if *toDevice == "" || *message == "" {
		return errors.New("--to-device and --message are required")
	}

	s, err := state.RequireReadyDevice(*statePath)
	if err != nil {
		return err
	}

	commandPaths, err := resolveCommandStatePaths(*statePath)
	if err != nil {
		return err
	}
	paths := commandPaths.TrustPaths
	decision, err := trust.EvaluateSend(paths, *toDevice, *strict)
	if err != nil {
		return err
	}

	if decision.Warning != "" {
		fmt.Printf("WARNING: %s\n", decision.Warning)
	}

	if !decision.Allowed {
		return fmt.Errorf("send blocked by trust policy: recipient trust_state=%s", decision.TrustState)
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
	allowLegacyStub := fs.Bool("allow-legacy-stub", false, "explicitly allow the legacy mock/stub inbox path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	printLegacyStubWarning("inbox")
	if !*allowLegacyStub {
		return legacyStubOptInError("inbox", "message-inbox-dev")
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
	allowLegacyStub := fs.Bool("allow-legacy-stub", false, "explicitly allow the standalone legacy ack helper")
	if err := fs.Parse(args); err != nil {
		return err
	}

	printLegacyStubWarning("ack")
	if !*allowLegacyStub {
		return legacyStubOptInError("ack", "message-inbox-dev --ack or a scoped Relay Space ack path")
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
