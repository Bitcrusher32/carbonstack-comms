# CarbonStackComms Local State Model v0

## Status

Classification: PLANNED / NOT IMPLEMENTED

This document defines the Phase 1 CLI local state model.

It is not the final secure vault design.

## Design Principles

- Keep local state inspectable during development.
- Do not claim local secrecy in Phase 1.
- Preserve future migration path to encrypted local vault.
- Separate account, device, trust, and message state conceptually.

## Local Directory

Default development directory:

```text
.carbonstack-comms/

Initial files:

state.json
trust.json
messages.jsonl
state.json

Purpose:

Store local account and device state.

Example:

{
  "server_url": "http://localhost:8080",
  "account_id": "uuid",
  "display_name": "alice",
  "device_id": "uuid",
  "device_label": "alice-cli-1",
  "public_identity_key": "stub-public-identity-key",
  "private_identity_key_ref": "stub-private-identity-key-ref",
  "protocol_version": "stub-v0"
}

Notes:

private_identity_key_ref is a placeholder.
No real private key security is claimed in Phase 1.
trust.json

Purpose:

Store known device/contact records.

Example:

{
  "trusted_devices": [
    {
      "account_id": "uuid",
      "device_id": "uuid",
      "display_label": "bob-cli-1",
      "public_identity_key": "stub-public-identity-key",
      "trust_state": "unverified",
      "first_seen_at": "2026-05-21T00:00:00Z",
      "last_seen_at": "2026-05-21T00:00:00Z"
    }
  ]
}

Initial trust states:

unverified
verified
changed
revoked

Phase 1 may use unverified only, but the model should not erase future loud trust-change UX.

messages.jsonl

Purpose:

Store local message/event history for development.

Example line:

{"direction":"outbound","envelope_id":"uuid","peer_device_id":"uuid","body":"hello","created_at":"2026-05-21T00:00:00Z"}

Notes:

This is not secure local storage.
Final CarbonStackComms must use an encrypted local vault.
This file should not be used for real private communications.
Future Vault Migration

Future secure local storage should separate:

identity keys
message database
trust records
group state
recovery state

Phase 1 does not implement this.

Non-Goals
no encrypted local vault yet
no Android Keystore yet
no StrongBox yet
no YubiKey/passkey unlock yet
no duress integration yet
no production local secrecy claim
Development Warning

Any Phase 1 CLI local state should be treated as plaintext development state.
Do not use it for sensitive real-world communication.
