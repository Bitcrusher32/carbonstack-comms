# CarbonStackComms Phase 1 Client Lifecycle

## Status

Classification: PLANNED / NOT IMPLEMENTED

This document defines the Phase 1 CLI client lifecycle.

The CLI client exists to validate CarbonStackComms message flow before Android implementation.

## Goal

Build a minimal local client that can:

1. Claim an invite.
2. Register a device.
3. Store local account/device state.
4. Look up another device.
5. Build a stub encrypted envelope.
6. Send it to CarbonStackCypher.
7. Retrieve envelopes.
8. Decode/decrypt through a mock provider.
9. Acknowledge delivery.

## Why CLI First

Android-first implementation would introduce:

- Gradle/project setup complexity
- Android lifecycle complexity
- UI complexity
- keystore integration
- permission model concerns
- emulator/device debugging
- hardware-key integration complexity

The CLI allows the relay, data model, and message lifecycle to be tested first.

## Phase 1 Commands

Potential CLI shape:

```text
carbonstack-comms init
carbonstack-comms claim-invite --server http://localhost:8080 --invite CODE --name alice
carbonstack-comms register-device --label alice-cli-1
carbonstack-comms list-devices --account ACCOUNT_ID
carbonstack-comms send --to-device DEVICE_ID --message "hello"
carbonstack-comms inbox
carbonstack-comms ack --envelope ENVELOPE_ID
Local Lifecycle
1. Initialize Local State

Create local state directory.

Example:

.carbonstack-comms/
  state.json
  trust.json
  messages.jsonl
2. Claim Invite

Client sends invite code and display name to Cypher.

Result:

account_id stored locally
3. Register Device

Client creates local device identity material.

Phase 1:

stub identity key
stub prekey bundle
device_label

Result:

device_id stored locally
4. Send Message

Client flow:

User enters recipient device ID.
Client asks CryptoProvider to produce envelope payload.
Client base64-encodes ciphertext/stub payload.
Client submits envelope to Cypher.
5. Retrieve Message

Client flow:

Client requests queued envelopes for its device_id.
Client passes ciphertext to CryptoProvider.
Client displays plaintext/stub output.
Client acknowledges envelope.
Mock CryptoProvider

Phase 1 must not implement custom cryptography.

The mock provider exists only to preserve architecture shape.

Required interface concept:

encrypt(recipient_device, plaintext) -> ciphertext
decrypt(sender_device, ciphertext) -> plaintext

The mock provider may initially base64-wrap or otherwise fake ciphertext for local testing, but this must be clearly marked insecure.

Non-Goals
no Android app
no hardware-key integration
no local vault hardening
no final protocol
no production encryption
no group messaging
no attachments
no notification system
Allowed Claim After Phase 1

CarbonStackComms has a CLI lifecycle that can exercise CarbonStackCypher envelope delivery.

Not Allowed Claim After Phase 1

CarbonStackComms is secure for real-world private communication.
