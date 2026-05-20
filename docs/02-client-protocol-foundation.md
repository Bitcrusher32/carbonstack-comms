# Client Protocol Foundation

CarbonStackComms MUST NOT invent cryptography casually.

The client protocol should be built around mature, reviewed foundations while preserving CarbonStack-specific trust UX, strict text policy, local vault behavior, and hostile-server assumptions.

## Phase 1 Target

Phase 1 targets one-to-one asynchronous messaging.

The preferred investigation path is a Signal-style protocol foundation:

- asynchronous initial session setup
- prekey-style delivery support
- Double Ratchet-style message key evolution
- forward secrecy
- post-compromise recovery properties
- replay resistance
- visible key-change behavior

Candidate foundations include:

- Signal Protocol / libsignal
- X3DH or PQXDH-style initial agreement
- Double Ratchet-style message encryption

## Future Group Target

Future group messaging SHOULD investigate MLS.

Group messaging should support:

- group epochs
- explicit membership changes
- visible device additions
- visible device removals
- auditable membership history
- server-hostile group state
- revocation propagation

Group messaging MUST NOT allow the server to silently add members, replace keys, or rewrite group state without client-visible detection.

## CarbonStack Envelope Layer

CarbonStackComms should define a CarbonStack envelope above or around the chosen crypto foundation.

The envelope should support:

- protocol version
- sender device identifier
- recipient or conversation identifier
- message type
- encrypted payload
- replay protection metadata
- trust-state metadata where appropriate
- future group epoch metadata
- future revocation metadata

The envelope must avoid plaintext leakage where possible.

Metadata minimization is desired, but early versions may not provide strong metadata privacy.

## Message Lifecycle

A normal outbound message should follow this path:

1. user enters text
2. text is validated
3. text is normalized
4. unsupported characters are rejected or visibly marked
5. message object is formed
6. message is encrypted locally
7. encrypted envelope is submitted to CarbonStackCypher
8. local send state is recorded

A normal inbound message should follow this path:

1. encrypted envelope is received
2. envelope structure is validated
3. replay/order state is checked
4. sender identity is checked
5. message is decrypted locally
6. plaintext is validated against policy
7. message is stored in local vault
8. UI renders through constrained text renderer

## Trust Failure Behavior

The client should fail closed or enter warning state when encountering:

- unknown sender key
- changed sender key
- mismatched device identity
- unexpected group epoch
- replayed message
- malformed envelope
- unsupported protocol version
- server-supplied identity mismatch
- revoked device
- stale or rolled-back state

## Hardware-Key Role

For earliest experimental MVP:

- hardware keys are not mandatory

For future high-assurance release:

- hardware-key-backed enrollment SHOULD be required
- hardware-key-backed recovery SHOULD be required
- hardware-key approval SHOULD be required for high-risk trust actions

High-risk trust actions include:

- adding a device
- replacing a device
- recovering a device
- revoking a device
- exporting backup material
- joining a high-assurance group

## Non-Claims

CarbonStackComms does not initially claim:

- full metadata privacy
- resistance to compromised endpoints
- audited Signal-equivalent security
- production-grade group messaging
- protection from malicious recipient devices

## Core Principle

Use mature crypto foundations.

Make CarbonStack-specific trust changes loud, testable, and hard for the server to fake.
