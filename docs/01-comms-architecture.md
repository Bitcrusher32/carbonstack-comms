# CarbonStackComms Architecture

CarbonStackComms is the text-first encrypted messaging client for CarbonStack.

It owns the user-facing trust boundary.

The server may route messages, store encrypted envelopes, enforce rate limits, and propagate revocation events, but the client is responsible for identity, encryption, text normalization, trust-state display, local vault protection, and visible safety changes.

## Primary Responsibilities

CarbonStackComms is responsible for:

- local identity
- local secure vault
- strict text validation
- message encryption and decryption
- trust-state tracking
- key-change warnings
- contact verification
- group membership display
- device replacement warnings
- revocation processing
- local session locking
- no-plaintext notification behavior

## Non-Responsibilities

CarbonStackComms should not become:

- a browser
- a file manager
- a rich media client
- a social network
- a general URI handler
- a cloud sync client
- a general-purpose identity provider

## MVP Scope

The first implementation target is:

- normal Android-compatible app
- one-to-one messaging first
- group-aware architecture
- strict text-only messages
- no attachments
- no rich previews
- no automatic linkification
- no HTML
- no Markdown rendering inside chat
- no browser/WebView rendering
- no plaintext notification content
- local encrypted vault
- QR or manual safety verification
- hardware-key support where feasible, not required for the earliest MVP

## Group-Aware, Not Group-First

The MVP SHOULD implement one-to-one messaging first.

However, internal models SHOULD avoid blocking future group messaging.

Important reserved concepts:

- conversation identifier
- sender device identifier
- recipient device identifier
- message sequence data
- replay protection state
- trust state
- future group epoch
- future membership state
- future revocation state

## Client Trust Boundary

The client MUST NOT trust the server to define identity truth.

The client MUST treat these events as safety-sensitive:

- identity key change
- device replacement
- new device enrollment
- group membership change
- revocation event
- history rollback attempt
- duplicate or replayed message
- server state inconsistency
- server-provided key mismatch

## User Experience Principle

Trust changes must be loud.

CarbonStackComms should prefer annoying clarity over silent convenience.

Examples:

- "This contact's identity changed."
- "This device was revoked."
- "This group membership state changed."
- "The server attempted to provide an unexpected key."
- "Message order or replay state is suspicious."

## Text Processing Boundary

Message text must be validated and normalized before encryption.

The client should not encrypt text that violates CarbonStack policy and then rely on receivers to reject it.

The sending path and receiving path should both enforce text policy.

## Local Vault Boundary

The local vault stores:

- message database
- identity keys
- session state
- group state
- contact trust records
- revocation state
- safety-number history

The vault must be cryptographically protected.

UI hiding is not vault protection.

## Relationship to CarbonStackOS

On normal Android, CarbonStackComms can only enforce app-level protections.

Inside CarbonStackOS, it SHOULD integrate with:

- appliance session state
- duress state machine
- secure vault domain
- hardware-key recovery
- restricted notification policy
- restricted text rendering
- interface lockdown events

## Core Principle

CarbonStackComms is not a convenience chat app.

It is the user-facing control surface for a hostile-server, text-first, small-group secure communications system.
