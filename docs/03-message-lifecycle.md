# Message Lifecycle

This document defines the high-level CarbonStackComms message lifecycle.

The lifecycle is intentionally explicit so that validation, encryption, server submission, storage, and rendering do not blur together.

## Outbound Text Message

1. User composes message.
2. Input is treated as untrusted text.
3. Text is checked against CarbonStack text policy.
4. Invalid byte sequences are rejected.
5. Text is normalized.
6. Forbidden characters are rejected or visibly marked.
7. Maximum size and line length are enforced.
8. Message object is created.
9. Message object is encrypted locally.
10. Encrypted envelope is submitted to CarbonStackCypher.
11. Local send record is stored in the secure vault.

## Inbound Text Message

1. Client receives encrypted envelope from CarbonStackCypher.
2. Envelope structure is validated.
3. Protocol version is checked.
4. Sender device identity is checked.
5. Replay state is checked.
6. Trust state is checked.
7. Payload is decrypted locally.
8. Plaintext is validated against CarbonStack text policy.
9. Message is stored in local secure vault.
10. UI renders message through constrained text renderer.

## Rejection Points

The client may reject a message before decryption if:

- envelope format is invalid
- protocol version is unsupported
- sender device is revoked
- message appears replayed
- message state appears rolled back
- group epoch is unexpected
- required metadata is missing

The client may reject a message after decryption if:

- plaintext violates text policy
- message type is unsupported
- message exceeds size limits
- message contains forbidden characters
- message attempts unsupported rich content

## Trust Warnings

The client must visibly warn for:

- key changes
- device replacements
- group membership changes
- unexpected server identity data
- revoked devices
- suspicious replay/order behavior

## No Silent Rich Content

The message lifecycle must not include:

- automatic link previews
- automatic URL detection
- HTML rendering
- Markdown rendering in chat
- inline attachments
- remote content fetching
- WebView rendering
- emoji fallback engines unless deliberately curated later

## Core Principle

A message should become boring, normalized text before encryption and boring, constrained text after decryption.
