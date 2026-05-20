# CarbonStackComms Requirements

## MVP Requirements

- one-device-per-user initial model
- text-only messaging
- strict UTF-8 validation
- QR or hardware-key contact verification
- loud key-change warnings
- encrypted local vault
- no plaintext notification content
- no rich previews
- no clickable links by default
- no attachments in MVP

## Trust Requirements

The server must not be able to silently:

- add members
- replace keys
- forge sender identity
- rewrite group history
- roll back group state

## Deferred

- group media
- camera
- images
- audio messages
- multi-device support
- rich text
- Markdown rendering in chat
- browser-based rendering
