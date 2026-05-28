# CarbonStackComms

CarbonStackComms is the text-first encrypted messaging client for the CarbonStack project.

It is designed for small trusted groups, hostile-server assumptions, loud trust changes, and minimal parser exposure.

## Core Properties

- text only by default
- no inline attachments
- no rich previews
- no stickers
- no GIFs
- no voice messages
- no browser rendering
- no hidden linkification
- no server-trusted identity changes
- strict text normalization
- hardware-key-backed identity where possible

## Relationship to CarbonStackOS

CarbonStackComms should run as a normal Android app during early development.

The long-term goal is deployment inside CarbonStackOS as the primary communications interface.

## Experimental OpenMLS real-Cypher relay smoke harness

CarbonStackComms includes a dev/test smoke harness for the current OpenMLS relay lifecycle proof:

    powershell -ExecutionPolicy Bypass -File .\scripts\smoke-openmls-real-cypher-relay.ps1

For broader validation:

    powershell -ExecutionPolicy Bypass -File .\scripts\smoke-openmls-real-cypher-relay.ps1 -Full

This harness starts a real local CarbonStackCypher server through the Go test path, uses a temp SQLite database, runs the OpenMLS KeyPackage -> Welcome -> application-message relay lifecycle, and verifies final sidecar message-open plaintext recovery.

This is experimental dev infrastructure only.

It is not production E2EE, not certified secure, not externally audited, not Android-ready, and not polished Comms runtime UX. Normal `comms send` / `comms inbox` remain stub-era until a later runtime integration rung.

