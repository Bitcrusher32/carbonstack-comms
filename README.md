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
