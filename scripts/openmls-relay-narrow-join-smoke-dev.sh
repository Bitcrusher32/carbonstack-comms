#!/usr/bin/env bash
set -euo pipefail

need() {
  name="$1"
  if [ -z "${!name:-}" ]; then
    echo "missing required environment variable: $name" >&2
    exit 2
  fi
}

need ALICE_STATE
need BOB_STATE
need RELAY_SPACE_ID
need ALICE_DEVICE_ID
need BOB_DEVICE_ID
need ALICE_SIDECAR_LABEL
need BOB_SIDECAR_LABEL
need ALICE_CONVERSATION_LABEL
need BOB_CONVERSATION_LABEL

if [ -n "${COMMS_DIR:-}" ]; then
  cd "$COMMS_DIR"
else
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cd "$script_dir/.."
fi

echo "===== CarbonStack v0.5.48 narrow Relay Space OpenMLS join smoke proof ====="
echo "scope: dev/pre-alpha command sequencing only"
echo "nonclaims: no local-backbone, no identity verification, no trust mutation, no candidate acceptance, no production/security claim"
echo

echo "===== Step 1: Bob submits KeyPackage to Alice through Relay Space ====="
go run ./cmd/comms openmls-relay-keypackage-submit-dev \
  --state "$BOB_STATE" \
  --relay-space "$RELAY_SPACE_ID" \
  --to-device "$ALICE_DEVICE_ID" \
  --sidecar-device-label "$BOB_SIDECAR_LABEL"

echo
echo "===== Step 2: Alice consumes KeyPackage, runs add-member, submits Welcome to Bob ====="
go run ./cmd/comms openmls-relay-add-member-dev \
  --state "$ALICE_STATE" \
  --relay-space "$RELAY_SPACE_ID" \
  --sidecar-device-label "$ALICE_SIDECAR_LABEL" \
  --conversation "$ALICE_CONVERSATION_LABEL" \
  --welcome-to-device "$BOB_DEVICE_ID"

echo
echo "===== Step 3: Bob consumes Welcome and runs conversation-join ====="
join_args=(
  openmls-relay-join-dev
  --state "$BOB_STATE"
  --relay-space "$RELAY_SPACE_ID"
  --sidecar-device-label "$BOB_SIDECAR_LABEL"
  --conversation "$BOB_CONVERSATION_LABEL"
)

if [ "${ACK_AFTER_JOIN:-0}" = "1" ]; then
  echo "ACK_AFTER_JOIN=1: scoped Welcome ack will be requested only after join success"
  join_args+=(--ack-after-join)
else
  echo "ACK_AFTER_JOIN not set to 1: scoped Welcome ack will not be requested"
fi

go run ./cmd/comms "${join_args[@]}"

echo
echo "===== Smoke proof command sequence completed ====="
echo "Reminder: this is not local-backbone, not identity verification, and not production security proof."
