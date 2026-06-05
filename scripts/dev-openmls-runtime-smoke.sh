#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '\n==> %s\n' "$1"
}

fail() {
  printf '\nFAIL: %s\n' "$1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
umbrella_root="$(cd "$repo_root/.." && pwd)"
cypher_root="$umbrella_root/carbonstack-cypher"
sidecar_dir="$repo_root/internal/protocol/mls/openmls-sidecar"

require_cmd go
require_cmd cargo
require_cmd curl
require_cmd python3

if [ ! -f "$repo_root/go.mod" ]; then
  fail "carbonstack-comms repo root not found: $repo_root"
fi

if [ ! -f "$cypher_root/cmd/cypher/main.go" ]; then
  fail "carbonstack-cypher repo not found at expected umbrella sibling: $cypher_root"
fi

if [ ! -f "$sidecar_dir/Cargo.toml" ]; then
  fail "OpenMLS sidecar not found: $sidecar_dir"
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/carbonstack-openmls-runtime-smoke-XXXXXXXXXX")"
cypher_bin="$work_dir/carbonstack-cypher-smoke"
cypher_db="$work_dir/cypher-smoke.db"
cypher_log="$work_dir/cypher.log"
alice_state="$work_dir/alice-state.json"
bob_state="$work_dir/bob-state.json"
alice_label="carbonstack-smoke-alice-device"
bob_label="carbonstack-smoke-bob-device"
conversation_label="carbonstack-smoke-conversation"
message_label="runtime-smoke-message-0001"
plaintext="hello bob through openmls runtime smoke"

cypher_pid=""

cleanup() {
  set +e
  if [ -n "${cypher_pid:-}" ] && kill -0 "$cypher_pid" >/dev/null 2>&1; then
    kill -INT "$cypher_pid" >/dev/null 2>&1 || true

    for _ in 1 2 3 4 5 6 7 8 9 10; do
      if ! kill -0 "$cypher_pid" >/dev/null 2>&1; then
        wait "$cypher_pid" >/dev/null 2>&1 || true
        return
      fi
      sleep 0.1
    done

    kill -TERM "$cypher_pid" >/dev/null 2>&1 || true

    for _ in 1 2 3 4 5 6 7 8 9 10; do
      if ! kill -0 "$cypher_pid" >/dev/null 2>&1; then
        wait "$cypher_pid" >/dev/null 2>&1 || true
        return
      fi
      sleep 0.1
    done

    kill -KILL "$cypher_pid" >/dev/null 2>&1 || true
    wait "$cypher_pid" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

json_field() {
  python3 - "$1" "$2" <<'PY'
import json
import sys

path = sys.argv[1]
key = sys.argv[2]

data = json.loads(open(path, "r", encoding="utf-8").read())

cur = data
for part in key.split("."):
    cur = cur[part]

print(cur)
PY
}

run_sidecar_json() {
  local out="$1"
  shift
  (
    cd "$sidecar_dir"
    cargo run --quiet -- "$@" > "$out"
  )
}

run_comms() {
  (
    cd "$repo_root"
    go run ./cmd/comms "$@"
  )
}

wait_for_cypher() {
  local url="$1"
  local i
  for i in $(seq 1 80); do
    if curl -fsS "$url/v0/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done

  printf '\nCypher log:\n' >&2
  cat "$cypher_log" >&2 || true
  return 1
}

log "Smoke workspace"
printf 'work_dir: %s\n' "$work_dir"

log "Remove prior OpenMLS sidecar dev state"
rm -rf "$sidecar_dir/.carbonstack-openmls-sidecar-state"

log "Build temporary Cypher binary"
(
  cd "$cypher_root"
  go build -o "$cypher_bin" ./cmd/cypher
)

log "Start temporary Cypher server"
port="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
cypher_addr="127.0.0.1:$port"
cypher_url="http://$cypher_addr"

(
  cd "$cypher_root"
  CYPHER_ADDR="$cypher_addr" \
  CYPHER_DB="$cypher_db" \
  CYPHER_MIGRATIONS="$cypher_root/migrations" \
  CYPHER_DEV_INVITE="dev-invite" \
  "$cypher_bin" > "$cypher_log" 2>&1
) &
cypher_pid="$!"

wait_for_cypher "$cypher_url" || fail "Cypher did not become healthy"

printf 'cypher_url: %s\n' "$cypher_url"

log "Create Comms local states and Cypher devices"
run_comms init --state "$alice_state" --server "$cypher_url" >/dev/null
run_comms init --state "$bob_state" --server "$cypher_url" >/dev/null

run_comms claim-invite --state "$alice_state" --invite dev-invite --name alice-runtime-smoke >/dev/null

bob_invite_out="$work_dir/bob-invite.txt"
run_comms dev-create-invite --state "$alice_state" --invite bob-runtime-smoke-invite > "$bob_invite_out"

run_comms claim-invite --state "$bob_state" --invite bob-runtime-smoke-invite --name bob-runtime-smoke >/dev/null

alice_register_out="$work_dir/alice-register.txt"
bob_register_out="$work_dir/bob-register.txt"

run_comms register-device --state "$alice_state" --label alice-runtime-smoke-device > "$alice_register_out"
run_comms register-device --state "$bob_state" --label bob-runtime-smoke-device > "$bob_register_out"

alice_device_id="$(awk -F': ' '/device_id:/ {print $2; exit}' "$alice_register_out")"
bob_device_id="$(awk -F': ' '/device_id:/ {print $2; exit}' "$bob_register_out")"

[ -n "$alice_device_id" ] || fail "could not parse Alice device ID"
[ -n "$bob_device_id" ] || fail "could not parse Bob device ID"

printf 'alice_device_id: %s\n' "$alice_device_id"
printf 'bob_device_id: %s\n' "$bob_device_id"

log "Create sidecar identities"
run_sidecar_json "$work_dir/alice-identity.json" identity-create --device-label "$alice_label"
run_sidecar_json "$work_dir/bob-identity.json" identity-create --device-label "$bob_label"

log "Bootstrap sidecar conversation directly for dev smoke setup"
run_sidecar_json "$work_dir/bob-public-bundle.json" public-bundle-export --device-label "$bob_label" --write-artifact
bob_keypackage_hint="$(json_field "$work_dir/bob-public-bundle.json" "data.key_package_artifact_path_hint")"
bob_keypackage_path="$sidecar_dir/$bob_keypackage_hint"

run_sidecar_json "$work_dir/alice-conversation.json" conversation-create --device-label "$alice_label" --conversation-label "$conversation_label"

run_sidecar_json "$work_dir/alice-add-member.json" conversation-add-member \
  --device-label "$alice_label" \
  --conversation-label "$conversation_label" \
  --member-keypackage "$bob_keypackage_path"

welcome_hint="$(json_field "$work_dir/alice-add-member.json" "data.welcome_artifact_path_hint")"
welcome_path="$sidecar_dir/$welcome_hint"

run_sidecar_json "$work_dir/bob-join.json" conversation-join \
  --device-label "$bob_label" \
  --conversation-label "$conversation_label" \
  --welcome "$welcome_path"

log "Send application message through Comms openmls-send-dev"
send_out="$work_dir/openmls-send-dev.txt"
run_comms openmls-send-dev \
  --state "$alice_state" \
  --to-device "$bob_device_id" \
  --sidecar-device-label "$alice_label" \
  --conversation "$conversation_label" \
  --message-label "$message_label" \
  --message "$plaintext" > "$send_out"

cat "$send_out"

grep -q "status: sent" "$send_out" || fail "openmls-send-dev did not report status: sent"
grep -q "content_type: carbonstack.mls.application-message.v0" "$send_out" || fail "send output did not report OpenMLS application-message content type"
grep -q "protocol_version: carbonstack-openmls-sidecar-v0" "$send_out" || fail "send output did not report OpenMLS sidecar protocol version"

log "Open and ack application message through Comms openmls-inbox-dev"
inbox_out="$work_dir/openmls-inbox-dev.txt"
run_comms openmls-inbox-dev \
  --state "$bob_state" \
  --sidecar-device-label "$bob_label" \
  --conversation "$conversation_label" \
  --message-label "$message_label" \
  --limit 1 \
  --ack > "$inbox_out"

cat "$inbox_out"

grep -q "openmls_message_opened" "$inbox_out" || fail "openmls-inbox-dev did not report message opened"
grep -q "plaintext_utf8: $plaintext" "$inbox_out" || fail "opened plaintext did not match expected message"
grep -q "acked: true" "$inbox_out" || fail "openmls-inbox-dev did not ack after message-open success"

log "Verify Bob inbox is empty after ack"
after_ack="$work_dir/bob-inbox-after-ack.json"
curl -fsS "$cypher_url/v0/devices/$bob_device_id/envelopes" > "$after_ack"

queued_after_ack="$(python3 - "$after_ack" <<'PY'
import json
import sys
data = json.loads(open(sys.argv[1], "r", encoding="utf-8").read())
print(len(data.get("envelopes", [])))
PY
)"

if [ "$queued_after_ack" != "0" ]; then
  cat "$after_ack"
  fail "expected Bob inbox to be empty after ack, got $queued_after_ack envelopes"
fi

log "PASS: dev runtime OpenMLS CLI smoke proof"
printf 'proof: openmls-send-dev -> Cypher -> openmls-inbox-dev --ack\n'
printf 'plaintext: %s\n' "$plaintext"
printf 'workspace: %s\n' "$work_dir"
printf 'boundary: dev/pre-alpha smoke proof; not local-backbone; not production messaging UX\n'
