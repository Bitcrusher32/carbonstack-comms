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

parse_field() {
  local file="$1"
  local key="$2"
  awk -F': ' -v key="$key" '$1 == key {print $2; exit}' "$file"
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
umbrella_root="$(cd "$repo_root/.." && pwd)"
cypher_root="$umbrella_root/carbonstack-cypher"
sidecar_dir="$repo_root/internal/protocol/mls/openmls-sidecar"

require_cmd go
require_cmd cargo
require_cmd curl
require_cmd python3
require_cmd awk

if [ ! -f "$repo_root/go.mod" ]; then
  fail "carbonstack-comms repo root not found: $repo_root"
fi

if [ ! -f "$cypher_root/cmd/cypher/main.go" ]; then
  fail "carbonstack-cypher repo not found at expected umbrella sibling: $cypher_root"
fi

if [ ! -f "$sidecar_dir/Cargo.toml" ]; then
  fail "OpenMLS sidecar not found: $sidecar_dir"
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/carbonstack-openmls-runtime-smoke-wrappers-XXXXXXXXXX")"
cypher_bin="$work_dir/carbonstack-cypher-smoke"
cypher_db="$work_dir/cypher-smoke.db"
cypher_log="$work_dir/cypher.log"
alice_state="$work_dir/alice-state.json"
bob_state="$work_dir/bob-state.json"
alice_label="carbonstack-smoke-wrapper-alice-device"
bob_label="carbonstack-smoke-wrapper-bob-device"
conversation_label="carbonstack-smoke-wrapper-conversation"
message_label="runtime-smoke-wrapper-message-0001"
plaintext="hello bob through wrapper bootstrap runtime smoke"

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

log "Wrapper smoke workspace"
printf 'work_dir: %s\n' "$work_dir"

log "Remove prior OpenMLS sidecar dev state"
rm -rf "$sidecar_dir/.carbonstack-openmls-sidecar-state"

log "Build temporary Cypher binary"
(
  cd "$cypher_root"
  go build -o "$cypher_bin" ./cmd/cypher
)

log "Start temporary Cypher server"
port="$(python3 - <<'PYPORT'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PYPORT
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

run_comms claim-invite --state "$alice_state" --invite dev-invite --name alice-runtime-smoke-wrapper >/dev/null

bob_invite_out="$work_dir/bob-invite.txt"
run_comms dev-create-invite --state "$alice_state" --invite bob-runtime-smoke-wrapper-invite > "$bob_invite_out"

run_comms claim-invite --state "$bob_state" --invite bob-runtime-smoke-wrapper-invite --name bob-runtime-smoke-wrapper >/dev/null

alice_register_out="$work_dir/alice-register.txt"
bob_register_out="$work_dir/bob-register.txt"

run_comms register-device --state "$alice_state" --label alice-runtime-smoke-wrapper-device > "$alice_register_out"
run_comms register-device --state "$bob_state" --label bob-runtime-smoke-wrapper-device > "$bob_register_out"

alice_device_id="$(awk -F': ' '/device_id:/ {print $2; exit}' "$alice_register_out")"
bob_device_id="$(awk -F': ' '/device_id:/ {print $2; exit}' "$bob_register_out")"

[ -n "$alice_device_id" ] || fail "could not parse Alice device ID"
[ -n "$bob_device_id" ] || fail "could not parse Bob device ID"

printf 'alice_device_id: %s\n' "$alice_device_id"
printf 'bob_device_id: %s\n' "$bob_device_id"

log "Create sidecar identities through Comms wrappers"
run_comms openmls-identity-create-dev --sidecar-device-label "$alice_label" > "$work_dir/alice-identity.txt"
run_comms openmls-identity-create-dev --sidecar-device-label "$bob_label" > "$work_dir/bob-identity.txt"

cat "$work_dir/alice-identity.txt"
cat "$work_dir/bob-identity.txt"

grep -q "status: created" "$work_dir/alice-identity.txt" || fail "Alice identity wrapper did not report created"
grep -q "status: created" "$work_dir/bob-identity.txt" || fail "Bob identity wrapper did not report created"

log "Bootstrap sidecar conversation through Comms wrappers"
bob_bundle_out="$work_dir/bob-public-bundle.txt"
run_comms openmls-bundle-export-dev --sidecar-device-label "$bob_label" --write-artifact > "$bob_bundle_out"
cat "$bob_bundle_out"

bob_keypackage_path="$(parse_field "$bob_bundle_out" "key_package_artifact_path")"
[ -n "$bob_keypackage_path" ] || fail "could not parse Bob key_package_artifact_path from wrapper output"
[ -f "$repo_root/$bob_keypackage_path" ] || fail "Bob KeyPackage artifact does not exist: $repo_root/$bob_keypackage_path"

alice_conversation_out="$work_dir/alice-conversation.txt"
run_comms openmls-conversation-create-dev \
  --sidecar-device-label "$alice_label" \
  --conversation "$conversation_label" > "$alice_conversation_out"
cat "$alice_conversation_out"
grep -q "status: created" "$alice_conversation_out" || fail "conversation create wrapper did not report created"

alice_load_out="$work_dir/alice-load-check.txt"
run_comms openmls-conversation-load-check-dev \
  --sidecar-device-label "$alice_label" \
  --conversation "$conversation_label" > "$alice_load_out"
cat "$alice_load_out"
grep -q "group_reloadable: true" "$alice_load_out" || fail "Alice conversation load-check did not report group_reloadable: true"

alice_add_member_out="$work_dir/alice-add-member.txt"
run_comms openmls-conversation-add-member-dev \
  --sidecar-device-label "$alice_label" \
  --conversation "$conversation_label" \
  --member-keypackage "$bob_keypackage_path" > "$alice_add_member_out"
cat "$alice_add_member_out"

grep -q "status: welcome_created" "$alice_add_member_out" || fail "add-member wrapper did not report welcome_created"
grep -q "member_added: true" "$alice_add_member_out" || fail "add-member wrapper did not report member_added: true"
grep -q "welcome_artifact_written: true" "$alice_add_member_out" || fail "add-member wrapper did not report welcome_artifact_written: true"

welcome_path="$(parse_field "$alice_add_member_out" "welcome_artifact_path")"
[ -n "$welcome_path" ] || fail "could not parse welcome_artifact_path from add-member wrapper output"
[ -f "$repo_root/$welcome_path" ] || fail "Welcome artifact does not exist: $repo_root/$welcome_path"

bob_join_out="$work_dir/bob-join.txt"
run_comms openmls-conversation-join-dev \
  --sidecar-device-label "$bob_label" \
  --conversation "$conversation_label" \
  --welcome "$welcome_path" > "$bob_join_out"
cat "$bob_join_out"

grep -q "status: joined" "$bob_join_out" || fail "join wrapper did not report joined"
grep -q "joined: true" "$bob_join_out" || fail "join wrapper did not report joined: true"

bob_load_out="$work_dir/bob-load-check.txt"
run_comms openmls-conversation-load-check-dev \
  --sidecar-device-label "$bob_label" \
  --conversation "$conversation_label" > "$bob_load_out"
cat "$bob_load_out"
grep -q "group_reloadable: true" "$bob_load_out" || fail "Bob conversation load-check did not report group_reloadable: true"

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

queued_after_ack="$(python3 - "$after_ack" <<'PYCHECK'
import json
import sys
data = json.loads(open(sys.argv[1], "r", encoding="utf-8").read())
print(len(data.get("envelopes", [])))
PYCHECK
)"

if [ "$queued_after_ack" != "0" ]; then
  cat "$after_ack"
  fail "expected Bob inbox to be empty after ack, got $queued_after_ack envelopes"
fi

log "PASS: wrapper-based dev runtime OpenMLS CLI smoke proof"
printf 'proof: openmls-*-dev bootstrap wrappers -> openmls-send-dev -> Cypher -> openmls-inbox-dev --ack\n'
printf 'plaintext: %s\n' "$plaintext"
printf 'workspace: %s\n' "$work_dir"
printf 'boundary: dev/pre-alpha wrapper smoke proof; not local-backbone; not production messaging UX\n'
