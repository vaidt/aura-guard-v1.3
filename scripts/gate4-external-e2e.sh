#!/usr/bin/env bash
# Gate 4 external-client black-box E2E:
# real TCP listener -> HTTP client -> Python Core evaluator -> JSONL -> aura-replay/Merkle.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="$ROOT_DIR/artifacts/gate4"
mkdir -p "$ARTIFACT_DIR"
rm -f "$ARTIFACT_DIR/request.json" "$ARTIFACT_DIR/response.json" \
  "$ARTIFACT_DIR/replay.json" "$ARTIFACT_DIR/server.log" "$ARTIFACT_DIR/setup.log" \
  "$ARTIFACT_DIR/audit.jsonl"
rm -rf "$ARTIFACT_DIR/segments"
mkdir -p "$ARTIFACT_DIR/segments"

: "${AURA_CORE_PATH:?AURA_CORE_PATH must point to a checked-out AURA Core repository}"
export AURA_CORE_CONSTITUTION_VECTOR="${AURA_CORE_CONSTITUTION_VECTOR:-[100000,0,0,0]}"
export AURA_CORE_PYTHON="${AURA_CORE_PYTHON:-python3}"
export AURA_CORE_VERSION="${AURA_CORE_VERSION:-core-v3.3-gate4}"

# Build the actual server/verification CLIs and generate signatures for the
# repository's expected policy packs. The test never disables API auth or
# policy-signature verification.
"$ROOT_DIR/scripts/setup.sh" 2>&1 | tee "$ARTIFACT_DIR/setup.log"

API_KEY="$(openssl rand -hex 32)"
BIND="${AURA_GATE4_BIND:-127.0.0.1:18089}"
BASE_URL="http://$BIND"

env \
  AURA_BIND="$BIND" \
  AURA_API_KEY="$API_KEY" \
  AURA_POLICIES_DIR="$ROOT_DIR/policies" \
  AURA_TRUSTED_SIGNERS_FILE="$ROOT_DIR/policies/trusted_signers.json" \
  AURA_DEFAULT_POLICY_SET="finance-v1" \
  AURA_AUDIT_LOG_PATH="$ARTIFACT_DIR/audit.jsonl" \
  AURA_SEGMENTS_DIR="$ARTIFACT_DIR/segments" \
  AURA_SEGMENT_SIZE=1 \
  AURA_SEGMENT_INTERVAL_SECONDS=0 \
  AURA_CORE_PATH="$AURA_CORE_PATH" \
  AURA_CORE_CONSTITUTION_VECTOR="$AURA_CORE_CONSTITUTION_VECTOR" \
  AURA_CORE_PYTHON="$AURA_CORE_PYTHON" \
  AURA_CORE_VERSION="$AURA_CORE_VERSION" \
  "$ROOT_DIR/target/release/aura-guard" >"$ARTIFACT_DIR/server.log" 2>&1 &
SERVER_PID=$!

cleanup() {
  if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

ready=0
for attempt in $(seq 1 60); do
  if curl --silent --fail "$BASE_URL/health" >/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    cat "$ARTIFACT_DIR/server.log" >&2
    echo "FAIL: Aura-Guard exited before the HTTP listener became healthy" >&2
    exit 1
  fi
  sleep 0.5
done
if [[ "$ready" != "1" ]]; then
  cat "$ARTIFACT_DIR/server.log" >&2
  echo "FAIL: Aura-Guard did not become healthy at $BASE_URL" >&2
  exit 1
fi

cat >"$ARTIFACT_DIR/request.json" <<'JSON'
{
  "context": "Finance Bot",
  "policy_set": "finance-v1",
  "payload": {
    "prompt": "Show a brief log.",
    "response": "No issue was found."
  },
  "measurement_input": {
    "vector": [100000, 0, 0, 0],
    "valid_schema": true
  }
}
JSON

# This curl call is an external client request over TCP to the listening service;
# it is intentionally not a Tower/Router in-process test.
HTTP_STATUS="$(curl --silent --show-error \
  --output "$ARTIFACT_DIR/response.json" \
  --write-out '%{http_code}' \
  --request POST "$BASE_URL/v1/audit" \
  --header "Content-Type: application/json" \
  --header "X-API-Key: $API_KEY" \
  --header "X-Request-ID: gate4-external-black-box" \
  --data-binary @"$ARTIFACT_DIR/request.json")"

if [[ "$HTTP_STATUS" != "200" ]]; then
  cat "$ARTIFACT_DIR/response.json" >&2
  cat "$ARTIFACT_DIR/server.log" >&2
  echo "FAIL: external POST /v1/audit returned HTTP $HTTP_STATUS (expected 200)" >&2
  exit 1
fi

python3 - "$ARTIFACT_DIR" "$AURA_CORE_VERSION" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
expected_version = sys.argv[2]
request = json.loads((out / "request.json").read_text())
response = json.loads((out / "response.json").read_text())
lines = (out / "audit.jsonl").read_text().splitlines()

assert response["schema"] == "aura-guard.audit.v2", response
assert response["decision"] == "ALLOW", response.get("decision")
assert response["policy_set"] == request["policy_set"]
assert response["context"] == request["context"]
assert response["seq"] == 1
assert response["request_id"] == "gate4-external-black-box"
assert response["core_measurement"]["status"] == "COMPLETED"
assert response["core_measurement"]["ari"] == 100000
assert response["core_measurement"]["drift"] == 0
assert response["core_measurement"]["evaluator_version"] == expected_version
for field in ("measurement_input_hash",):
    digest = response["core_measurement"][field]
    assert isinstance(digest, str) and len(digest) == 64, (field, digest)
for field in ("input_hash", "shadow_hash", "chain_hash", "prev_hash", "policy_hash"):
    digest = response[field]
    assert isinstance(digest, str) and len(digest) == 64, (field, digest)

assert len(lines) == 1, f"expected one persisted JSONL entry, found {len(lines)}"
persisted = json.loads(lines[0])
assert persisted == response, "HTTP response and persisted JSONL record differ"
assert persisted["core_measurement"] == response["core_measurement"]
# Prompt and response remain privacy-minimized: only hashes are stored.
serialized_log = json.dumps(persisted, ensure_ascii=False)
assert request["payload"]["prompt"] not in serialized_log
assert request["payload"]["response"] not in serialized_log

print("GATE4 API ASSERTIONS: PASS")
print(f"HTTP decision: {response['decision']}")
print(f"core_measurement: status={response['core_measurement']['status']}, "
      f"ari={response['core_measurement']['ari']}, drift={response['core_measurement']['drift']}")
print(f"JSONL entries: {len(lines)}; response matches persisted record: true")
PY

"$ROOT_DIR/target/release/aura-replay" \
  --log "$ARTIFACT_DIR/audit.jsonl" \
  --verify-segments \
  --segments-dir "$ARTIFACT_DIR/segments" \
  --json >"$ARTIFACT_DIR/replay.json"

python3 - "$ARTIFACT_DIR" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
summary = json.loads((out / "replay.json").read_text())
manifests = sorted((out / "segments").glob("*.manifest.json"))
assert summary["status"] == "ok", summary
assert summary["entries"] == 1, summary
assert summary["core_measurements"] == 1, summary
assert summary["verified_segments"] is True, summary
assert summary["segments"] == 1, summary
assert len(manifests) == 1, [str(p) for p in manifests]
print("GATE4 INDEPENDENT REPLAY: PASS")
print(json.dumps(summary, sort_keys=True))
print(f"Merkle segment manifests: {len(manifests)}; verifier accepted: true")
PY

echo "GATE4 EXTERNAL BLACK-BOX E2E: PASS"
echo "Evidence artifacts: $ARTIFACT_DIR"
