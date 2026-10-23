#!/usr/bin/env bash
# Binary-driven signer-wiring test: two instances, two ports.
#
# Instance A (port 19876) is seeded with KNOWN_ID; instance B (port 19877) is not.
#   - A must answer the known ID with code=0 (the seed travelled through the wired signer);
#   - B must answer the same ID with code=1 (the cache is per process).
#
# The seed path is: XLAYER_TEST_SEED_REF_ORDER_ID -> startup wiring -> set_signer ->
# get_signer() -> lookup target -> seed. If the wiring step is removed, instance A answers
# code=1 for its own known ID and the first assertion fails.
set -uo pipefail
FAILURES=0
TZ_DEFENDER="${TZ_DEFENDER_BIN:-./target/debug/tz-defender}"
KNOWN_ID="${KNOWN_ID:-CHALLENGER_TZ_99_9999_ffffffff}"
DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_OUT="${TEST_OUT_DIR:-$DIR/test_output}"
mkdir -p "$TEST_OUT"

cleanup() {
  [ -n "${PID_A:-}" ] && kill "$PID_A" 2>/dev/null || true
  [ -n "${PID_B:-}" ] && kill "$PID_B" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

# Wait for listener readiness, distinguishing a crashed process from a slow bind.
wait_ready() {
  local port="$1" pid="$2" label="$3"
  local deadline=$(($(date +%s) + 30))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "FAIL $label: process died before ready"
      return 1
    fi
    if curl -sS --connect-timeout 2 --max-time 3 \
         "http://127.0.0.1:${port}/signer/get?refOrderId=health" >/dev/null 2>&1; then
      echo "READY $label (pid=$pid, port=$port)"
      return 0
    fi
    sleep 1
  done
  echo "FAIL $label: timeout waiting for readiness"
  return 1
}

# jq-based structural assertion, shared with the listener matrix.
assert_verify_fields() {
  local json="$1" label="$2" expected_code="$3"
  local fails=0
  echo "$json" | jq -e '.status | type == "number"' >/dev/null 2>&1 \
    || { echo "FAIL $label: missing/invalid status"; fails=$((fails+1)); }
  echo "$json" | jq -e '.code | type == "number"' >/dev/null 2>&1 \
    || { echo "FAIL $label: missing/invalid code"; fails=$((fails+1)); }
  echo "$json" | jq -e '.msg | type == "string"' >/dev/null 2>&1 \
    || { echo "FAIL $label: missing/invalid msg"; fails=$((fails+1)); }
  echo "$json" | jq -e '.detailMsg | type == "string"' >/dev/null 2>&1 \
    || { echo "FAIL $label: missing/invalid detailMsg"; fails=$((fails+1)); }
  local actual_code
  actual_code=$(echo "$json" | jq -r '.code // "MISSING"')
  if [ "$actual_code" != "$expected_code" ]; then
    echo "FAIL $label: code=$actual_code (expected $expected_code)"
    fails=$((fails+1))
  fi
  echo "$json" | jq -e '.data == null' >/dev/null 2>&1 \
    || { echo "FAIL $label: data is not null"; fails=$((fails+1)); }
  return $fails
}

# --- Instance A: seeded, port 19876 ---
echo "=== Gap 1(a): seeded instance A on port 19876 ==="
XLAYER_TEST_SEED_REF_ORDER_ID="$KNOWN_ID" \
  "$TZ_DEFENDER" --env-file "$DIR/test_signer_full.env" \
  > "$TEST_OUT/gap1_instance_a.log" 2>&1 &
PID_A=$!

if wait_ready 19876 "$PID_A" "instance-A"; then
  HTTP_RESP=$(curl -sS -w '\n%{http_code}' --connect-timeout 2 --max-time 5 \
    "http://127.0.0.1:19876/signer/get?refOrderId=${KNOWN_ID}")
  CURL_EXIT=$?
  HTTP_STATUS=$(echo "$HTTP_RESP" | tail -n 1)
  JSON_BODY=$(echo "$HTTP_RESP" | sed '$d')
  if [ "$CURL_EXIT" -eq 0 ] && [ "$HTTP_STATUS" = "200" ]; then
    assert_verify_fields "$JSON_BODY" "Gap1(a)-known-hit" "0"
    ASSERT_RC=$?
    if [ "$ASSERT_RC" -eq 0 ]; then
      echo "PASS Gap1(a)-known-hit (HTTP 200, code=0, envelope well formed)"
    else
      FAILURES=$((FAILURES + ASSERT_RC))
    fi
  else
    echo "FAIL Gap1(a): curl=$CURL_EXIT HTTP=$HTTP_STATUS"
    FAILURES=$((FAILURES+1))
  fi
else
  echo "FAIL Gap1(a): instance A did not start"
  FAILURES=$((FAILURES+1))
fi

# --- Instance B: unseeded, port 19877 ---
echo "=== Gap 1(b): unseeded instance B on port 19877 ==="
"$TZ_DEFENDER" --env-file "$DIR/test_signer_b.env" \
  > "$TEST_OUT/gap1_instance_b.log" 2>&1 &
PID_B=$!

if wait_ready 19877 "$PID_B" "instance-B"; then
  HTTP_RESP2=$(curl -sS -w '\n%{http_code}' --connect-timeout 2 --max-time 5 \
    "http://127.0.0.1:19877/signer/get?refOrderId=${KNOWN_ID}")
  CURL_EXIT2=$?
  HTTP_STATUS2=$(echo "$HTTP_RESP2" | tail -n 1)
  JSON_BODY2=$(echo "$HTTP_RESP2" | sed '$d')
  if [ "$CURL_EXIT2" -eq 0 ] && [ "$HTTP_STATUS2" = "200" ]; then
    assert_verify_fields "$JSON_BODY2" "Gap1(b)-unknown-miss" "1"
    ASSERT_RC=$?
    if [ "$ASSERT_RC" -eq 0 ]; then
      echo "PASS Gap1(b)-unknown-miss (HTTP 200, code=1, envelope well formed)"
    else
      FAILURES=$((FAILURES + ASSERT_RC))
    fi
  else
    echo "FAIL Gap1(b): curl=$CURL_EXIT2 HTTP=$HTTP_STATUS2"
    FAILURES=$((FAILURES+1))
  fi
else
  echo "FAIL Gap1(b): instance B did not start"
  FAILURES=$((FAILURES+1))
fi

echo "=== Gap 1 binary test results: $FAILURES failure(s) ==="
exit $FAILURES