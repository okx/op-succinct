#!/usr/bin/env bash
# Defender lookup-endpoint matrix, part 1: the cases in which the endpoint must NOT be listening.
# No set -e — failures accumulate so one bad probe cannot hide the rest of the matrix.
set -uo pipefail
FAILURES=0
TZ_DEFENDER="${TZ_DEFENDER_BIN:-./target/debug/tz-defender}"
DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_OUT="${TEST_OUT_DIR:-$DIR/test_output}"
mkdir -p "$TEST_OUT"

cleanup() {
  [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

# Check that no listener is bound to the given port.
# Exit 7  = connection refused (PASS — no listener).
# Exit 28 = timeout (FAIL — port may be firewalled).
# Anything else = FAIL.
check_no_listener() {
  local label="$1" port="$2"
  curl -sS --connect-timeout 2 --max-time 3 \
    "http://127.0.0.1:${port}/signer/get?refOrderId=probe" >/dev/null 2>&1
  local curl_exit=$?
  case $curl_exit in
    7)  echo "PASS ${label} (exit 7 — connection refused)"; return 0 ;;
    28) echo "FAIL ${label}: timeout (exit 28 — not refused)"; return 1 ;;
    *)  echo "FAIL ${label}: curl exit=$curl_exit (expected 7)"; return 1 ;;
  esac
}

# T1: No signer env (no XLAYER_SIGNER_ENABLED)
echo "=== T1: No signer ==="
"$TZ_DEFENDER" --env-file "$DIR/test_no_signer.env" > "$TEST_OUT/t1a.log" 2>&1 &
PID=$!
sleep 4
if kill -0 "$PID" 2>/dev/null; then
  echo "PASS T1-A (process alive, no signer)"
else
  echo "FAIL T1-A: process died"
  FAILURES=$((FAILURES+1))
fi
check_no_listener "T1-B" 19876 || FAILURES=$((FAILURES+1))
kill "$PID" 2>/dev/null; wait 2>/dev/null; unset PID

# T2: Disabled gate (XLAYER_SIGNER_ENABLED=false)
echo "=== T2: Disabled gate ==="
"$TZ_DEFENDER" --env-file "$DIR/test_disabled_gate.env" > "$TEST_OUT/t2a.log" 2>&1 &
PID=$!
sleep 4
if kill -0 "$PID" 2>/dev/null; then
  echo "PASS T2-A (process alive, signer gate disabled)"
else
  echo "FAIL T2-A: process died"
  FAILURES=$((FAILURES+1))
fi
check_no_listener "T2-B" 19876 || FAILURES=$((FAILURES+1))
kill "$PID" 2>/dev/null; wait 2>/dev/null; unset PID

# T3: Empty verify addr
echo "=== T3: Empty verify addr ==="
"$TZ_DEFENDER" --env-file "$DIR/test_signer_empty_verify.env" > "$TEST_OUT/t3a.log" 2>&1 &
PID=$!
sleep 4
if kill -0 "$PID" 2>/dev/null; then
  echo "PASS T3-A (process alive, empty verify addr)"
else
  echo "FAIL T3-A: process died"
  FAILURES=$((FAILURES+1))
fi
check_no_listener "T3-B" 19876 || FAILURES=$((FAILURES+1))
kill "$PID" 2>/dev/null; wait 2>/dev/null; unset PID

echo "=== No-listener results: $FAILURES failure(s) ==="
exit $FAILURES