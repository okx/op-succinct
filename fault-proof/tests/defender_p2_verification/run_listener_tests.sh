#!/usr/bin/env bash
# Defender lookup-endpoint matrix, part 2: the endpoint itself, plus the startup-validation cases.
#   T5a-T5e  a deliberately invalid environment must stop startup with the specific diagnostic and
#            must not leave a listener behind.
#   T4       a valid environment serves the endpoint: known-ID hit, unknown-ID miss, HEAD, 404,
#            empty parameter, wrong method, and the illegal-JSON negative control.
# No set -e — failures accumulate.
set -uo pipefail
FAILURES=0
TZ_DEFENDER="${TZ_DEFENDER_BIN:-./target/debug/tz-defender}"
DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_OUT="${TEST_OUT_DIR:-$DIR/test_output}"
mkdir -p "$TEST_OUT"
KNOWN_ID="${KNOWN_ID:-CHALLENGER_TZ_99_9999_ffffffff}"

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

# Reusable jq-based structural assertion.
# Checks all 5 field names, their exact types, code value, and data=null.
# Returns failure count as exit code (0 = all assertions passed).
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

# ===================================================================
# T5: startup-validation error tests (T5a-T5e)
# Each: start with a bad env, require the process to exit non-zero on its
# own, require no listener, and require the specific diagnostic in the log.
# ===================================================================
T5_DEADLINE=15  # seconds — startup validation is near-instant
T5_LOG_DIR="$TEST_OUT/t5_startup"
rm -rf "$T5_LOG_DIR" && mkdir -p "$T5_LOG_DIR"

run_t5_test() {
  local t5_label="$1" t5_env_file="$2" t5_log="$3" t5_error_pattern="$4"
  local t5_log_path="$T5_LOG_DIR/${t5_log}"

  echo "=== ${t5_label}: starting with ${t5_env_file} ==="
  "$TZ_DEFENDER" --env-file "$DIR/${t5_env_file}" > "$t5_log_path" 2>&1 &
  local t5_pid=$!

  local t5_start=$(date +%s)
  local t5_deadline=$((t5_start + T5_DEADLINE))
  local t5_exited=0
  while [ "$(date +%s)" -lt "$t5_deadline" ]; do
    if ! kill -0 "$t5_pid" 2>/dev/null; then
      t5_exited=1
      break
    fi
    sleep 1
  done

  if [ "$t5_exited" -eq 0 ]; then
    echo "FAIL ${t5_label}: process still alive at ${T5_DEADLINE}s deadline"
    kill "$t5_pid" 2>/dev/null
    wait "$t5_pid" 2>/dev/null
    return 1
  fi

  local t5_rc=0
  wait "$t5_pid" 2>/dev/null || t5_rc=$?
  if [ "$t5_rc" -eq 0 ]; then
    echo "FAIL ${t5_label}: process exited 0 (expected non-zero)"
    return 1
  fi

  check_no_listener "${t5_label}-no-listener" 19876 || return 1

  if grep -qE "$t5_error_pattern" "$t5_log_path" 2>/dev/null; then
    echo "PASS ${t5_label}: exited $t5_rc, no listener on 19876, log has expected error"
    return 0
  else
    echo "FAIL ${t5_label}: log missing expected error pattern ($t5_error_pattern)"
    echo "  Log tail:"; tail -20 "$t5_log_path" | sed 's/^/    /'
    return 1
  fi
}

# T5a: no XLAYER_SIGNER_REF_ORDER_PREFIX
run_t5_test "T5a" "test_signer_no_prefix.env" \
  "t5a_no_prefix.log" \
  "XLAYER_SIGNER_REF_ORDER_PREFIX is required when XLAYER_SIGNER_ENABLED=true" \
  || FAILURES=$((FAILURES+1))

# T5b: empty XLAYER_SIGNER_REF_ORDER_PREFIX
run_t5_test "T5b" "test_signer_empty_prefix.env" \
  "t5b_empty_prefix.log" \
  "XLAYER_SIGNER_REF_ORDER_PREFIX must not be empty" \
  || FAILURES=$((FAILURES+1))

# T5c: bad XLAYER_SIGNER_REF_ORDER_PREFIX (contains "!")
run_t5_test "T5c" "test_signer_bad_prefix.env" \
  "t5c_bad_prefix.log" \
  "only ASCII alphanumeric and underscore allowed" \
  || FAILURES=$((FAILURES+1))

# T5d: no XLAYER_SIGNER_ENDPOINT
run_t5_test "T5d" "test_signer_no_endpoint.env" \
  "t5d_no_endpoint.log" \
  "XLAYER_SIGNER_ENDPOINT is required when XLAYER_SIGNER_ENABLED=true" \
  || FAILURES=$((FAILURES+1))

# T5e: bad XLAYER_SIGNER_ADDRESS
run_t5_test "T5e" "test_signer_bad_address.env" \
  "t5e_bad_address.log" \
  "Failed to parse XLAYER_SIGNER_ADDRESS" \
  || FAILURES=$((FAILURES+1))

# ===================================================================
# T4: Real listener tests (only if the full signer config works)
# ===================================================================
echo "=== T4: Real listener tests ==="
XLAYER_TEST_SEED_REF_ORDER_ID="$KNOWN_ID" \
  "$TZ_DEFENDER" --env-file "$DIR/test_signer_full.env" > "$TEST_OUT/t4_defender.log" 2>&1 &
PID=$!

if ! wait_ready 19876 "$PID" "T4-defender"; then
  FAILURES=$((FAILURES+1))
else
  # T4-good: the ID seeded through the wired signer path → HTTP 200, code=0
  HTTP_RESP=$(curl -sS -w '\n%{http_code}' --connect-timeout 2 --max-time 5 \
    "http://127.0.0.1:19876/signer/get?refOrderId=${KNOWN_ID}")
  CURL_EXIT=$?
  HTTP_STATUS=$(echo "$HTTP_RESP" | tail -n 1)
  JSON_BODY=$(echo "$HTTP_RESP" | sed '$d')
  if [ "$CURL_EXIT" -eq 0 ] && [ "$HTTP_STATUS" = "200" ]; then
    assert_verify_fields "$JSON_BODY" "T4-good" "0"
    ASSERT_RC=$?
    if [ "$ASSERT_RC" -eq 0 ]; then
      echo "PASS T4-good (known ID confirmed, code=0, envelope well formed)"
    else
      FAILURES=$((FAILURES + ASSERT_RC))
    fi
  else
    echo "FAIL T4-good: curl=$CURL_EXIT HTTP=$HTTP_STATUS"
    FAILURES=$((FAILURES+1))
  fi

  # T4-unknown: an ID this process never issued → HTTP 200, code=1
  HTTP_RESP2=$(curl -sS -w '\n%{http_code}' --connect-timeout 2 --max-time 5 \
    "http://127.0.0.1:19876/signer/get?refOrderId=UNKNOWN_99_9999_deadbeef")
  CURL_EXIT2=$?
  HTTP_STATUS2=$(echo "$HTTP_RESP2" | tail -n 1)
  JSON_BODY2=$(echo "$HTTP_RESP2" | sed '$d')
  if [ "$CURL_EXIT2" -eq 0 ] && [ "$HTTP_STATUS2" = "200" ]; then
    assert_verify_fields "$JSON_BODY2" "T4-unknown" "1"
    ASSERT_RC=$?
    if [ "$ASSERT_RC" -eq 0 ]; then
      echo "PASS T4-unknown (unissued ID not confirmed, code=1, envelope well formed)"
    else
      FAILURES=$((FAILURES + ASSERT_RC))
    fi
  else
    echo "FAIL T4-unknown: curl=$CURL_EXIT2 HTTP=$HTTP_STATUS2"
    FAILURES=$((FAILURES+1))
  fi

  # T4-HEAD: the endpoint answers every method with 405; the transport strips the body from a HEAD
  # response, so the observable result is HTTP 405 with zero downloaded bytes.
  HEAD_FILE=$(mktemp)
  HEAD_CURL_OUT=$(curl -sS -I \
    -o /dev/null \
    -D "$HEAD_FILE" \
    -w '%{http_code} %{size_download}' \
    --connect-timeout 2 --max-time 5 \
    "http://127.0.0.1:19876/signer/get?refOrderId=${KNOWN_ID}" 2>&1)
  CURL_EXIT3=$?
  HEAD_PASS=0
  if [ "$CURL_EXIT3" -eq 0 ]; then
    HTTP_CODE=$(echo "$HEAD_CURL_OUT" | awk '{print $1}')
    BODY_SIZE=$(echo "$HEAD_CURL_OUT" | awk '{print $2}')
    if [ "$HTTP_CODE" = "405" ] && [ "$BODY_SIZE" = "0" ]; then
      HEAD_PASS=1
    fi
  fi
  if [ "${HEAD_PASS:-0}" -eq 1 ]; then
    echo "PASS T4-HEAD (HTTP 405, body 0 bytes)"
  else
    echo "FAIL T4-HEAD: curl=$CURL_EXIT3 HTTP=$HTTP_CODE body_size=$BODY_SIZE (expected 405, 0)"
    FAILURES=$((FAILURES+1))
  fi
  rm -f "$HEAD_FILE"

  # T4-missing-path: nonexistent path
  HTTP_STATUS4=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 3 \
    "http://127.0.0.1:19876/signer/nonexistent")
  if [ "$HTTP_STATUS4" = "404" ]; then
    echo "PASS T4-missing-path"
  else
    echo "FAIL T4-missing-path: HTTP=$HTTP_STATUS4 (expected 404)"
    FAILURES=$((FAILURES+1))
  fi

  # T4-empty-param: empty refOrderId is treated exactly like an absent one
  HTTP_STATUS5=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 3 \
    "http://127.0.0.1:19876/signer/get?refOrderId=")
  if [ "$HTTP_STATUS5" = "400" ]; then
    echo "PASS T4-empty-param (empty refOrderId -> 400)"
  else
    echo "FAIL T4-empty-param: HTTP=$HTTP_STATUS5 (expected 400)"
    FAILURES=$((FAILURES+1))
  fi

  # T4-POST: wrong method -> 405 carrying the JSON envelope
  POST_RESP=$(curl -sS -w '\n%{http_code}' --connect-timeout 2 --max-time 5 \
    -X POST "http://127.0.0.1:19876/signer/get?refOrderId=${KNOWN_ID}")
  CURL_EXIT6=$?
  HTTP_STATUS6=$(echo "$POST_RESP" | tail -n 1)
  POST_JSON=$(echo "$POST_RESP" | sed '$d')
  POST_PASS=0
  if [ "$CURL_EXIT6" -eq 0 ] && [ "$HTTP_STATUS6" = "405" ]; then
    if echo "$POST_JSON" | jq -e '.status == 405 and .code == 1' >/dev/null 2>&1; then
      POST_PASS=1
    fi
  fi
  if [ "${POST_PASS:-0}" -eq 1 ]; then
    echo "PASS T4-POST (405 with JSON envelope status=405 code=1)"
  else
    echo "FAIL T4-POST: curl=$CURL_EXIT6 HTTP=$HTTP_STATUS6 (expected 405 + JSON 405 envelope)"
    FAILURES=$((FAILURES+1))
  fi
fi

# --- Negative control: the assertion helper must reject a body that merely looks right ---
echo "=== NEG-CTL: Illegal JSON negative control ==="
ILLEGAL_JSON='{"status":200,"code":1,"msg":"success","detailMsg":"","data":123}'
# Fed to the SAME assertion function with expected_code=0: code=1 != 0 and data=123 is not null,
# so both assertions must fail and the helper must return non-zero.
NEG_OUT=$(mktemp)
assert_verify_fields "$ILLEGAL_JSON" "NEG-CTL" "0" >"$NEG_OUT" 2>&1
NEG_FAILS=$?
cat "$NEG_OUT"
rm -f "$NEG_OUT"
if [ "$NEG_FAILS" -ne 0 ]; then
  echo "PASS NEG-CTL: illegal JSON correctly rejected ($NEG_FAILS failure(s))"
else
  echo "FAIL NEG-CTL: illegal JSON passed assertion"
  FAILURES=$((FAILURES+1))
fi

cleanup
unset PID

echo "=== Listener results (T4+T5): $FAILURES failure(s) ==="
exit $FAILURES