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

# The normative five-field envelope assertion lives in one place only, so the copies cannot drift
# apart and no consumer can fall back to a weaker parser of its own.
. "$DIR/envelope_assert.sh"

# HEAD on the route must answer 405, advertise `Allow: GET`, and send a zero-byte body.
#
# `curl -I` cannot produce that evidence: it issues a HEAD and never reads a response body, so
# `%{size_download}` is structurally 0 whatever the server actually sent — a control service that
# answers with a 5-byte body and no `Allow` header still reports `405 0`. So the raw response is
# read straight off the socket, the header/body separator is located, and the bytes after it are
# counted with the real byte count.
#
# Usage: assert_head_405_no_body <host> <port> <path> <label>
# Returns the number of failed assertions (0 = every assertion passed).
assert_head_405_no_body() {
  local host="$1" port="$2" path="$3" label="$4"
  local raw status_line allow_value total header_len body_bytes fails=0
  raw=$(mktemp)

  if ! {
    printf 'HEAD %s HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n' \
      "$path" "$host" "$port" >&3
    timeout 5 cat <&3 > "$raw"
  } 3<>"/dev/tcp/${host}/${port}" 2>/dev/null; then
    echo "FAIL $label: could not read a raw response from ${host}:${port}"
    rm -f "$raw"
    return 1
  fi

  status_line=$(head -1 "$raw" | tr -d '\r')
  case "$status_line" in
    *" 405 "*|*" 405") : ;;
    *)
      echo "FAIL $label: status line is '$status_line' (expected HTTP 405)"
      fails=$((fails+1))
      ;;
  esac

  allow_value=$(LC_ALL=C grep -i '^Allow:' "$raw" | head -1 | tr -d '\r')
  case "$allow_value" in
    *GET*) : ;;
    *)
      echo "FAIL $label: Allow header does not advertise GET (got '${allow_value:-<absent>}')"
      fails=$((fails+1))
      ;;
  esac

  # Bytes up to and including the blank line that ends the headers, then whatever follows it.
  header_len=$(LC_ALL=C awk '{ n += length($0) + 1 } /^\r?$/ { print n; exit }' "$raw")
  total=$(wc -c < "$raw" | tr -d ' ')
  if [ -z "$header_len" ]; then
    echo "FAIL $label: the response carries no header/body separator"
    fails=$((fails+1))
  else
    body_bytes=$((total - header_len))
    [ "$body_bytes" -lt 0 ] && body_bytes=0
    if [ "$body_bytes" -ne 0 ]; then
      echo "FAIL $label: body is $body_bytes byte(s) by raw count (expected 0)"
      fails=$((fails+1))
    fi
  fi

  if [ "$fails" -eq 0 ]; then
    echo "PASS $label (HTTP 405, Allow advertises GET, 0-byte body by raw count)"
  fi
  rm -f "$raw"
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
    assert_verify_fields "$JSON_BODY" "T4-good" 200 0 "success"
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
    assert_verify_fields "$JSON_BODY2" "T4-unknown" 200 1 "not found"
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

  # T4-HEAD: the endpoint answers every non-GET method with 405, advertises the methods it serves,
  # and a HEAD response carries no body. All three are asserted against the raw socket response, so
  # the byte count is measured rather than inferred from curl's HEAD bookkeeping.
  assert_head_405_no_body "127.0.0.1" "19876" "/signer/get?refOrderId=${KNOWN_ID}" "T4-HEAD"
  HEAD_RC=$?
  if [ "$HEAD_RC" -ne 0 ]; then
    FAILURES=$((FAILURES + HEAD_RC))
  fi

  # T4-missing-path: nonexistent path
  HTTP_STATUS4=$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 3 \
    "http://127.0.0.1:19876/signer/nonexistent")
  if [ "$HTTP_STATUS4" = "404" ]; then
    echo "PASS T4-missing-path"
  else
    echo "FAIL T4-missing-path: HTTP=$HTTP_STATUS4 (expected 404)"
    FAILURES=$((FAILURES+1))
  fi

  # T4-bad-request: an empty refOrderId is treated exactly like an absent one. This case gets the
  # same full five-field assertions as the 200 cases.
  HTTP_RESP5=$(curl -sS -w '\n%{http_code}' --connect-timeout 2 --max-time 5 \
    "http://127.0.0.1:19876/signer/get?refOrderId=")
  CURL_EXIT5=$?
  HTTP_STATUS5=$(echo "$HTTP_RESP5" | tail -n 1)
  JSON_BODY5=$(echo "$HTTP_RESP5" | sed '$d')
  if [ "$CURL_EXIT5" -eq 0 ] && [ "$HTTP_STATUS5" = "400" ]; then
    assert_verify_fields "$JSON_BODY5" "T4-bad-request" 400 1 "refOrderId is required"
    ASSERT_RC=$?
    if [ "$ASSERT_RC" -eq 0 ]; then
      echo "PASS T4-bad-request (empty refOrderId -> 400, envelope exact)"
    else
      FAILURES=$((FAILURES + ASSERT_RC))
    fi
  else
    echo "FAIL T4-bad-request: curl=$CURL_EXIT5 HTTP=$HTTP_STATUS5 (expected 400)"
    FAILURES=$((FAILURES+1))
  fi

  # T4-POST: wrong method -> 405 carrying the full five-field envelope, asserted exactly.
  POST_RESP=$(curl -sS -w '\n%{http_code}' --connect-timeout 2 --max-time 5 \
    -X POST "http://127.0.0.1:19876/signer/get?refOrderId=${KNOWN_ID}")
  CURL_EXIT6=$?
  HTTP_STATUS6=$(echo "$POST_RESP" | tail -n 1)
  POST_JSON=$(echo "$POST_RESP" | sed '$d')
  if [ "$CURL_EXIT6" -eq 0 ] && [ "$HTTP_STATUS6" = "405" ]; then
    assert_verify_fields "$POST_JSON" "T4-POST" 405 1 "method not allowed"
    ASSERT_RC=$?
    if [ "$ASSERT_RC" -eq 0 ]; then
      echo "PASS T4-POST (405 with the exact five-field envelope)"
    else
      FAILURES=$((FAILURES + ASSERT_RC))
    fi
  else
    echo "FAIL T4-POST: curl=$CURL_EXIT6 HTTP=$HTTP_STATUS6 (expected 405 + JSON 405 envelope)"
    FAILURES=$((FAILURES+1))
  fi
fi

# ===================================================================
# Controls for the assertion helpers themselves.
#
# An acceptance assertion that cannot fail is worse than no assertion, so the helpers are exercised
# directly: every wrong envelope below must be rejected, every real envelope must be accepted, and
# the HEAD check must report FAIL against a deliberately wrong responder.
# ===================================================================

# expect_helper_reject <json> <label> <expected_status> <expected_code> <expected_msg>
# The helper must return non-zero for a body that must not pass.
expect_helper_reject() {
  local json="$1" label="$2" want_status="$3" want_code="$4" want_msg="$5"
  local out rc
  out=$(mktemp)
  assert_verify_fields "$json" "$label" "$want_status" "$want_code" "$want_msg" >"$out" 2>&1
  rc=$?
  sed 's/^/    /' "$out"
  rm -f "$out"
  if [ "$rc" -ne 0 ]; then
    echo "PASS $label: correctly rejected ($rc failed assertion(s))"
    return 0
  fi
  echo "FAIL $label: a wrong envelope passed the assertion — the helper admits a false pass"
  return 1
}

# expect_helper_accept <json> <label> <expected_status> <expected_code> <expected_msg>
# The helper must return zero for the exact real envelope of that case.
expect_helper_accept() {
  local json="$1" label="$2" want_status="$3" want_code="$4" want_msg="$5"
  local out rc
  out=$(mktemp)
  assert_verify_fields "$json" "$label" "$want_status" "$want_code" "$want_msg" >"$out" 2>&1
  rc=$?
  sed 's/^/    /' "$out"
  rm -f "$out"
  if [ "$rc" -eq 0 ]; then
    echo "PASS $label: real envelope accepted"
    return 0
  fi
  echo "FAIL $label: the real envelope was rejected ($rc failed assertion(s))"
  return 1
}

echo "=== CTL-NEG: the helper must reject every wrong envelope ==="

# Wrong status value: a type-only check would have let 999 through.
expect_helper_reject '{"status":999,"code":0,"msg":"success","detailMsg":"","data":null}' \
  "CTL-NEG-wrong-status" 200 0 "success" || FAILURES=$((FAILURES+1))

# Wrong msg value.
expect_helper_reject '{"status":200,"code":0,"msg":"wrong","detailMsg":"","data":null}' \
  "CTL-NEG-wrong-msg" 200 0 "success" || FAILURES=$((FAILURES+1))

# Missing `data` key: in jq a missing key reads as null, so `.data == null` alone would pass.
expect_helper_reject '{"status":200,"code":0,"msg":"success","detailMsg":""}' \
  "CTL-NEG-missing-data" 200 0 "success" || FAILURES=$((FAILURES+1))

# Missing `detailMsg` key.
expect_helper_reject '{"status":200,"code":0,"msg":"success","data":null}' \
  "CTL-NEG-missing-detailMsg" 200 0 "success" || FAILURES=$((FAILURES+1))

# The exact body that produced a false pass against the previous type-only helper.
expect_helper_reject '{"status":999,"code":0,"msg":"wrong","detailMsg":"wrong"}' \
  "CTL-NEG-known-false-pass" 200 0 "success" || FAILURES=$((FAILURES+1))

# Wrong code.
expect_helper_reject '{"status":200,"code":1,"msg":"success","detailMsg":"","data":null}' \
  "CTL-NEG-wrong-code" 200 0 "success" || FAILURES=$((FAILURES+1))

# Non-null `data`.
expect_helper_reject '{"status":200,"code":0,"msg":"success","detailMsg":"","data":123}' \
  "CTL-NEG-nonnull-data" 200 0 "success" || FAILURES=$((FAILURES+1))

# The original illegal-JSON control: wrong code and non-null data at once.
expect_helper_reject '{"status":200,"code":1,"msg":"success","detailMsg":"","data":123}' \
  "CTL-NEG-illegal-json" 200 0 "success" || FAILURES=$((FAILURES+1))

echo "=== CTL-POS: the helper must accept the real envelope of every case ==="

expect_helper_accept '{"status":200,"code":0,"msg":"success","detailMsg":"","data":null}' \
  "CTL-POS-found" 200 0 "success" || FAILURES=$((FAILURES+1))

expect_helper_accept '{"status":200,"code":1,"msg":"not found","detailMsg":"","data":null}' \
  "CTL-POS-not-found" 200 1 "not found" || FAILURES=$((FAILURES+1))

expect_helper_accept \
  '{"status":400,"code":1,"msg":"refOrderId is required","detailMsg":"","data":null}' \
  "CTL-POS-bad-request" 400 1 "refOrderId is required" || FAILURES=$((FAILURES+1))

expect_helper_accept \
  '{"status":405,"code":1,"msg":"method not allowed","detailMsg":"","data":null}' \
  "CTL-POS-method-not-allowed" 405 1 "method not allowed" || FAILURES=$((FAILURES+1))

# --- CTL-HEAD-NEG: the HEAD check must FAIL against a deliberately wrong responder ---
echo "=== CTL-HEAD-NEG: HEAD check against a control that answers with a body and no Allow ==="
HEAD_CTL_PY="$DIR/head_negative_control.py"
HEAD_CTL_PORT=19878
HEAD_CTL_PYTHON=$(command -v python3 || true)
if [ -z "$HEAD_CTL_PYTHON" ]; then
  echo "FAIL CTL-HEAD-NEG: python3 not available — the HEAD check is UNVERIFIED, not passing"
  FAILURES=$((FAILURES+1))
else
  "$HEAD_CTL_PYTHON" "$HEAD_CTL_PY" "$HEAD_CTL_PORT" \
    > "$TEST_OUT/head_negative_control.log" 2>&1 &
  HEAD_CTL_PID=$!
  HEAD_CTL_READY=0
  HEAD_CTL_DEADLINE=$(($(date +%s) + 10))
  while [ "$(date +%s)" -lt "$HEAD_CTL_DEADLINE" ]; do
    if ! kill -0 "$HEAD_CTL_PID" 2>/dev/null; then
      break
    fi
    if (echo >"/dev/tcp/127.0.0.1/${HEAD_CTL_PORT}") >/dev/null 2>&1; then
      HEAD_CTL_READY=1
      break
    fi
    sleep 1
  done

  if [ "$HEAD_CTL_READY" -ne 1 ]; then
    echo "FAIL CTL-HEAD-NEG: the control service never became reachable — UNVERIFIED"
    FAILURES=$((FAILURES+1))
  else
    CTL_HEAD_OUT=$(mktemp)
    assert_head_405_no_body "127.0.0.1" "$HEAD_CTL_PORT" "/signer/get?refOrderId=probe" \
      "CTL-HEAD-NEG-inner" >"$CTL_HEAD_OUT" 2>&1
    CTL_HEAD_RC=$?
    sed 's/^/    /' "$CTL_HEAD_OUT"
    # A non-zero result is not enough: a connection or timeout problem would also be non-zero and
    # would make an unexercised check look like a working one. The control only counts when the
    # two defects it actually carries are the findings reported.
    CTL_SAW_ALLOW=0
    CTL_SAW_BODY=0
    grep -q 'Allow header does not advertise GET' "$CTL_HEAD_OUT" && CTL_SAW_ALLOW=1
    grep -qE 'body is [1-9][0-9]* byte\(s\) by raw count' "$CTL_HEAD_OUT" && CTL_SAW_BODY=1
    rm -f "$CTL_HEAD_OUT"
    if [ "$CTL_HEAD_RC" -ne 0 ] && [ "$CTL_SAW_ALLOW" -eq 1 ] && [ "$CTL_SAW_BODY" -eq 1 ]; then
      echo "PASS CTL-HEAD-NEG: reported FAIL on the missing Allow header AND the non-empty body"
    elif [ "$CTL_HEAD_RC" -eq 0 ]; then
      echo "FAIL CTL-HEAD-NEG: a body-bearing, Allow-less HEAD response passed the check"
      FAILURES=$((FAILURES+1))
    else
      echo "FAIL CTL-HEAD-NEG: the control failed for the wrong reason" \
        "(allow_finding=$CTL_SAW_ALLOW body_finding=$CTL_SAW_BODY) — UNVERIFIED, not a pass"
      FAILURES=$((FAILURES+1))
    fi
  fi
  kill "$HEAD_CTL_PID" 2>/dev/null
  wait "$HEAD_CTL_PID" 2>/dev/null
  unset HEAD_CTL_PID
fi

cleanup
unset PID

echo "=== Listener results (T4+T5): $FAILURES failure(s) ==="
exit $FAILURES