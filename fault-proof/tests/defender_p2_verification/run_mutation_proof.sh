#!/usr/bin/env bash
# Mutation proof for the Defender signer wiring.
#
# The wiring is a single `cfg`-free statement inside `wire_defender_signer_core`, so removing it
# changes every build configuration at once — the delivered binary and the test-utils build alike.
# This script proves that, in legs that each have to be able to fail:
#
#   A2        the wiring statement occurs exactly ONCE. A partial mutation (the old `sed` range
#             rewrote only the first of two copies) would prove nothing, so a count other than 1
#             aborts the run instead of producing a verdict.
#   BASELINE  the named Rust case passes on the unmutated tree.
#   A3        with the statement removed the PRODUCTION feature set (`--features tz`, no test-utils)
#             still compiles. The deleted line is behavioral, not structural, which is what makes it
#             provable that the delivered binary executes that same line.
#   A5-PREP   the test-utils binary is explicitly rebuilt and bound AFTER A3, because A3 overwrites
#             target/debug/tz-defender with a binary that cannot seed at all. Measuring A5 against
#             that leftover would silently test the wrong binary.
#   A4        the named Rust case compiles, ACTUALLY EXECUTES, and fails ON ITS WIRING ASSERTION.
#   A5-CTL    the known-ID probe is exercised against a local responder with deliberately wrong
#             status/body pairs first. A probe that cannot reject a wrong response cannot support
#             A5 either way, so the controls run before the probe is trusted with a real binary.
#   A5        the process-level known-ID lookup answers the exact 200 / 1 / not found / "" / null
#             envelope where the baseline recorded the exact 200 / 0 / success / "" / null envelope,
#             for the same known ID. Both legs check the probe's real exit code, not just a code
#             scraped out of the body.
#   RESTORE   after restoring byte-identical content, both the Rust case and the binary-driven case
#             are green again.
#
# A compile error, a case that never ran, a failure attributable to a pre-existing broken test, a
# startup or connection failure, a timeout, or a stale binary is NOT mutation evidence. Each of
# those is reported as the obstacle it is and yields an `unverified` verdict rather than a pass.
#
# Run from the repository root.
set -uo pipefail

MUTATION_LOG="docs/superpowers/evidence/gap1-mutation-run.log"
SIGNER_RS="fault-proof/src/tz/defender/signer.rs"
P2_DIR="fault-proof/tests/defender_p2_verification"
# The one shared five-field envelope assertion. This script used to carry a private, weaker parser
# that looked at `code` alone; it now uses the same definition as the listener and binary matrices.
. "$P2_DIR/envelope_assert.sh"
KNOWN_ID="${KNOWN_ID:-CHALLENGER_TZ_99_9999_ffffffff}"
# The exact wiring statement, matched as a fixed string so no regex escaping can drift.
WIRING_STMT='challenge.set_signer(Arc::new(lock.clone()));'
# The assertion the named case must fail on when the wiring is gone. Attribution matters: any other
# failure means the case broke for an unrelated reason and proves nothing about the wiring.
WIRING_ASSERTION='the wiring step attached the signer'
RUST_CASE='shared_construction_ptr_equality'

mkdir -p "$(dirname "$MUTATION_LOG")" "$P2_DIR/test_output"
PRISTINE_SHA=$(sha256sum "$SIGNER_RS" | awk '{print $1}')

restore_and_rebuild() {
  echo "=== trap: restoring ${SIGNER_RS} ==="
  git checkout "$SIGNER_RS" 2>&1
  echo "=== trap: rebuilding the test-utils binary after restore ==="
  cargo build --bin tz-defender --features "tz,xlayer-verify-test-utils" 2>&1
  echo "trap restore+rebuild rc=$?"
}
trap restore_and_rebuild EXIT

# Starts the given tz-defender binary with the seed in place, queries the known ID once, and
# validates the WHOLE response in this order:
#   1. the request itself succeeded (curl),
#   2. the HTTP status is 200,
#   3. all five envelope fields EXIST, checked separately from their values, and then each carries
#      its exact expected value — through `assert_verify_fields`, the single shared definition in
#      envelope_assert.sh, which is the same assertion the listener and binary matrices use.
#
# `ENVELOPE_CODE=<code>` is emitted ONLY when every one of those checks passes. Otherwise the marker
# is `invalid` (a response arrived and was wrong) or `unavailable` (no usable response arrived at
# all), and the return code says which check failed:
#
#   0  the expected envelope, exactly
#   2  the binary is missing or not executable
#   3  the process exited before the endpoint was ready
#   4  readiness timed out
#   5  the lookup request failed (connection refused, timeout, ...)
#   6  the HTTP status was not 200
#   7  the envelope failed the five-field assertion
#
# Codes 2-5 are obstacles and are never mutation evidence; 6 and 7 are real negative results.
#
# The earlier version of this function printed the HTTP status, read `.code` out of the body, and
# then returned 0 unconditionally. Two false passes were reproduced through it: HTTP 500 carrying
# `{"code":0}` satisfied the baseline leg, and HTTP 500 carrying `{"code":1}` satisfied the mutated
# leg. Printing the full response is not the same as checking it, so every check below is separate,
# every failure has its own exit code, and the callers test that exit code.
#
# Usage: probe_known_id <binary|-> <label> <log> <expected_code> <expected_msg> [base_url]
# Passing `-` as the binary skips process startup and queries <base_url> directly. That is how the
# controls exercise THIS function rather than a copy of it.
probe_known_id() {
  if [ "$#" -lt 5 ]; then
    echo "FAIL probe_known_id: expected at least 5 arguments, got $# — a call site was not updated"
    echo "ENVELOPE_CODE=unavailable"
    return 2
  fi
  local binary="$1" label="$2" log="$3" expected_code="$4" expected_msg="$5"
  local base_url="${6:-http://127.0.0.1:19876}"
  local pid="" deadline ready=0 resp curl_rc status body code assert_out assert_rc

  if [ "$binary" != "-" ]; then
    if [ ! -x "$binary" ]; then
      echo "$label: binary $binary is missing or not executable — lookup UNAVAILABLE"
      echo "ENVELOPE_CODE=unavailable"
      return 2
    fi

    XLAYER_TEST_SEED_REF_ORDER_ID="$KNOWN_ID" \
      "$binary" --env-file "$P2_DIR/test_signer_full.env" > "$log" 2>&1 &
    pid=$!

    deadline=$(($(date +%s) + 30))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      if ! kill -0 "$pid" 2>/dev/null; then
        echo "$label: the process exited before the endpoint was ready — lookup UNAVAILABLE"
        echo "  log tail:"; tail -10 "$log" | sed 's/^/    /'
        echo "ENVELOPE_CODE=unavailable"
        return 3
      fi
      if curl -sS --connect-timeout 2 --max-time 3 \
           "${base_url}/signer/get?refOrderId=health" >/dev/null 2>&1; then
        ready=1
        break
      fi
      sleep 1
    done

    if [ "$ready" -ne 1 ]; then
      echo "$label: timed out waiting for the lookup endpoint — lookup UNAVAILABLE"
      kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
      echo "ENVELOPE_CODE=unavailable"
      return 4
    fi
  fi

  # 1. The request itself.
  resp=$(curl -sS -w '\n%{http_code}' --connect-timeout 2 --max-time 5 \
    "${base_url}/signer/get?refOrderId=${KNOWN_ID}")
  curl_rc=$?
  if [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
  fi
  if [ "$curl_rc" -ne 0 ]; then
    echo "$label: the lookup request failed (curl exit $curl_rc) — lookup UNAVAILABLE"
    echo "ENVELOPE_CODE=unavailable"
    return 5
  fi

  status=$(echo "$resp" | tail -n 1)
  body=$(echo "$resp" | sed '$d')
  echo "$label: HTTP $status"
  echo "$label: envelope $(echo "$body" | jq -c . 2>/dev/null || echo "$body")"

  # 2. The HTTP status, on its own. A 500 that happens to carry the expected `code` is not a correct
  #    answer, and the absence of exactly this check is what produced the reported false passes.
  if [ "$status" != "200" ]; then
    echo "$label: HTTP status is $status (expected 200) — envelope INVALID"
    echo "ENVELOPE_CODE=invalid"
    return 6
  fi

  # 3. Field existence, then exact values, through the one shared assertion.
  assert_out=$(mktemp)
  assert_verify_fields "$body" "$label" 200 "$expected_code" "$expected_msg" \
    >"$assert_out" 2>&1
  assert_rc=$?
  sed 's/^/  /' "$assert_out"
  rm -f "$assert_out"
  if [ "$assert_rc" -ne 0 ]; then
    echo "$label: the envelope failed $assert_rc five-field assertion(s) — envelope INVALID"
    echo "ENVELOPE_CODE=invalid"
    return 7
  fi

  # The marker reports the code actually read back out of the validated body, not the expectation.
  code=$(echo "$body" | jq -r '.code | tostring')
  echo "$label: envelope matches exactly 200 / ${expected_code} / ${expected_msg} / \"\" / null"
  echo "ENVELOPE_CODE=${code}"
  return 0
}

# Runs one control through the real probe against a fixed-response local service.
#
# A non-zero probe result is not by itself evidence that a check was exercised: a connection
# problem is also non-zero. So each control pins BOTH the exact expected return code (which names
# the check that must have fired) and the marker, and a responder that never comes up is reported
# as unverified rather than as a working control.
#
# Usage: run_a5_control <name> <http-status> <body> <want-rc> <want-marker> <exp-code> <exp-msg>
run_a5_control() {
  local name="$1" http_status="$2" ctl_body="$3" want_rc="$4" want_marker="$5"
  local exp_code="$6" exp_msg="$7"
  local ctl_pid ctl_ready=0 ctl_deadline out rc marker

  "$CTL_PYTHON" "$CTL_RESPONDER" "$CTL_PORT" "$http_status" "$ctl_body" \
    > "$CTL_LOG_DIR/${name}.responder.log" 2>&1 &
  ctl_pid=$!
  # Readiness is a COMPLETE request/response exchange, not a bare TCP open: the responder serves
  # one connection at a time, and leaving a response unread would hand it a half-closed socket
  # right before the probe's own request.
  ctl_deadline=$(($(date +%s) + 10))
  while [ "$(date +%s)" -lt "$ctl_deadline" ]; do
    kill -0 "$ctl_pid" 2>/dev/null || break
    if curl -sS -o /dev/null --connect-timeout 2 --max-time 3 \
         "http://127.0.0.1:${CTL_PORT}/readiness" >/dev/null 2>&1; then
      ctl_ready=1
      break
    fi
    sleep 1
  done
  if [ "$ctl_ready" -ne 1 ]; then
    echo "FAIL ${name}: the control responder never became reachable — UNVERIFIED, not a pass"
    kill "$ctl_pid" 2>/dev/null; wait "$ctl_pid" 2>/dev/null
    return 1
  fi

  out=$(mktemp)
  probe_known_id - "$name" "$CTL_LOG_DIR/${name}.probe-stdout.log" \
    "$exp_code" "$exp_msg" "http://127.0.0.1:${CTL_PORT}" >"$out" 2>&1
  rc=$?
  marker=$(grep '^ENVELOPE_CODE=' "$out" | tail -1 | cut -d= -f2)
  sed 's/^/    /' "$out"
  cp "$out" "$CTL_LOG_DIR/${name}.probe.log"
  rm -f "$out"
  kill "$ctl_pid" 2>/dev/null; wait "$ctl_pid" 2>/dev/null

  echo "  served: HTTP ${http_status} body ${ctl_body}"
  if [ "$rc" -eq "$want_rc" ] && [ "$marker" = "$want_marker" ]; then
    echo "PASS ${name}: probe rc=$rc marker=$marker (the required check fired)"
    return 0
  fi
  echo "FAIL ${name}: probe rc=$rc marker=$marker (expected rc=$want_rc marker=$want_marker)"
  return 1
}

{
  echo "=== Signer wiring mutation run $(date -u) ==="
  echo "Mutation target: the single cfg-free wiring statement in wire_defender_signer_core"
  echo "Pristine ${SIGNER_RS} sha256=${PRISTINE_SHA}"
  echo ""

  # ---- A2: the wiring statement must occur exactly once ----
  echo "--- A2: wiring-statement occurrence count ---"
  OCCURRENCES=$(grep -c -F "$WIRING_STMT" "$SIGNER_RS")
  echo "Occurrences of '${WIRING_STMT}' in ${SIGNER_RS}: ${OCCURRENCES}"
  if [ "$OCCURRENCES" -ne 1 ]; then
    echo "FAIL: expected exactly 1 wiring statement, found $OCCURRENCES — mutation would be partial"
    echo "Verdict: OPEN (wiring not consolidated)"
    exit 1
  fi
  echo "A2 PASS: exactly one wiring statement, so one mutation covers every configuration"

  # ---- A5-CTL: the known-ID probe must be able to fail, and for the right reason ----
  echo ""
  echo "--- A5-CTL: controls for the known-ID probe, against a fixed-response local service ---"
  CTL_PORT=19879
  CTL_RESPONDER="$P2_DIR/envelope_control_responder.py"
  CTL_LOG_DIR="$P2_DIR/test_output/a5_controls"
  CTL_PYTHON=$(command -v python3 || true)
  rm -rf "$CTL_LOG_DIR" && mkdir -p "$CTL_LOG_DIR"
  A5_CTL_FAILURES=0

  if [ -z "$CTL_PYTHON" ] || [ ! -f "$CTL_RESPONDER" ]; then
    echo "FAIL: python3 or ${CTL_RESPONDER} is unavailable, so the probe cannot be controlled."
    echo "      A5 would then rest on an unexercised check."
    echo "Verdict: unverified (A5 probe controls could not run)"
    exit 1
  fi

  # Negative — the two responses the review reproduced as false passes. The status check must fire
  # first (rc=6) for both, so neither a `code:0` nor a `code:1` body can be accepted over HTTP 500.
  run_a5_control "A5-CTL-NEG-http500-code0" 500 '{"code":0}' 6 invalid 0 "success" \
    || A5_CTL_FAILURES=$((A5_CTL_FAILURES+1))
  run_a5_control "A5-CTL-NEG-http500-code1" 500 '{"code":1}' 6 invalid 1 "not found" \
    || A5_CTL_FAILURES=$((A5_CTL_FAILURES+1))

  # Negative — a 200 whose envelope is wrong must fail the five-field assertion (rc=7).
  run_a5_control "A5-CTL-NEG-missing-field" 200 \
    '{"status":200,"code":0,"msg":"success","data":null}' 7 invalid 0 "success" \
    || A5_CTL_FAILURES=$((A5_CTL_FAILURES+1))
  run_a5_control "A5-CTL-NEG-wrong-msg" 200 \
    '{"status":200,"code":0,"msg":"wrong","detailMsg":"","data":null}' 7 invalid 0 "success" \
    || A5_CTL_FAILURES=$((A5_CTL_FAILURES+1))
  run_a5_control "A5-CTL-NEG-missing-data" 200 \
    '{"status":200,"code":0,"msg":"success","detailMsg":""}' 7 invalid 0 "success" \
    || A5_CTL_FAILURES=$((A5_CTL_FAILURES+1))
  # Negative — the mutated leg must not accept a still-found envelope for the known ID.
  run_a5_control "A5-CTL-NEG-mutated-sees-found" 200 \
    '{"status":200,"code":0,"msg":"success","detailMsg":"","data":null}' 7 invalid 1 "not found" \
    || A5_CTL_FAILURES=$((A5_CTL_FAILURES+1))

  # Positive — the two envelopes the real legs are allowed to accept, and nothing else.
  run_a5_control "A5-CTL-POS-found" 200 \
    '{"status":200,"code":0,"msg":"success","detailMsg":"","data":null}' 0 0 0 "success" \
    || A5_CTL_FAILURES=$((A5_CTL_FAILURES+1))
  run_a5_control "A5-CTL-POS-not-found" 200 \
    '{"status":200,"code":1,"msg":"not found","detailMsg":"","data":null}' 0 1 1 "not found" \
    || A5_CTL_FAILURES=$((A5_CTL_FAILURES+1))

  echo "A5-CTL failures: ${A5_CTL_FAILURES} (expected 0; 6 negative + 2 positive controls)"
  if [ "$A5_CTL_FAILURES" -ne 0 ]; then
    echo "FAIL: the known-ID probe does not reject what it must reject, or rejects what it must"
    echo "      accept — A5 cannot be evidence either way until the probe itself is sound."
    echo "Verdict: unverified (A5 probe controls failed)"
    exit 1
  fi
  echo "A5-CTL PASS: the probe rejects a wrong status, a missing field and a wrong value, each for"
  echo "             its own reason, and accepts exactly the two legal envelopes"

  # ---- BASELINE: the named case must pass before anything is mutated ----
  echo ""
  echo "--- BASELINE: named Rust case on the unmutated tree (expects pass) ---"
  BASE_RUST_OUT=$(mktemp)
  cargo test -p op-succinct-fp --features "tz,xlayer-verify-test-utils" \
    --test tz_defender_integration -- "$RUST_CASE" 2>&1 | tee "$BASE_RUST_OUT"
  BASELINE_RUST_RC=${PIPESTATUS[0]}
  echo "Baseline Rust case rc=$BASELINE_RUST_RC"

  # The Rust legs need the package's dev-dependencies. If one of those fails to compile for a
  # reason this change does not own, the Rust legs are BLOCKED: they are recorded as unverified
  # with the real obstacle and never counted as evidence either way. The production-side legs
  # (A2/A3/A5), which do not need dev-dependencies, still run so the round is not evidence-free.
  RUST_LEGS_BLOCKED=0
  BLOCKING_CRATE=""
  if [ "$BASELINE_RUST_RC" -ne 0 ] && grep -qE '^error: could not compile `[^`]+`' "$BASE_RUST_OUT"
  then
    BLOCKING_CRATE=$(grep -oE '^error: could not compile `[^`]+`' "$BASE_RUST_OUT" | head -1 \
      | sed 's/.*`\(.*\)`/\1/')
    # Only a crate other than the one under change can be a pre-existing external obstacle.
    if [ "$BLOCKING_CRATE" != "op-succinct-fp" ]; then
      RUST_LEGS_BLOCKED=1
      echo "BLOCKED: the Rust legs cannot compile because dev-dependency '${BLOCKING_CRATE}'"
      echo "         fails to build. That is an out-of-scope, pre-existing obstacle: the Rust legs"
      echo "         (baseline and A4) are recorded as UNVERIFIED, not as pass and not as failure."
    fi
  fi

  if [ "$RUST_LEGS_BLOCKED" -eq 0 ]; then
    if [ "$BASELINE_RUST_RC" -ne 0 ]; then
      echo "FAIL: the named case does not pass on the unmutated tree — nothing can be attributed"
      echo "Verdict: unverified (no usable baseline)"
      rm -f "$BASE_RUST_OUT"
      exit 1
    fi
    if ! grep -qE '1 passed' "$BASE_RUST_OUT"; then
      echo "FAIL: the baseline run did not report a passing case — it may never have executed"
      echo "Verdict: unverified (baseline case did not execute)"
      rm -f "$BASE_RUST_OUT"
      exit 1
    fi
    echo "BASELINE PASS: ${RUST_CASE} executed and passed"
  fi
  rm -f "$BASE_RUST_OUT"

  # ---- BASELINE A5: the known-ID lookup must answer a full correct 200 envelope with code=0 ----
  echo ""
  echo "--- BASELINE A5: known-ID lookup on the unmutated test-utils binary (expects code=0) ---"
  cargo build --bin tz-defender --features "tz,xlayer-verify-test-utils" 2>&1
  BASELINE_BUILD_RC=$?
  if [ "$BASELINE_BUILD_RC" -ne 0 ]; then
    echo "FAIL: the unmutated test-utils binary does not build"
    echo "Verdict: unverified (baseline build failure)"
    exit 1
  fi
  BASE_PROBE=$(mktemp)
  probe_known_id "./target/debug/tz-defender" "BASELINE-A5" \
    "$P2_DIR/test_output/mutation_baseline.log" 0 "success" 2>&1 | tee "$BASE_PROBE"
  BASELINE_PROBE_RC=${PIPESTATUS[0]}
  BASELINE_CODE=$(grep '^ENVELOPE_CODE=' "$BASE_PROBE" | tail -1 | cut -d= -f2)
  rm -f "$BASE_PROBE"
  echo "Baseline probe rc=${BASELINE_PROBE_RC} envelope code=${BASELINE_CODE}"
  # The exit code is the authoritative result: it is what says the status and all five fields were
  # checked. The marker is reported alongside it, never instead of it.
  if [ "$BASELINE_PROBE_RC" -ne 0 ] || [ "$BASELINE_CODE" != "0" ]; then
    echo "FAIL: the baseline known-ID lookup did not answer the exact 200 / 0 / success / \"\" /"
    echo "      null envelope (probe rc=${BASELINE_PROBE_RC}, marker='${BASELINE_CODE}')"
    echo "Verdict: unverified (no usable A5 baseline)"
    exit 1
  fi
  echo "BASELINE A5 PASS: the known ID answers the full correct envelope 200 / 0 / success /"
  echo "                  \"\" / null before mutation"

  # ---- Step 1: apply the mutation to the single wiring statement ----
  echo ""
  echo "--- Applying the mutation ---"
  sed -i "s|^\( *\)${WIRING_STMT}|\1// ${WIRING_STMT} // MUTATION|" "$SIGNER_RS"
  MUTATED_COUNT=$(grep -c -F "// ${WIRING_STMT} // MUTATION" "$SIGNER_RS")
  LIVE_COUNT=$(grep -F "$WIRING_STMT" "$SIGNER_RS" | grep -vc '// MUTATION')
  echo "Commented-out wiring statements: ${MUTATED_COUNT}; live wiring statements left: ${LIVE_COUNT}"
  if [ "$MUTATED_COUNT" -ne 1 ] || [ "$LIVE_COUNT" -ne 0 ]; then
    echo "FAIL: the mutation did not land cleanly on the single wiring statement"
    echo "Verdict: OPEN (mutation failed to apply)"
    exit 1
  fi
  echo "MUTATION VERIFIED: the one wiring statement is commented out"

  # ---- A3: the PRODUCTION feature set must still compile ----
  echo ""
  echo "--- A3: production build with the mutation (no test-utils; expects compile success) ---"
  cargo build --bin tz-defender --features tz 2>&1
  PROD_BUILD_RC=$?
  echo "Production build rc=$PROD_BUILD_RC"
  if [ "$PROD_BUILD_RC" -ne 0 ]; then
    echo "FAIL: the production feature set no longer compiles — the mutation is structural, so it"
    echo "      cannot demonstrate a behavioral change in the delivered binary"
    echo "Verdict: unverified (production build failure)"
    exit 1
  fi
  echo "A3 PASS: the delivered feature set compiles without the wiring statement, so that statement"
  echo "         is behavioral and is the same line the delivered binary executes"

  # ---- A5-PREP: rebuild and bind the test-utils binary that A3 just overwrote ----
  echo ""
  echo "--- A5-PREP: rebuilding the test-utils binary that the production build overwrote ---"
  cargo build --bin tz-defender --features "tz,xlayer-verify-test-utils" 2>&1
  BUILD_RC=$?
  echo "Test-utils build rc=$BUILD_RC"
  if [ "$BUILD_RC" -ne 0 ]; then
    echo "FAIL: the mutated test-utils build failed with rc=$BUILD_RC"
    echo "Verdict: unverified (mutated test-utils build failure)"
    exit 1
  fi
  MUTATED_BIN="./target/debug/tz-defender"
  echo "Bound A5 binary: ${MUTATED_BIN} (mtime $(date -u -r "$MUTATED_BIN" '+%Y-%m-%dT%H:%M:%SZ'))"

  # ---- A4: the named Rust case must execute and fail on the wiring assertion ----
  echo ""
  echo "--- A4: named Rust case with the mutation (expects an executed, attributable failure) ---"
  if [ "$RUST_LEGS_BLOCKED" -eq 1 ]; then
    echo "SKIPPED: dev-dependency '${BLOCKING_CRATE}' does not compile, so A4 cannot be executed."
    echo "         Recorded as UNVERIFIED. Not a pass."
    RUST_RC="blocked"
    RUST_EXECUTED=0
    RUST_ATTRIBUTED=0
  else
  MUT_RUST_OUT=$(mktemp)
  cargo test -p op-succinct-fp --features "tz,xlayer-verify-test-utils" \
    --test tz_defender_integration -- "$RUST_CASE" 2>&1 | tee "$MUT_RUST_OUT"
  RUST_RC=${PIPESTATUS[0]}
  echo "Mutated Rust case rc=$RUST_RC"

  RUST_EXECUTED=0
  RUST_ATTRIBUTED=0
  if grep -qE "error(\[E[0-9]+\])?:" "$MUT_RUST_OUT" && grep -q 'error: could not compile' \
       "$MUT_RUST_OUT"; then
    echo "NOTE: the mutated tree failed to COMPILE — a compile error is not mutation evidence"
  else
    if grep -qE "^test .*${RUST_CASE}.* \.\.\. FAILED" "$MUT_RUST_OUT" && \
       grep -qE '[0-9]+ failed' "$MUT_RUST_OUT"; then
      RUST_EXECUTED=1
    fi
    if grep -qF "$WIRING_ASSERTION" "$MUT_RUST_OUT"; then
      RUST_ATTRIBUTED=1
    fi
  fi
  echo "Mutated Rust case executed=${RUST_EXECUTED} attributed_to_wiring=${RUST_ATTRIBUTED}"
  rm -f "$MUT_RUST_OUT"
  fi

  # ---- A5: the process-level known-ID lookup must flip to code=1 ----
  echo ""
  echo "--- A5: known-ID lookup on the mutated test-utils binary (expects code=1) ---"
  MUT_PROBE=$(mktemp)
  probe_known_id "$MUTATED_BIN" "MUTATED-A5" "$P2_DIR/test_output/mutation_mutated.log" \
    1 "not found" 2>&1 | tee "$MUT_PROBE"
  MUTATED_PROBE_RC=${PIPESTATUS[0]}
  MUTATED_CODE=$(grep '^ENVELOPE_CODE=' "$MUT_PROBE" | tail -1 | cut -d= -f2)
  rm -f "$MUT_PROBE"
  echo "Mutated probe rc=${MUTATED_PROBE_RC} envelope code=${MUTATED_CODE}"

  # ---- The binary-driven matrix must also fail under mutation ----
  echo ""
  # Corroboration only. Its non-zero return says "something in the two-instance matrix broke", not
  # "the known ID answered a correct not-found envelope", so it never stands in for A5 above.
  echo "--- Binary-driven case with the mutation (expects failure) ---"
  TZ_DEFENDER_BIN="$MUTATED_BIN" \
    TEST_OUT_DIR="$P2_DIR/test_output/mutation" \
    "$P2_DIR/run_gap1_binary_test.sh" 2>&1
  BINARY_RC=$?
  echo "Binary-driven case rc=$BINARY_RC"

  # ---- Restore and rebuild ----
  echo ""
  echo "--- Restoring the wiring statement ---"
  git checkout "$SIGNER_RS"
  RESTORED_SHA=$(sha256sum "$SIGNER_RS" | awk '{print $1}')
  echo "Restored ${SIGNER_RS} sha256=${RESTORED_SHA}"
  if [ "$RESTORED_SHA" != "$PRISTINE_SHA" ]; then
    echo "FAIL: the restored file is not byte-identical to the pristine content"
    echo "Verdict: unverified (restore is not byte-identical)"
    exit 1
  fi
  echo "Restore is byte-identical to the pristine content"

  cargo build --bin tz-defender --features "tz,xlayer-verify-test-utils" 2>&1
  RESTORE_BUILD_RC=$?
  echo "Restore build rc=$RESTORE_BUILD_RC"
  if [ "$RESTORE_BUILD_RC" -ne 0 ]; then
    echo "FAIL: the restored tree does not build — later results cannot be trusted"
    echo "Verdict: unverified (restore build failure)"
    exit 1
  fi

  # ---- Both cases must be green again ----
  echo ""
  echo "--- Binary-driven case after restore (expects pass) ---"
  TZ_DEFENDER_BIN=./target/debug/tz-defender \
    TEST_OUT_DIR="$P2_DIR/test_output/restored" \
    "$P2_DIR/run_gap1_binary_test.sh" 2>&1
  RESTORED_RC=$?
  echo "Restored binary-driven case rc=$RESTORED_RC"

  echo ""
  echo "--- Rust case after restore (expects pass) ---"
  if [ "$RUST_LEGS_BLOCKED" -eq 1 ]; then
    echo "SKIPPED: dev-dependency '${BLOCKING_CRATE}' does not compile — UNVERIFIED, not a pass."
    RESTORED_RUST_RC="blocked"
  else
    cargo test -p op-succinct-fp --features "tz,xlayer-verify-test-utils" \
      --test tz_defender_integration -- "$RUST_CASE" 2>&1
    RESTORED_RUST_RC=$?
    echo "Restored Rust case rc=$RESTORED_RUST_RC"
  fi

  # ---- Verdict, derived only from what was actually observed ----
  echo ""
  echo "=== Mutation evidence ==="
  echo "A2 occurrences=$OCCURRENCES (expected 1)"
  echo "BASELINE_RUST_RC=$BASELINE_RUST_RC (expected 0)"
  echo "A5_CTL_FAILURES=$A5_CTL_FAILURES (expected 0 — 6 negative + 2 positive probe controls)"
  echo "BASELINE_PROBE_RC=$BASELINE_PROBE_RC (expected 0 — full 200/0/success envelope)"
  echo "BASELINE_CODE=$BASELINE_CODE (expected 0)"
  echo "PROD_BUILD_RC=$PROD_BUILD_RC (expected 0 — A3)"
  echo "BUILD_RC=$BUILD_RC (expected 0 — mutated test-utils build)"
  echo "RUST_RC=$RUST_RC (expected != 0 — A4)"
  echo "RUST_EXECUTED=$RUST_EXECUTED (expected 1 — A4)"
  echo "RUST_ATTRIBUTED=$RUST_ATTRIBUTED (expected 1 — A4, failed on the wiring assertion)"
  echo "MUTATED_PROBE_RC=$MUTATED_PROBE_RC (expected 0 — full 200/1/not found envelope — A5)"
  echo "MUTATED_CODE=$MUTATED_CODE (expected 1 — A5)"
  echo "BINARY_RC=$BINARY_RC (expected != 0)"
  echo "RESTORE_BUILD_RC=$RESTORE_BUILD_RC (expected 0)"
  echo "RESTORED_RC=$RESTORED_RC (expected 0)"
  echo "RESTORED_RUST_RC=$RESTORED_RUST_RC (expected 0)"
  echo ""

  if [ "$RUST_LEGS_BLOCKED" -eq 1 ]; then
    echo "Verdict: unverified (the Rust legs are blocked by the pre-existing dev-dependency"
    echo "         failure in '${BLOCKING_CRATE}', which this change does not own and must not"
    echo "         modify to force green). Evidence that WAS obtained this run:"
    echo "           A2 single wiring statement       : occurrences=$OCCURRENCES"
    echo "           A3 production build w/o wiring   : rc=$PROD_BUILD_RC"
    echo "           A5 probe controls (6 neg, 2 pos) : failures=$A5_CTL_FAILURES"
    echo "           A5 baseline known-ID lookup      : probe_rc=$BASELINE_PROBE_RC code=$BASELINE_CODE"
    echo "           A5 mutated known-ID lookup       : probe_rc=$MUTATED_PROBE_RC code=$MUTATED_CODE"
    echo "           binary-driven matrix (mutated)   : rc=$BINARY_RC"
    echo "           binary-driven matrix (restored)  : rc=$RESTORED_RC"
    echo "           restore byte-identical           : yes"
    exit 1
  fi

  # An obstacle and a wrong answer are different outcomes and must not collapse into one verdict.
  case "$MUTATED_PROBE_RC" in
    0) : ;;
    2|3|4|5)
      echo "Verdict: unverified (the mutated lookup never produced a usable response — missing"
      echo "         binary, startup, connection or timeout obstacle, rc=$MUTATED_PROBE_RC. That is"
      echo "         not mutation evidence)"
      exit 1
      ;;
    *)
      echo "Verdict: wiring mutation is NOT DETECTED (the mutated lookup answered, but not with the"
      echo "         exact 200 / 1 / not found / \"\" / null envelope A5 requires — probe"
      echo "         rc=$MUTATED_PROBE_RC, marker='${MUTATED_CODE}')"
      exit 1
      ;;
  esac

  if [ "$A5_CTL_FAILURES" -eq 0 ] && [ "$BASELINE_PROBE_RC" -eq 0 ] && \
     [ "$PROD_BUILD_RC" -eq 0 ] && [ "$BUILD_RC" -eq 0 ] && \
     [ "$RUST_RC" -ne 0 ] && [ "$RUST_EXECUTED" -eq 1 ] && [ "$RUST_ATTRIBUTED" -eq 1 ] && \
     [ "$MUTATED_PROBE_RC" -eq 0 ] && [ "$MUTATED_CODE" = "1" ] && [ "$BINARY_RC" -ne 0 ] && \
     [ "$RESTORE_BUILD_RC" -eq 0 ] && [ "$RESTORED_RC" -eq 0 ] && \
     [ "$RESTORED_RUST_RC" -eq 0 ]; then
    echo "Verdict: wiring mutation is DETECTED in both configurations"
    echo "  production: compiles without the statement (so it executes that same statement)"
    echo "  mutated:    rust_rc=$RUST_RC on the wiring assertion, known-ID full envelope"
    echo "              200/1/not found (probe rc=$MUTATED_PROBE_RC, code=$MUTATED_CODE),"
    echo "              binary_rc=$BINARY_RC"
    echo "  restored:   byte-identical, binary_rc=$RESTORED_RC rust_rc=$RESTORED_RUST_RC"
  else
    echo "Verdict: wiring mutation is NOT DETECTED"
    exit 1
  fi
} | tee "$MUTATION_LOG"
