#!/usr/bin/env bash
#
# Defender signer-gate matrix, part 2: the refOrderId lookup endpoint itself.
#
#   T4   signer enabled with a configured address -> the endpoint is served
#   T5a  GET without refOrderId            -> HTTP 400, code 1
#   T5b  GET with an empty refOrderId      -> HTTP 400, code 1 (identical to T5a)
#   T5c  POST                              -> HTTP 405, code 1
#   T5d  GET with an ID this process issued -> code 0 (skipped here, see below)
#   T5e  GET with an unknown ID            -> HTTP 200, code 1
#   T5f  every response carries the five documented envelope fields
#
# T5d needs the running process to have issued a refOrderID, which requires a live signing round
# trip against the asset-management service. The cache is process-local and has no wire-level way
# to seed it, so the hit case is covered by the Rust integration tests that call the test-only
# seeding bridge on the same client (see tests/tz_defender_integration.rs). It is reported as SKIP
# here rather than silently dropped.
#
# Exit status: 0 when every case passes, otherwise the number of failed cases.
#
# Note: errexit is deliberately NOT enabled. A matrix accumulates failures; aborting on the first
# failing probe would hide the rest of the matrix.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
PORT="${TZ_DEFENDER_TEST_PORT:-18081}"
BASE="http://127.0.0.1:${PORT}"
READY_TIMEOUT="${TZ_DEFENDER_TEST_READY_TIMEOUT:-30}"
WORK_DIR="$(mktemp -d)"
PID=""

FAILURES=0
SKIPPED=0
fail() {
    echo "FAIL $1: $2"
    FAILURES=$((FAILURES + 1))
}
pass() { echo "PASS $1"; }
skip() {
    echo "SKIP $1: $2"
    SKIPPED=$((SKIPPED + 1))
}

cleanup() {
    if [ -n "${PID}" ]; then
        kill "${PID}" 2>/dev/null
        wait "${PID}" 2>/dev/null
    fi
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT INT TERM

resolve_bin() {
    if [ -n "${TZ_DEFENDER_BIN:-}" ]; then
        printf '%s' "${TZ_DEFENDER_BIN}"
        return
    fi
    local prebuilt="${REPO_ROOT}/target/debug/tz-defender"
    if [ ! -x "${prebuilt}" ]; then
        echo "building tz-defender (no prebuilt binary at ${prebuilt})"
        ( cd "${REPO_ROOT}" && cargo build --bin tz-defender --features tz ) || return 1
    fi
    printf '%s' "${prebuilt}"
}

port_answers() {
    curl -sS --max-time 2 -o /dev/null "${BASE}/signer/get?refOrderId=probe" 2>/dev/null
}

# Extracts the numeric `code` field from a response body. Prints nothing when the field is absent.
code_of() {
    grep -o '"code":[0-9]*' <<< "$1" | head -1 | cut -d: -f2
}

# Asserts the HTTP status and the envelope `code` of one request.
expect() { # name url expected_status expected_code [curl args...]
    local name="$1" url="$2" want_status="$3" want_code="$4"
    shift 4
    local body status code
    body="$(curl -sS --max-time 5 -w '\n%{http_code}' "$@" "${url}" 2>&1)"
    status="$(tail -1 <<< "${body}")"
    body="$(sed '$d' <<< "${body}")"
    code="$(code_of "${body}")"
    if [ "${status}" != "${want_status}" ] || [ "${code}" != "${want_code}" ]; then
        fail "${name}" "expected HTTP ${want_status}/code ${want_code}, got HTTP ${status}/code '${code}' body=${body}"
    else
        pass "${name} (HTTP ${status}, code ${code})"
    fi
}

BIN="$(resolve_bin)" || { echo "FATAL: cannot obtain the tz-defender binary"; exit 1; }
echo "binary: ${BIN}"
echo "port:   ${PORT}"
echo

if port_answers; then
    echo "FATAL: ${BASE} is already served before any test ran; stop the process using it"
    exit 1
fi

# T4: the endpoint is served when the signer is enabled and an address is configured.
echo "=== T4: endpoint is served ==="
{
    echo "DEFENDER_L2_RPC=http://127.0.0.1:18545"
    echo "DEFENDER_CHALLENGE_CONTRACT=0x0000000000000000000000000000000000000000"
    echo "DEFENDER_ROOT_MANAGER=0x0000000000000000000000000000000000000000"
    echo "DEFENDER_WB_ENDPOINT=http://127.0.0.1:18546"
    echo "DEFENDER_TZ_CHAIN_ID=2882"
    echo "DEFENDER_FINALITY_BLOCKS=0"
    echo "XLAYER_SIGNER_ENABLED=true"
    echo "XLAYER_SIGNER_REF_ORDER_PREFIX=DEFENDER_LOCAL_PROBE"
    echo "XLAYER_SIGNER_ENDPOINT=http://127.0.0.1:19999"
    echo "XLAYER_SIGNER_ADDRESS=0x0000000000000000000000000000000000000000"
    echo "XLAYER_ACCESS_KEY=local-placeholder"
    echo "XLAYER_SECRET_KEY=0000000000000000000000000000000000000000000000000000000000000000"
    echo "XLAYER_SIGNER_VERIFY_ADDR=127.0.0.1:${PORT}"
} > "${WORK_DIR}/listener.env"

"${BIN}" --env-file "${WORK_DIR}/listener.env" > "${WORK_DIR}/server.log" 2>&1 &
PID=$!

if timeout "${READY_TIMEOUT}" bash -c "while ! curl -sS --max-time 1 -o /dev/null '${BASE}/signer/get?refOrderId=probe' 2>/dev/null; do sleep 1; done"; then
    pass "T4 endpoint ready on ${BASE}"
else
    fail "T4" "endpoint did not answer within ${READY_TIMEOUT}s (see ${WORK_DIR}/server.log)"
    echo "--- server log ---"
    cat "${WORK_DIR}/server.log"
    echo "=== Done: ${FAILURES} failure(s), ${SKIPPED} skipped ==="
    exit "${FAILURES}"
fi
echo

echo "=== T5a: missing refOrderId ==="
expect "T5a" "${BASE}/signer/get" 400 1
echo

echo "=== T5b: empty refOrderId ==="
expect "T5b" "${BASE}/signer/get?refOrderId=" 400 1
echo

echo "=== T5c: unsupported method ==="
expect "T5c" "${BASE}/signer/get?refOrderId=x" 405 1 -X POST
echo

echo "=== T5d: known refOrderId ==="
skip "T5d" "the cache is process-local and has no wire-level seeding; the hit case is covered by the Rust integration tests"

echo
echo "=== T5e: unknown refOrderId ==="
expect "T5e" "${BASE}/signer/get?refOrderId=never-issued-$(date +%s)" 200 1
echo

echo "=== T5f: response envelope fields ==="
BODY="$(curl -sS --max-time 5 "${BASE}/signer/get?refOrderId=envelope-probe")"
for field in status code msg detailMsg data; do
    if grep -q "\"${field}\":" <<< "${BODY}"; then
        pass "T5f/${field}"
    else
        fail "T5f/${field}" "field missing from body=${BODY}"
    fi
done
echo

echo "=== Done: ${FAILURES} failure(s), ${SKIPPED} skipped ==="
exit "${FAILURES}"