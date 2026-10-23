#!/usr/bin/env bash
#
# Defender signer-gate matrix, part 1: the cases in which the refOrderId lookup endpoint must
# NOT be listening.
#
#   T1  XLAYER_SIGNER_ENABLED unset      -> no signer, no listener, supervisor loop reached
#   T2  XLAYER_SIGNER_ENABLED=false      -> no signer, no listener, supervisor loop reached
#   T3  XLAYER_SIGNER_ENABLED=true with an empty XLAYER_SIGNER_VERIFY_ADDR
#                                        -> signer built, no listener, supervisor loop reached
#
# The companion script run_listener_tests.sh covers the case in which the endpoint is served.
#
# The process is expected to reach its supervisor loop and stay there; the L2 RPC and the witness
# builder in the generated environment are deliberately unreachable, so the binary logs connection
# errors and keeps looping. Every run is therefore bounded with `timeout` and a run that exits
# before the bound is a failure unless the case expects a startup abort (none do here).
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
RUN_SECONDS="${TZ_DEFENDER_TEST_RUN_SECONDS:-5}"
WORK_DIR="$(mktemp -d)"
PID=""

FAILURES=0
fail() {
    echo "FAIL $1: $2"
    FAILURES=$((FAILURES + 1))
}
pass() { echo "PASS $1"; }

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

# Prints whether anything already answers on the test port, so a leftover process cannot be
# mistaken for a listener this binary opened.
port_in_use() {
    curl -sS --max-time 2 -o /dev/null "${BASE}/signer/get?refOrderId=preflight" 2>/dev/null
}

# Writes an environment file for the Defender. Only the variables the binary actually reads are
# set; the credential values are local placeholders that unlock no service.
write_env() { # dest enabled verify_addr
    local dest="$1" enabled="$2" verify_addr="$3"
    {
        echo "DEFENDER_L2_RPC=http://127.0.0.1:18545"
        echo "DEFENDER_CHALLENGE_CONTRACT=0x0000000000000000000000000000000000000000"
        echo "DEFENDER_ROOT_MANAGER=0x0000000000000000000000000000000000000000"
        echo "DEFENDER_WB_ENDPOINT=http://127.0.0.1:18546"
        echo "DEFENDER_TZ_CHAIN_ID=2882"
        echo "DEFENDER_FINALITY_BLOCKS=0"
        if [ -n "${enabled}" ]; then
            echo "XLAYER_SIGNER_ENABLED=${enabled}"
        fi
        echo "XLAYER_SIGNER_REF_ORDER_PREFIX=DEFENDER_LOCAL_PROBE"
        echo "XLAYER_SIGNER_ENDPOINT=http://127.0.0.1:19999"
        echo "XLAYER_SIGNER_ADDRESS=0x0000000000000000000000000000000000000000"
        echo "XLAYER_ACCESS_KEY=local-placeholder"
        echo "XLAYER_SECRET_KEY=0000000000000000000000000000000000000000000000000000000000000000"
        echo "XLAYER_SIGNER_VERIFY_ADDR=${verify_addr}"
    } > "${dest}"
}

# Runs one no-listener case: starts the binary, lets it settle, then requires that (a) the process
# is still running and reached the supervisor loop and (b) nothing answers on the test port.
no_listener_case() { # name env_file log_file
    local name="$1" env_file="$2" log="$3"
    timeout "${RUN_SECONDS}" "$(resolve_bin)" --env-file "${env_file}" > "${log}" 2>&1 &
    PID=$!
    sleep 3

    if ! kill -0 "${PID}" 2>/dev/null; then
        fail "${name}" "process exited before the supervisor loop (see ${log})"
        PID=""
        return
    fi
    if ! grep -q "entering supervisor loop" "${log}"; then
        fail "${name}" "supervisor loop not reached (see ${log})"
    fi
    if port_in_use; then
        fail "${name}" "the lookup endpoint answered on ${BASE} although it must not be served"
    else
        pass "${name}"
    fi

    kill "${PID}" 2>/dev/null
    wait "${PID}" 2>/dev/null
    PID=""
}

BIN="$(resolve_bin)" || { echo "FATAL: cannot obtain the tz-defender binary"; exit 1; }
echo "binary: ${BIN}"
echo "port:   ${PORT}"
echo

if port_in_use; then
    echo "FATAL: ${BASE} is already served before any test ran; stop the process using it"
    exit 1
fi

echo "=== T1: XLAYER_SIGNER_ENABLED unset ==="
write_env "${WORK_DIR}/t1.env" "" ""
no_listener_case "T1 no-signer" "${WORK_DIR}/t1.env" "${WORK_DIR}/t1.log"
echo

echo "=== T2: XLAYER_SIGNER_ENABLED=false ==="
write_env "${WORK_DIR}/t2.env" "false" ""
no_listener_case "T2 disabled" "${WORK_DIR}/t2.env" "${WORK_DIR}/t2.log"
echo

echo "=== T3: enabled, empty XLAYER_SIGNER_VERIFY_ADDR ==="
write_env "${WORK_DIR}/t3.env" "true" ""
no_listener_case "T3 empty-verify-address" "${WORK_DIR}/t3.env" "${WORK_DIR}/t3.log"
echo

echo "=== Done: ${FAILURES} failure(s) ==="
exit "${FAILURES}"