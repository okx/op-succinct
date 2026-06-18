#!/usr/bin/env bash
#
# Watch tz-challenger's log until it emits its first "[MALICIOUS CHALLENGE]"
# message, then SIGKILL the challenger. Pairs with setup-tz-mock-devnet.sh
# when MALICIOUS_CHALLENGE_PERCENTAGE>0 — limits the test run to a single
# challenged game so we can validate the proposer's range→agg→on-chain
# proof path without the challenger flooding every new game.
#
# Run this *after* setup-tz-mock-devnet.sh has started the challenger.
# Foreground; exits as soon as the kill is delivered.
#
# Override the watched log / pid file via env if running a non-default
# layout.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

LOG="${CHALLENGER_LOG:-${WORKSPACE_ROOT}/dev/data/tz-challenger.log}"
PID_FILE="${CHALLENGER_PID:-${WORKSPACE_ROOT}/dev/data/tz-challenger.pid}"
# Wait until the *successful* tx broadcast, not the "Attempting" line —
# SIGKILL-ing mid-broadcast aborts the tx before it lands on L1, so the
# game ends up never actually challenged. The "Game challenged successfully"
# log is emitted by challenger.rs only after the tx is sent + confirmed.
MARKER="${CHALLENGE_MARKER:-Game challenged successfully}"

if [ ! -f "${PID_FILE}" ]; then
    echo "ERROR: PID file not found: ${PID_FILE}" >&2
    echo "       (challenger probably not started yet — run setup-tz-mock-devnet.sh first)" >&2
    exit 2
fi
pid="$(cat "${PID_FILE}")"
if ! kill -0 "${pid}" 2>/dev/null; then
    echo "ERROR: PID ${pid} from ${PID_FILE} is not alive" >&2
    exit 2
fi

echo "[kill-challenger-after-first] watching ${LOG} for '${MARKER}' (challenger PID=${pid})..."

# Poll the log every 2s — fast enough for an interactive validation run.
until grep -q "${MARKER}" "${LOG}" 2>/dev/null; do
    if ! kill -0 "${pid}" 2>/dev/null; then
        echo "[kill-challenger-after-first] PID ${pid} died on its own; nothing to do." >&2
        exit 0
    fi
    sleep 2
done

ts="$(grep "${MARKER}" "${LOG}" | head -1 | head -c 30)"
echo "[kill-challenger-after-first] first challenge detected at ${ts}"
echo "[kill-challenger-after-first] sending SIGKILL to PID ${pid}"
kill -9 "${pid}"
echo "[kill-challenger-after-first] done — proposer will continue defending the challenged game(s)"
