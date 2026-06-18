#!/usr/bin/env bash
#
# One-shot driver for "single challenge" devnet validation: clean up old
# processes, run setup-tz-mock-devnet.sh, then start the kill-challenger
# watcher in the background so the challenger is shot the moment it
# challenges the first game. After that the proposer is free to defend
# that single game end-to-end without the challenger flooding new ones.
#
# Foreground; prints next steps when ready.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[single-challenge] killing leftover devnet processes (if any)..."
ps -ef | grep -iE "anvil|tz-proposer|tz-challenger" | grep -v grep | awk '{print $2}' | xargs -r kill -9 2>/dev/null || true
sleep 2

if ! curl -fsS -m 3 http://127.0.0.1:10000/chain/confirmed_block_info >/dev/null; then
    echo "ERROR: TZ chain at http://127.0.0.1:10000 is not reachable." >&2
    echo "       Start the TZ node first, then rerun this script." >&2
    exit 2
fi

# setup-tz-mock-devnet.sh checks for its own SP1_CORE_RUNNER_OVERRIDE_BINARY
# trap. Unset to avoid the stale-path failure documented in CLAUDE.md.
unset SP1_CORE_RUNNER_OVERRIDE_BINARY

echo "[single-challenge] running setup-tz-mock-devnet.sh (START_SERVICES=1)..."
START_SERVICES=1 "${SCRIPT_DIR}/setup-tz-mock-devnet.sh"

echo
echo "[single-challenge] starting kill-challenger watcher in background..."
# Log under dev/data (in-domain workspace) rather than /tmp — corp
# sandbox sometimes denies /tmp writes from sub-shells.
WATCHER_LOG="${WORKSPACE_ROOT:-$(pwd)}/dev/data/kill-challenger.log"
mkdir -p "$(dirname "${WATCHER_LOG}")"
nohup "${SCRIPT_DIR}/kill-challenger-after-first.sh" \
    >"${WATCHER_LOG}" 2>&1 &
watcher_pid="$!"
echo "[single-challenge] watcher PID=${watcher_pid} (log: ${WATCHER_LOG})"

echo
echo "[single-challenge] devnet is up. Watcher will SIGKILL the challenger as"
echo "                   soon as it emits its first [MALICIOUS CHALLENGE]."
echo
echo "Tail proposer for the range→agg→proof submit chain:"
echo "  tail -f dev/data/tz-proposer.log | grep --line-buffered -E 'Captured execution|Generating aggregation|proof submitted|Game resolved'"
