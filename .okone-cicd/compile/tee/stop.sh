#!/usr/bin/env bash
set -euo pipefail

# Must match start.sh.
ENCLAVE_CID="${ENCLAVE_CID:-4}"

GRACE_PERIOD=1800

# Step 1 — Terminate enclave
ENCLAVE_ID="$(nitro-cli describe-enclaves \
    | jq -r --argjson cid "${ENCLAVE_CID}" '.[] | select(.EnclaveCID == $cid) | .EnclaveID' \
    || true)"
if [ -n "${ENCLAVE_ID}" ]; then
    nitro-cli terminate-enclave --enclave-id "${ENCLAVE_ID}"
    echo "enclave terminated: ${ENCLAVE_ID}"
else
    echo "no enclave with cid=${ENCLAVE_CID} found"
fi

# Step 2 — Stop host gracefully.
# pgrep can return multiple PIDs (e.g. a dev instance running alongside prod).
# Keep the unquoted expansion below so each PID becomes its own argument to
# kill; quoting "${HOST_PIDS}" would pass a single multi-line string and bash
# kill would reject it as a bad pid.
HOST_PIDS="$(pgrep -f xlayer-tee-host || true)"
if [ -n "${HOST_PIDS}" ]; then
    # shellcheck disable=SC2086
    kill -TERM ${HOST_PIDS}
    echo "SIGTERM sent to xlayer-tee-host pids: ${HOST_PIDS}; waiting up to ${GRACE_PERIOD}s..."

    ELAPSED=0
    # Loop until every PID is gone or we hit the grace period.
    while [ "${ELAPSED}" -lt "${GRACE_PERIOD}" ]; do
        STILL_ALIVE=""
        for pid in ${HOST_PIDS}; do
            if kill -0 "${pid}" 2>/dev/null; then
                STILL_ALIVE="${STILL_ALIVE} ${pid}"
            fi
        done
        [ -z "${STILL_ALIVE}" ] && break
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done

    # Anyone still alive after the grace period gets SIGKILL.
    for pid in ${HOST_PIDS}; do
        if kill -0 "${pid}" 2>/dev/null; then
            kill -9 "${pid}"
            echo "xlayer-tee-host (pid=${pid}) force-killed after ${GRACE_PERIOD}s"
        fi
    done
    echo "xlayer-tee-host shutdown complete"
else
    echo "xlayer-tee-host not running"
fi
