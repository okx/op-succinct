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

# Step 2 — Stop host gracefully
HOST_PID="$(pgrep -f xlayer-tee-host || true)"
if [ -n "${HOST_PID}" ]; then
    kill -TERM "${HOST_PID}"
    echo "SIGTERM sent to xlayer-tee-host (pid=${HOST_PID}), waiting up to ${GRACE_PERIOD}s..."

    ELAPSED=0
    while kill -0 "${HOST_PID}" 2>/dev/null && [ "${ELAPSED}" -lt "${GRACE_PERIOD}" ]; do
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done

    if kill -0 "${HOST_PID}" 2>/dev/null; then
        kill -9 "${HOST_PID}"
        echo "xlayer-tee-host force-killed after ${GRACE_PERIOD}s"
    else
        echo "xlayer-tee-host exited gracefully"
    fi
else
    echo "xlayer-tee-host not running"
fi
