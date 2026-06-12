#!/usr/bin/env bash
set -euo pipefail

# Step 1 — Validate arguments
if [ $# -lt 2 ]; then
    echo "Usage: start.sh <CPU_COUNT> <MEMORY_MB>" >&2
    exit 1
fi

CPU_COUNT="$1"
MEMORY_MB="$2"

# Step 2 — Run enclave
nitro-cli run-enclave \
    --eif-path enclave.eif \
    --cpu-count "${CPU_COUNT}" \
    --memory "${MEMORY_MB}" \
    --enclave-cid 4
echo "enclave started (cid=4)"

# Step 3 — Validate host binary
if [ ! -x ./xlayer-tee-host ]; then
    echo "ERROR: xlayer-tee-host not found or not executable in current directory" >&2
    exit 1
fi

# [A-15 Finding #2] Set default vsock CID/port env vars if not already set
export TEE_HOST__ENCLAVE__VSOCK_CID="${TEE_HOST__ENCLAVE__VSOCK_CID:-4}"
export TEE_HOST__ENCLAVE__VSOCK_PORT="${TEE_HOST__ENCLAVE__VSOCK_PORT:-7878}"

# Step 4 — Start host
if [ -f ./config.toml ]; then
    TEE_HOST_CONFIG=./config.toml nohup ./xlayer-tee-host >> host.log 2>&1 &
else
    nohup ./xlayer-tee-host >> host.log 2>&1 &
fi
echo "xlayer-tee-host started (pid=$!)"
