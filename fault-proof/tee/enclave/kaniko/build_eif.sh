#!/bin/bash
# Build the enclave OCI image with Kaniko (reproducible), then assemble the EIF
# with the HOST's nitro-cli. Run on the Nitro-enabled EC2 host, from the `build/`
# dir produced by build.sh (it contains Dockerfile + xlayer-tee-enclave).
#
#   cd build && ../fault-proof/tee/enclave/kaniko/build_eif.sh   # or just ./build_eif.sh after copy
#
# Kaniko is PINNED BY DIGEST (the OCI image must be reproducible). nitro-cli is
# taken from the host — pin reproducibility by keeping the host's installed
# aws-nitro-enclaves-cli version frozen (it bundles the measured kernel/init).
set -euo pipefail

# --- Pinned kaniko image (replace with the exact digest you verified) --------
KANIKO_IMAGE="${KANIKO_IMAGE:-gcr.io/kaniko-project/executor}"

command -v nitro-cli >/dev/null 2>&1 || { echo "ERROR: nitro-cli not found on host" >&2; exit 1; }
echo "host nitro-cli: $(nitro-cli --version 2>/dev/null || echo unknown)"

WORKDIR="$(pwd)"

echo "==> [1/3] Kaniko: Dockerfile + binary -> enclave.tar (reproducible)"
docker run --rm --platform linux/amd64 \
    -v "$WORKDIR":/workspace \
    "$KANIKO_IMAGE" \
    --dockerfile=Dockerfile \
    --context=dir:///workspace \
    --destination=enclave:latest --no-push \
    --tarPath=/workspace/enclave.tar \
    --reproducible --single-snapshot

echo "    enclave.tar md5 = $(md5sum enclave.tar | awk '{print $1}')"

echo "==> [2/3] docker load enclave.tar"
docker load -i enclave.tar

echo "==> [3/3] nitro-cli build-enclave -> EIF + PCR0 (host nitro-cli)"
nitro-cli build-enclave \
    --docker-uri enclave:latest \
    --output-file "$WORKDIR/enclave.eif" \
    | tee "$WORKDIR/build_eif.log"

# Persist the measurements (PCR0/1/2) next to the EIF.
grep -oE '"PCR[0-9]"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]+"' "$WORKDIR/build_eif.log" \
    | sed 's/[",]//g' > "$WORKDIR/PCR.txt" || true

echo "=========================================================="
echo " EIF:  $WORKDIR/enclave.eif"
echo " PCRs:"; cat "$WORKDIR/PCR.txt" 2>/dev/null || true
echo " (two builds with the same binary MUST give the same PCR0)"
echo "=========================================================="
