#!/usr/bin/env bash
set -euo pipefail

NITRO_CLI_VERSION="${NITRO_CLI_VERSION:-1.3.3}"
NITRO_CLI_COMMIT="${NITRO_CLI_COMMIT:-afb7264}"
NITRO_CLI_MODE="${NITRO_CLI_MODE:-auto}"

# Guard 1 — Binary presence
if [ ! -f ./xlayer-tee-enclave ]; then
    echo "ERROR: xlayer-tee-enclave not found in current directory." >&2
    echo "Run this script from the build/ directory (after unpacking tee-enclave.tar)." >&2
    exit 1
fi

# Guard 2 — GNU tar requirement
if ! tar --version 2>&1 | grep -q 'GNU tar'; then
    echo "ERROR: GNU tar required. BSD tar produces different rootfs.tar → different PCR0." >&2
    echo "Run on Linux or install GNU tar." >&2
    exit 1
fi

# --- Part 1: Deterministic single-layer image ---

# Step 1 — Create staging directory
STAGING="$(mktemp -d)"
# [A-15 Finding #3] Trap for cleanup on any exit (success or failure)
trap 'rm -rf "${STAGING}" rootfs.tar 2>/dev/null' EXIT

install -m 744 ./xlayer-tee-enclave "${STAGING}/xlayer-tee-enclave"

# Step 2 — Deterministic rootfs.tar
export SOURCE_DATE_EPOCH=0
tar --sort=name \
    --mtime="@${SOURCE_DATE_EPOCH}" \
    --numeric-owner --owner=0 --group=0 \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -C "${STAGING}" -cf rootfs.tar .

# [A-15 Finding #1] Capture rootfs.tar hash before docker import
ROOTFS_HASH="$(sha256sum rootfs.tar | awk '{print $1}')"
echo "rootfs hash: ${ROOTFS_HASH}"

# Step 3 — docker import
docker import \
    --change 'CMD ["/xlayer-tee-enclave"]' \
    rootfs.tar enclave:latest

# Step 4 — Cleanup handled by trap

# --- Part 2: Pinned nitro-cli EIF assembly ---

build_nitro_cli_from_source() {
    local clone_dir
    clone_dir="$(mktemp -d)"
    git clone https://github.com/aws/aws-nitro-enclaves-cli "${clone_dir}"
    cd "${clone_dir}"
    git checkout "${NITRO_CLI_COMMIT}"
    cargo build --release -p nitro-cli
    NITRO_CLI="${clone_dir}/target/release/nitro-cli"
    export NITRO_CLI_BLOBS="${clone_dir}/blobs/x86_64"
    cd - > /dev/null
}

# Step 5 — Select nitro-cli binary
case "${NITRO_CLI_MODE}" in
    host-bin)
        if ! command -v nitro-cli > /dev/null 2>&1; then
            echo "ERROR: nitro-cli not found" >&2
            exit 1
        fi
        ACTUAL="$(nitro-cli --version | grep -oP '\d+\.\d+\.\d+')"
        if [ "${ACTUAL}" != "${NITRO_CLI_VERSION}" ]; then
            echo "ERROR: host nitro-cli version ${ACTUAL} != pinned ${NITRO_CLI_VERSION}" >&2
            exit 1
        fi
        NITRO_CLI=nitro-cli
        ;;
    host-src)
        build_nitro_cli_from_source
        ;;
    auto)
        if command -v nitro-cli > /dev/null 2>&1; then
            ACTUAL="$(nitro-cli --version | grep -oP '\d+\.\d+\.\d+')"
            if [ "${ACTUAL}" != "${NITRO_CLI_VERSION}" ]; then
                echo "ERROR: host nitro-cli version ${ACTUAL} != pinned ${NITRO_CLI_VERSION}" >&2
                exit 1
            fi
            NITRO_CLI=nitro-cli
        else
            build_nitro_cli_from_source
        fi
        ;;
    *)
        echo "ERROR: unknown NITRO_CLI_MODE: ${NITRO_CLI_MODE}" >&2
        exit 1
        ;;
esac

# Step 6 — Build EIF
${NITRO_CLI} build-enclave \
    --docker-uri enclave:latest \
    --output-file enclave.eif \
    2>&1 | tee eif-build.log

# Step 7 — Extract PCR values
PCR0="$(grep -oP '"PCR0"\s*:\s*"\K[^"]+' eif-build.log || echo 'UNKNOWN')"
PCR1="$(grep -oP '"PCR1"\s*:\s*"\K[^"]+' eif-build.log || echo 'UNKNOWN')"
PCR2="$(grep -oP '"PCR2"\s*:\s*"\K[^"]+' eif-build.log || echo 'UNKNOWN')"

cat > PCR.txt <<PCREOF
PCR0: ${PCR0}
PCR1: ${PCR1}
PCR2: ${PCR2}
PCREOF

echo "EIF built: enclave.eif"
echo "PCR0: ${PCR0}"
