#!/usr/bin/env bash
set -euo pipefail

NITRO_CLI_VERSION="${NITRO_CLI_VERSION:-1.3.3}"
NITRO_CLI_COMMIT="${NITRO_CLI_COMMIT:-afb7264}"
NITRO_CLI_MODE="${NITRO_CLI_MODE:-auto}"
# Expected sha256 of the blobs/ directory contents. When set, every build asserts
# the actual blobs hash matches this value — that is what guarantees byte-level
# reproducibility of PCR0 across hosts. Bootstrap workflow: run once with this
# unset (or with STRICT_BLOBS_HASH=0), copy the printed "blobs hash:" into your
# CI config, then enforce.
EXPECTED_BLOBS_HASH="${EXPECTED_BLOBS_HASH:-}"
# When STRICT_BLOBS_HASH=1 (default), an unset EXPECTED_BLOBS_HASH is a hard
# error in host-bin / auto modes. Set STRICT_BLOBS_HASH=0 to bootstrap and
# discover the hash, then turn it back on in CI.
STRICT_BLOBS_HASH="${STRICT_BLOBS_HASH:-1}"

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

# Require an explicit NITRO_CLI_BLOBS when using a host-installed nitro-cli.
# The kernel + init under blobs/ are an input to PCR0: same nitro-cli --version
# on two hosts can ship different blob bytes (AMI vintage, repackaging, kernel
# patch level), so PCR0 won't reproduce unless the blobs path is pinned. host-src
# mode already pins this via the cloned commit; host-bin / auto must declare it.
assert_nitro_cli_blobs_pinned() {
    if [ -z "${NITRO_CLI_BLOBS:-}" ]; then
        echo "ERROR: NITRO_CLI_BLOBS must be set when using host-installed nitro-cli." >&2
        echo "       The kernel + init under blobs/ are part of PCR0; different hosts" >&2
        echo "       with the same nitro-cli --version can ship different bytes, so the" >&2
        echo "       blobs path must be pinned explicitly." >&2
        echo "       Options:" >&2
        echo "         - export NITRO_CLI_BLOBS=/path/to/pinned/blobs/x86_64" >&2
        echo "         - or rerun with NITRO_CLI_MODE=host-src to build nitro-cli + blobs" >&2
        echo "           from the pinned commit (${NITRO_CLI_COMMIT})." >&2
        exit 1
    fi
    if [ ! -d "${NITRO_CLI_BLOBS}" ]; then
        echo "ERROR: NITRO_CLI_BLOBS=${NITRO_CLI_BLOBS} is not a directory." >&2
        exit 1
    fi
    BLOBS_HASH="$(find "${NITRO_CLI_BLOBS}" -type f -print0 \
        | LC_ALL=C sort -z \
        | xargs -0 sha256sum \
        | sha256sum \
        | awk '{print $1}')"
    echo "NITRO_CLI_BLOBS: ${NITRO_CLI_BLOBS}"
    echo "blobs hash:      ${BLOBS_HASH}"

    if [ -n "${EXPECTED_BLOBS_HASH}" ]; then
        if [ "${BLOBS_HASH}" != "${EXPECTED_BLOBS_HASH}" ]; then
            echo "ERROR: blobs hash mismatch — PCR0 will not reproduce." >&2
            echo "       expected: ${EXPECTED_BLOBS_HASH}" >&2
            echo "       actual:   ${BLOBS_HASH}" >&2
            echo "       This host's kernel/init blobs differ from the pinned ones." >&2
            echo "       Either update EXPECTED_BLOBS_HASH after auditing the change," >&2
            echo "       or rerun with NITRO_CLI_MODE=host-src to use commit-pinned blobs." >&2
            exit 1
        fi
        echo "blobs hash verified against EXPECTED_BLOBS_HASH"
    elif [ "${STRICT_BLOBS_HASH}" = "1" ]; then
        echo "ERROR: EXPECTED_BLOBS_HASH not set and STRICT_BLOBS_HASH=1." >&2
        echo "       Without a pinned hash, PCR0 reproducibility cannot be enforced." >&2
        echo "       Bootstrap: rerun once with STRICT_BLOBS_HASH=0, copy the printed" >&2
        echo "       'blobs hash:' value into EXPECTED_BLOBS_HASH (in CI config), then" >&2
        echo "       re-enable strict mode." >&2
        exit 1
    else
        echo "WARN: EXPECTED_BLOBS_HASH not set; blobs hash NOT verified (STRICT_BLOBS_HASH=0)."
    fi
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
        assert_nitro_cli_blobs_pinned
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
            assert_nitro_cli_blobs_pinned
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
