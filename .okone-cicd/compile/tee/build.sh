#!/usr/bin/env bash
set -euo pipefail

PROFILE="${1:-release}"
EXPECTED_TOOLCHAIN="nightly-2025-09-15"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Step 1 — Toolchain assertion
ACTUAL_VERSION="$(rustc --version)"
if [[ "${ACTUAL_VERSION}" != *"${EXPECTED_TOOLCHAIN}"* ]]; then
    echo "ERROR: expected toolchain ${EXPECTED_TOOLCHAIN}, got: ${ACTUAL_VERSION}" >&2
    exit 1
fi

# Step 2 — musl target
if ! rustup target list --installed | grep -q 'x86_64-unknown-linux-musl'; then
    rustup target add x86_64-unknown-linux-musl
fi

# Step 3 — Deterministic environment variables
export SOURCE_DATE_EPOCH=0
export TZ=UTC
export LC_ALL=C
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

# Step 4 — RUSTFLAGS for reproducibility
REPO_DIR="$(git rev-parse --show-toplevel)"
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--remap-path-prefix=${REPO_DIR}=/build/src --remap-path-prefix=${CARGO_HOME}=/build/cargo -C target-feature=+crt-static -C strip=symbols"

# Step 5 — Build
cargo build "--${PROFILE}" --locked \
    --target x86_64-unknown-linux-musl \
    --features vsock \
    --bin xlayer-tee-enclave \
    --manifest-path fault-proof/tee/enclave/Cargo.toml

# Step 6 — Normalize mtime + hash
BINARY="target/x86_64-unknown-linux-musl/${PROFILE}/xlayer-tee-enclave"
touch -d @0 "${BINARY}"
HASH="$(md5sum "${BINARY}" | awk '{print $1}')"
echo "enclave binary hash: ${HASH}"

# Step 7 — Package artifact
mkdir -p build/
cp "${BINARY}" build/xlayer-tee-enclave
cp "${SCRIPT_DIR}/Dockerfile" build/
cp "${SCRIPT_DIR}/build_eif.sh" build/
cp "${SCRIPT_DIR}/start.sh" build/
cp "${SCRIPT_DIR}/stop.sh" build/
tar -czf tee-enclave.tar -C build .
echo "artifact: tee-enclave.tar"
