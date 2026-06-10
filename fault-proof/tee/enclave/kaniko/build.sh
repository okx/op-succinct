#!/bin/bash
# Reproducible build of the op-succinct TEE enclave binary (xlayer-tee-enclave).
#
# Philosophy (same as tradezone): reproducibility comes from a NORMALISED
# ENVIRONMENT, not from flag-soup. This script MUST run inside the pinned okone
# compile image (a stagex/pallet-go-style hermetic toolchain) at a FIXED mount
# path. Given that, the binary is byte-identical across builds.
#
# We still set a few belt-and-suspenders knobs so it also reproduces if the
# build PATH happens to differ (op-succinct has heavy C deps where this matters).
#
# Usage (run from anywhere; it cds to the workspace root):
#   ./fault-proof/tee/enclave/kaniko/build.sh [debug|release]   # default: release
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Workspace root = dir containing the top-level Cargo.toml (4 levels up).
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
cd "$REPO_ROOT"

MODE="${1:-release}"
CARGO_MODE_FLAG=""
[ "$MODE" = "release" ] && CARGO_MODE_FLAG="--release"

echo "==> Installing system build deps for native crates (c-kzg/blst/aws-lc-sys/ring/openssl-sys)"
# NOTE: in the pinned compile image these are usually preinstalled; this block
# is for ad-hoc/local runs. apt at build time is itself a reproducibility risk —
# in CI rely on the pinned image instead of installing here.
if command -v apt-get >/dev/null 2>&1 && [ "${SKIP_APT:-0}" != "1" ]; then
    apt-get update && apt-get install -y --no-install-recommends \
        clang libclang-dev cmake make perl pkg-config \
        libssl-dev zlib1g-dev libcurl4-openssl-dev \
        build-essential git ca-certificates \
        && rm -rf /var/lib/apt/lists/*
fi

echo "==> Reproducibility environment"
export SOURCE_DATE_EPOCH=0
export TZ=UTC
export LC_ALL=C
export CARGO_INCREMENTAL=0
# Determinism: serialise codegen (op-succinct has no [profile.release] override,
# so the default is 16 units -> non-deterministic ordering). 1 unit fixes it.
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
# Erase absolute paths embedded by rustc AND by cc-rs (C objects in c-kzg/blst/
# aws-lc-sys/ring). --remap-path-prefix only covers Rust; -ffile-prefix-map
# covers the C side. op-succinct sets no .cargo/config rustflags, so overriding
# RUSTFLAGS here is safe (nothing to clobber).
export RUSTFLAGS="--remap-path-prefix=${REPO_ROOT}=. --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo -C strip=symbols"
export CFLAGS="-ffile-prefix-map=${REPO_ROOT}=. -ffile-prefix-map=${CARGO_HOME:-$HOME/.cargo}=/cargo"
export CXXFLAGS="$CFLAGS"

echo "==> Toolchain"
# rust-toolchain.toml pins nightly-2025-09-15; rustup honours it automatically.
rustc --version || true

rm -rf build
mkdir -p build

echo "==> Building xlayer-tee-enclave (--features vsock, $MODE, --locked)"
cargo build $CARGO_MODE_FLAG --locked \
    --package xlayer-tee-enclave \
    --features vsock \
    --bin xlayer-tee-enclave

BIN="target/${MODE}/xlayer-tee-enclave"
echo "==> shared lib deps (runtime — the enclave Dockerfile base must provide these):"
# ldd on Linux (the real build env); otool -L as a courtesy on macOS ad-hoc runs.
if command -v ldd >/dev/null 2>&1; then
    ldd "$BIN" || true
elif command -v otool >/dev/null 2>&1; then
    otool -L "$BIN" || true
else
    echo "    (no ldd/otool available; skipping)"
fi

cp "$BIN" build/xlayer-tee-enclave
# Normalise the binary's own mtime so the downstream OCI layer is deterministic.
# GNU touch (Linux) understands -d @EPOCH; BSD touch (macOS) needs -t [[CC]YY]MMDDhhmm[.SS].
touch -hcd "@${SOURCE_DATE_EPOCH}" build/xlayer-tee-enclave 2>/dev/null \
    || touch -hct "$(date -u -r "${SOURCE_DATE_EPOCH}" +%Y%m%d%H%M.%S)" build/xlayer-tee-enclave

cp "$SCRIPT_DIR/Dockerfile"     build/Dockerfile
cp "$SCRIPT_DIR/build_eif.sh"   build/build_eif.sh
chmod +x build/build_eif.sh

# md5sum on Linux/coreutils; md5 -q on macOS.
ENCLAVE_MD5="$({ md5sum build/xlayer-tee-enclave 2>/dev/null || md5 -q build/xlayer-tee-enclave; } | awk '{print $1}')"
echo "=========================================================="
echo " enclave binary md5 = $ENCLAVE_MD5"
echo " (record this; two builds MUST produce the same md5)"
echo "=========================================================="

tar -zcf tee-enclave.tar build/*
ls -lah tee-enclave.tar
