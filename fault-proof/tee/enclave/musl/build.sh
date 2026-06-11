#!/bin/bash
# Reproducible STATIC build of the op-succinct TEE enclave binary
# (xlayer-tee-enclave) for a `FROM scratch` enclave image.
#
# Target: x86_64-unknown-linux-musl -> a fully static binary (no libc / ld.so /
# shared objects). This is feasible because xlayer-tee-enclave has ZERO C deps
# (kzg-rs is pure Rust; no c-kzg/blst/openssl/ring), so musl needs no cross C
# toolchain — just the rustup target. If a future dep pulls in a C/-sys crate,
# use the sibling kaniko/ (glibc + digest-pinned Debian) variant instead.
#
# Philosophy: reproducibility comes
# from a NORMALISED ENVIRONMENT, not flag-soup. Run this INSIDE the pinned okone
# compile image (a fixed linux/amd64 toolchain) at a FIXED mount path; given
# that, the binary (hence PCR2/PCR0) is byte-identical across machines. The few
# knobs below are belt-and-suspenders so it also reproduces if the build PATH
# happens to differ.
#
# Linux/amd64 ONLY — macOS/native-host handling is intentionally absent.
#
# Usage (run from anywhere; it cds to the workspace root):
#   ./fault-proof/tee/enclave/musl/build.sh [debug|release]   # default: release
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Workspace root = dir containing the top-level Cargo.toml (4 levels up).
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
cd "$REPO_ROOT"

MODE="${1:-release}"
CARGO_MODE_FLAG=""
[ "$MODE" = "release" ] && CARGO_MODE_FLAG="--release"

TARGET="x86_64-unknown-linux-musl"

echo "==> Ensuring rustup target $TARGET is installed"
# Honours rust-toolchain.toml (nightly-2025-09-15). No C cross-compiler needed:
# the enclave has no -sys/cc crates, so rustc's bundled musl is sufficient.
if command -v rustup >/dev/null 2>&1; then
    rustup target add "$TARGET" || true
else
    echo "    (rustup not found — assuming the pinned compile image already has $TARGET)"
fi

echo "==> Reproducibility environment"
export SOURCE_DATE_EPOCH=0
export TZ=UTC
export LC_ALL=C
export CARGO_INCREMENTAL=0
# Determinism: serialise codegen (op-succinct has no [profile.release] override,
# so the default is 16 units -> non-deterministic ordering). 1 unit fixes it.
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
# Erase absolute paths embedded by rustc. (No C deps -> no CFLAGS/-ffile-prefix-map
# needed here, unlike the kaniko/ variant.) +crt-static is the musl default for
# bins but we set it explicitly so a fully static link is guaranteed.
export RUSTFLAGS="--remap-path-prefix=${REPO_ROOT}=. --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo -C target-feature=+crt-static -C strip=symbols"

echo "==> Toolchain"
rustc --version || true

rm -rf build
mkdir -p build

echo "==> Building xlayer-tee-enclave (--target $TARGET, --features vsock, $MODE, --locked)"
cargo build $CARGO_MODE_FLAG --locked \
    --target "$TARGET" \
    --package xlayer-tee-enclave \
    --features vsock \
    --bin xlayer-tee-enclave

BIN="target/${TARGET}/${MODE}/xlayer-tee-enclave"
echo "==> Verifying the binary is fully static (must say 'statically linked' / 'not a dynamic executable'):"
file "$BIN" || true
ldd "$BIN" || true   # for a static musl bin this prints 'not a dynamic executable'

cp "$BIN" build/xlayer-tee-enclave
# Normalise the binary's own mtime so the downstream OCI layer is deterministic.
touch -hcd "@${SOURCE_DATE_EPOCH}" build/xlayer-tee-enclave

# Ship the scratch Dockerfile + the SHARED build_eif.sh (kaniko + pinned
# nitro-cli). build_eif.sh is base-agnostic, so the musl/scratch path reuses it
# verbatim — only the Dockerfile differs from the kaniko/ variant.
cp "$SCRIPT_DIR/Dockerfile"              build/Dockerfile
cp "$SCRIPT_DIR/../kaniko/build_eif.sh"  build/build_eif.sh
chmod +x build/build_eif.sh

ENCLAVE_MD5="$(md5sum build/xlayer-tee-enclave | awk '{print $1}')"
echo "=========================================================="
echo " enclave binary md5 = $ENCLAVE_MD5"
echo " (record this; two builds MUST produce the same md5)"
echo "=========================================================="

tar -zcf tee-enclave.tar build/*
ls -lah tee-enclave.tar
