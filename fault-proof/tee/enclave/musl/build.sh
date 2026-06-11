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

# --- Pin enforcement --------------------------------------------------------
# Reproducibility requires the EXACT toolchain, not "whatever nightly is default".
# Both rustc and the musl rust-std (which provides the statically-linked musl
# startup objects / libc.a) come from this one immutable snapshot, declared in
# the repo's rust-toolchain.toml. We READ the expected channel from that file
# (single source of truth) and ASSERT the running toolchain matches — aborting
# loudly on drift instead of silently building with the wrong version.
TOOLCHAIN_FILE="$REPO_ROOT/rust-toolchain.toml"
EXPECTED_CHANNEL="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' "$TOOLCHAIN_FILE" | head -n1)"
if [ -z "$EXPECTED_CHANNEL" ]; then
    echo "ERROR: could not read channel from $TOOLCHAIN_FILE" >&2; exit 1
fi
# nightly-2025-09-15 -> 2025-09-15 ; `rustc --version` for that nightly embeds
# this date, so it's a reliable equality check across machines.
EXPECTED_DATE="${EXPECTED_CHANNEL#nightly-}"

echo "==> Enforcing pinned toolchain ($EXPECTED_CHANNEL)"
RUSTC_VERSION="$(rustc --version 2>/dev/null || true)"
echo "    rustc: $RUSTC_VERSION"
case "$RUSTC_VERSION" in
    *"$EXPECTED_DATE"*) : ;;  # ok: the active rustc is the pinned nightly
    *)
        echo "ERROR: active rustc is not the pinned $EXPECTED_CHANNEL (got: $RUSTC_VERSION)." >&2
        echo "       Run inside the pinned okone compile image, or 'rustup toolchain install $EXPECTED_CHANNEL'." >&2
        exit 1 ;;
esac

# The musl target std must already be present (baked into the pinned compile
# image). It is per-toolchain, so it can only ever match the pinned nightly
# above — no separate version pin is needed. We do NOT network-install at build
# time (non-hermetic); local dev can opt in explicitly via ALLOW_RUSTUP_NETWORK.
if command -v rustup >/dev/null 2>&1; then
    if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
        if [ "${ALLOW_RUSTUP_NETWORK:-0}" = "1" ]; then
            echo "==> ALLOW_RUSTUP_NETWORK=1 -> installing $TARGET (non-hermetic; local dev only)"
            rustup target add "$TARGET"
        else
            echo "ERROR: target $TARGET not installed for $EXPECTED_CHANNEL." >&2
            echo "       It must be pre-baked in the compile image. For local dev, re-run with" >&2
            echo "       ALLOW_RUSTUP_NETWORK=1 to 'rustup target add $TARGET'." >&2
            exit 1
        fi
    fi
else
    echo "    (rustup absent — assuming the pinned compile image already provides $TARGET)"
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
