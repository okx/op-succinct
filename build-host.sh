#!/usr/bin/env bash
# Cross-compile the xlayer-tee-host binary for Linux x86_64 in a Docker
# container. The output binary is a plain ELF you can scp to the TEE machine
# and run directly (no enclave packaging needed for the host side).
#
# Usage:
#   ./build-host.sh                  # build with default rust:1.81-bookworm
#   ./build-host.sh --features vsock # build with vsock feature (production)
#
# Output:
#   target/x86_64-unknown-linux-gnu/release/xlayer-tee-host
#   build/xlayer-tee-host             (copy, ready to scp)
#
# Deploy:
#   scp build/xlayer-tee-host tee:/data/xlayer_user/op-succinct/target/x86_64-unknown-linux-gnu/release/
#   ssh tee 'pkill -f xlayer-tee-host; sleep 2; cd /data/xlayer_user/op-succinct && nohup ./target/x86_64-unknown-linux-gnu/release/xlayer-tee-host --config config.toml > /root/logs/host.log 2>&1 & disown'

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

RUST_IMAGE="rust:1.81-bookworm"
FEATURES=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --features) FEATURES="--features $2"; shift 2 ;;
    --rust-image) RUST_IMAGE="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

BIN=target/x86_64-unknown-linux-gnu/release/xlayer-tee-host

echo "==> cargo build (in $RUST_IMAGE) ${FEATURES:+with $FEATURES}"
# Note: not using --offline because the cargo-cache volume may not have host-specific
# deps (e.g. tower-http) on first run. Cache still works to avoid re-downloading.
# Mount a rustup-cache volume too: rust-toolchain.toml pins nightly-2025-09-15 so
# rustup downloads ~500MB on first run; without this volume that download repeats
# every fresh container.
docker run --rm --platform linux/amd64 \
  -v "$(pwd)":/workspace -w /workspace \
  -v cargo-cache:/usr/local/cargo \
  -v rustup-cache:/usr/local/rustup \
  -e RUSTUP_HOME=/usr/local/rustup \
  "$RUST_IMAGE" \
  bash -c "cargo build --release --target x86_64-unknown-linux-gnu -p xlayer-tee-host $FEATURES"

if [[ ! -f "$BIN" ]]; then
  echo "ERROR: $BIN not found." >&2
  exit 1
fi

mkdir -p build
cp "$BIN" build/xlayer-tee-host

BIN_SIZE=$(du -h "$BIN" | cut -f1)
BIN_MTIME=$(date -r "$BIN" '+%Y-%m-%d %H:%M:%S')

echo
echo "==> done"
echo "    $BIN ($BIN_SIZE, modified $BIN_MTIME)"
echo "    build/xlayer-tee-host (copy ready to scp)"

# Smoke checks: which features were compiled in
echo
if grep -aoq 'proxy_debug' build/xlayer-tee-host; then
  echo "    ✓ binary contains 'proxy_debug' (/debug/* forwarding)"
else
  echo "    ✗ binary missing 'proxy_debug' — old build?"
fi
if grep -aoq 'vsock_cid' build/xlayer-tee-host 2>/dev/null; then
  echo "    ✓ binary contains 'vsock_cid' (vsock support)"
fi
if grep -aoq 'host memory snapshot' build/xlayer-tee-host 2>/dev/null; then
  echo "    ✓ binary contains 'host memory snapshot' (periodic RSS logger)"
else
  echo "    ✗ binary missing 'host memory snapshot' — old build (no mem.rs)?"
fi
if grep -aoq 'create_task memory profile' build/xlayer-tee-host 2>/dev/null; then
  echo "    ✓ binary contains 'create_task memory profile' (per-request RSS)"
fi

echo
echo "next: scp build/xlayer-tee-host to TEE machine, then restart host process"
