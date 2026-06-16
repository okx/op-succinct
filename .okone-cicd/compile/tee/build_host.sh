#!/usr/bin/env bash
# Cross-compile the xlayer-tee-host binary for Linux x86_64 in a Docker
# container. The output binary is a plain ELF you can scp to the TEE machine
# and run directly — it lives OUTSIDE the enclave (no EIF / no PCR0 input).
#
# Pair with build.sh + build_eif.sh: those produce the enclave-side artifact;
# this produces the host-side bridge process that proxies vsock <-> HTTP.
#
# Usage:
#   ./build_host.sh                     # default rust:1.81-bookworm
#   ./build_host.sh --features vsock    # production build with vsock
#   ./build_host.sh --rust-image rust:1.82-bookworm
#
# Output:
#   target/x86_64-unknown-linux-gnu/release/xlayer-tee-host
#   build/xlayer-tee-host               (copy, ready to scp)
#
# Deploy (example):
#   scp build/xlayer-tee-host tee:/path/to/op-succinct/target/x86_64-unknown-linux-gnu/release/
#   ssh tee 'pkill -f xlayer-tee-host; sleep 2; nohup ./xlayer-tee-host --config config.toml >> host.log 2>&1 & disown'

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${REPO_ROOT}"

RUST_IMAGE="rust:1.81-bookworm"
FEATURES=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --features) FEATURES="--features $2"; shift 2 ;;
    --rust-image) RUST_IMAGE="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

BIN=target/x86_64-unknown-linux-gnu/release/xlayer-tee-host

echo "==> cargo build (in ${RUST_IMAGE}) ${FEATURES:+with ${FEATURES}}"
# Not using --offline because the cargo-cache volume may not have host-specific
# deps (e.g. tower-http) on first run. Cache still avoids re-downloads after.
docker run --rm --platform linux/amd64 \
  -v "$(pwd)":/workspace -w /workspace \
  -v cargo-cache:/usr/local/cargo \
  "${RUST_IMAGE}" \
  bash -c "cargo build --release --target x86_64-unknown-linux-gnu -p xlayer-tee-host ${FEATURES}"

if [[ ! -f "${BIN}" ]]; then
  echo "ERROR: ${BIN} not found." >&2
  exit 1
fi

mkdir -p build
cp "${BIN}" build/xlayer-tee-host

BIN_SIZE=$(du -h "${BIN}" | cut -f1)
BIN_MTIME=$(date -r "${BIN}" '+%Y-%m-%d %H:%M:%S')

echo
echo "==> done"
echo "    ${BIN} (${BIN_SIZE}, modified ${BIN_MTIME})"
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

echo
echo "next: scp build/xlayer-tee-host to the TEE machine and restart the host process"
