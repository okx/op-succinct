#!/usr/bin/env bash
# Build the xlayer-tee-enclave binary in a Linux container, then pack it into
# a Docker image tarball ready for `nitro-cli build-enclave`.
#
# Usage:
#   ./build-eif.sh                     # full build
#   ./build-eif.sh --skip-cargo        # reuse existing binary, just repack tar
#   ./build-eif.sh --tag enclave:foo   # custom image tag (default: enclave:latest)
#   ./build-eif.sh --prof              # enable jemalloc heap profiling via MALLOC_CONF
#
# Output:
#   target/x86_64-unknown-linux-gnu/release/xlayer-tee-enclave
#   build/Dockerfile
#   build/enclave           (copy of the binary)
#   build/enclave.tar       (docker image tar — feed this to nitro-cli build-enclave)
#
# After this completes, scp build/enclave.tar to your TEE machine and run:
#   docker load -i enclave.tar
#   nitro-cli build-enclave --docker-uri <tag> --output-file enclave.eif

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

# ---- args -----------------------------------------------------------------

SKIP_CARGO=0
TAG="enclave:latest"
RUST_IMAGE="rust:1.81-bookworm"
PROF=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-cargo) SKIP_CARGO=1; shift ;;
    --tag) TAG="$2"; shift 2 ;;
    --rust-image) RUST_IMAGE="$2"; shift 2 ;;
    --prof) PROF=1; shift ;;
    -h|--help)
      sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

BIN=target/x86_64-unknown-linux-gnu/release/xlayer-tee-enclave

# ---- step 1: cargo build inside container ---------------------------------

if [[ "$SKIP_CARGO" -eq 0 ]]; then
  echo "==> [1/3] cargo build (in $RUST_IMAGE)"
  docker run --rm --platform linux/amd64 \
    -v "$(pwd)":/workspace -w /workspace \
    -v cargo-cache:/usr/local/cargo \
    "$RUST_IMAGE" \
    cargo build --offline --release \
      --target x86_64-unknown-linux-gnu \
      -p xlayer-tee-enclave --features vsock
else
  echo "==> [1/3] skip cargo build (--skip-cargo)"
fi

if [[ ! -f "$BIN" ]]; then
  echo "ERROR: $BIN not found. Did cargo build succeed?" >&2
  exit 1
fi

# Show build artifact info
BIN_SIZE=$(du -h "$BIN" | cut -f1)
BIN_MTIME=$(date -r "$BIN" '+%Y-%m-%d %H:%M:%S')
echo "    binary: $BIN ($BIN_SIZE, modified $BIN_MTIME)"

# ---- step 2: stage Dockerfile + binary in build/ --------------------------

echo "==> [2/3] stage build/ directory"
mkdir -p build
cp "$BIN" build/enclave

if [[ "$PROF" -eq 1 ]]; then
  cat > build/Dockerfile <<'EOF'
FROM debian:bookworm-slim
# jemalloc heap profiling: dump every 2^30 (=1 GiB) bytes allocated.
# Profile files go to /tmp/jeprof.<pid>.<n>.<seq>.heap inside the enclave.
ENV MALLOC_CONF=prof:true,prof_active:true,lg_prof_interval:30,prof_prefix:/tmp/jeprof
COPY --chown=0:0 --chmod=755 ./enclave /enclave
CMD ["/enclave"]
EOF
  echo "    profiling enabled: MALLOC_CONF=prof:true,prof_active:true,lg_prof_interval:30,prof_prefix:/tmp/jeprof"
else
  cat > build/Dockerfile <<'EOF'
FROM debian:bookworm-slim
COPY --chown=0:0 --chmod=755 ./enclave /enclave
CMD ["/enclave"]
EOF
fi

# ---- step 3: docker buildx build ------------------------------------------

echo "==> [3/3] docker buildx build (tag=$TAG)"
docker buildx build \
  --platform linux/amd64 \
  --file build/Dockerfile \
  --tag "$TAG" \
  --output type=docker,dest=build/enclave.tar \
  build/

# ---- summary --------------------------------------------------------------

TAR_SIZE=$(du -h build/enclave.tar | cut -f1)
echo
echo "==> done"
echo "    binary: $BIN ($BIN_SIZE)"
echo "    tar:    build/enclave.tar ($TAR_SIZE, tag=$TAG)"

# Quick smoke check: tar's binary contains expected markers
if grep -aoq 'task memory profile' build/enclave; then
  echo "    ✓ binary contains 'task memory profile' (PeakTracker)"
fi
if grep -aoq 'rss_after_trim_mib' build/enclave; then
  echo "    ✓ binary contains 'rss_after_trim_mib' (malloc_trim diagnostic)"
fi
if grep -aoq 'jemalloc' build/enclave; then
  echo "    ✓ binary contains 'jemalloc' (jemalloc allocator)"
fi

echo
echo "next steps on TEE machine:"
echo "  scp build/enclave.tar tee-machine:~/"
echo "  ssh tee-machine 'docker load -i ~/enclave.tar &&"
echo "    nitro-cli build-enclave --docker-uri $TAG --output-file ~/enclave.eif'"
