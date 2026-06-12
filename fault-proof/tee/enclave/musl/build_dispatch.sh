#!/bin/bash
# Portable launcher for the reproducible musl/scratch enclave build (build.sh).
#
# It DISPATCHES by host:
#   - linux/amd64 host   -> runs build.sh DIRECTLY. No docker, no image pulled.
#                           (This is build.sh's native, supported environment.)
#   - any other host     -> runs the UNCHANGED build.sh inside a linux/amd64
#     (macOS, arm Linux)    container, because there the native linker can't
#                           build the target.
#
# Why the container is only a fallback:
#   build.sh is "Linux/amd64 ONLY". On macOS, `cargo build --target
#   x86_64-unknown-linux-musl` links via Apple's ld64, which rejects GNU linker
#   options (`ld: unknown option: --as-needed`) and cannot emit Linux ELF. A
#   native linux/amd64 host has none of that problem, so it needs no container.
#   Use FORCE_DOCKER=1 to take the container path even on a Linux host.
#
# Reproducibility is preserved by build.sh itself (pinned toolchain via
# rust-toolchain.toml, --locked, codegen-units=1, --remap-path-prefix). This
# wrapper only adds: fixed mount path, forced linux/amd64, and an overridable
# compile image. For BYTE-IDENTICAL PCR across machines, set COMPILE_IMAGE to
# your internal pinned image PINNED BY DIGEST (see notes at the bottom).
#
# Usage (run from anywhere):
#   ./fault-proof/tee/enclave/musl/build_in_docker.sh [debug|release]   # default: release
#
# Env knobs:
#   COMPILE_IMAGE   docker image to build in   (default: rust:1-bookworm)
#   MOUNT_PATH      fixed in-container repo path (default: /op-succinct)
#   CARGO_CACHE     1 to reuse a named cargo volume across runs (default: 1)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Workspace root = dir containing the top-level Cargo.toml (4 levels up), same
# anchoring as build.sh.
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

MODE="${1:-release}"

# --- Native fast-path -------------------------------------------------------
# build.sh is "Linux/amd64 ONLY" and needs NO container there: on a native
# linux/amd64 host, `cc`/GNU ld link the static musl binary directly. The
# container is ONLY a shim for hosts that can't do that (macOS, or arm Linux
# whose gcc targets aarch64). So if we're already on linux/amd64, just exec
# build.sh — no docker, no image pulled. Set FORCE_DOCKER=1 to override (e.g.
# to reproduce against a specific pinned image even on a Linux host).
HOST_OS="$(uname -s)"
HOST_ARCH="$(uname -m)"
if [ "${FORCE_DOCKER:-0}" != "1" ] && [ "$HOST_OS" = "Linux" ] && { [ "$HOST_ARCH" = "x86_64" ] || [ "$HOST_ARCH" = "amd64" ]; }; then
    echo "==> Native linux/amd64 host detected — running build.sh directly (no docker, no image)."
    exec bash "$SCRIPT_DIR/build.sh" "$MODE"
fi

echo "==> Host is $HOST_OS/$HOST_ARCH (not linux/amd64) — falling back to a container."

# NOT reproducible unless pinned by digest. rust:1-bookworm carries rustup+gcc;
# the image's own rust version is irrelevant because rust-toolchain.toml pins the
# nightly that rustup will auto-install. Override for your internal mirror:
#   COMPILE_IMAGE=your-registry.example.com/okbase/rust@sha256:... \
#     ./build_in_docker.sh
COMPILE_IMAGE="${COMPILE_IMAGE:-rust:1-bookworm}"
MOUNT_PATH="${MOUNT_PATH:-/op-succinct}"
CARGO_CACHE="${CARGO_CACHE:-1}"

if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker not found on PATH." >&2
    exit 1
fi

# Path from REPO_ROOT to build.sh, re-expressed under the in-container mount.
REL_BUILD="${SCRIPT_DIR#"$REPO_ROOT"/}/build.sh"

echo "==> Route A: building inside container"
echo "    image       : $COMPILE_IMAGE"
echo "    platform     : linux/amd64 (forced; emulated on Apple Silicon)"
echo "    repo (host)  : $REPO_ROOT"
echo "    repo (mount) : $MOUNT_PATH"
echo "    mode         : $MODE"

CACHE_ARGS=()
if [ "$CARGO_CACHE" = "1" ]; then
    # Persist downloaded crates across runs. CARGO_HOME in the rust image is
    # /usr/local/cargo; caching it does NOT affect output bytes, only speed.
    CACHE_ARGS=(-v op-succinct-enclave-cargo:/usr/local/cargo/registry)
fi

# --network is left default (build.sh's `rustup target add` + cargo fetch need
# network on first run; bake the toolchain+target into a pinned image for a fully
# offline/hermetic build).
docker run --rm \
    --platform=linux/amd64 \
    -v "$REPO_ROOT":"$MOUNT_PATH" \
    -w "$MOUNT_PATH" \
    "${CACHE_ARGS[@]}" \
    -e CARGO_TERM_COLOR=always \
    "$COMPILE_IMAGE" \
    bash "$MOUNT_PATH/$REL_BUILD" "$MODE"

echo ""
echo "==> Done. Artifacts (written to the host via the bind mount):"
echo "    binary : $REPO_ROOT/target/x86_64-unknown-linux-musl/$MODE/xlayer-tee-enclave"
echo "    bundle : $REPO_ROOT/tee-enclave.tar  (build/ + Dockerfile + build_eif.sh)"
echo ""
echo "Next (EIF + PCR) runs on the Nitro host, not here — it needs the docker"
echo "daemon + a pinned nitro-cli:  cd build && ./build_eif.sh"
