#!/bin/bash
# Reproducible EIF build for the musl/scratch enclave — WITHOUT kaniko, and
# without pulling any base/builder docker IMAGE in the happy path.
#
# What is (and is NOT) avoidable:
#  - kaniko: ELIMINATED. A `FROM scratch` + single-binary image is trivially one
#    layer (a tar holding /xlayer-tee-enclave) + a CMD. We assemble it
#    deterministically with `tar` + `docker import`, so there is no kaniko image
#    to pull and no kaniko version to pin (it's gone). This builds the exact
#    equivalent of musl/Dockerfile, imperatively.
#  - nitro-cli: REQUIRED and version-pinned. Selected via NITRO_CLI_MODE:
#      host-bin : a pinned nitro-cli already on PATH (bake it into the okone
#                 compile image). Its version is ASSERTED, so a wrong/unpinned
#                 one aborts the build. NO docker image.
#      host-src : build nitro-cli from the pinned COMMIT on the host (host cargo).
#                 NO docker image. The compiled binary's own bytes don't affect
#                 PCR — only the committed blobs/x86_64 + build-enclave logic do,
#                 both pinned by the commit (binary need NOT be reproducible).
#                 Needs host git+cargo+openssl headers.
#      auto     : (default) host-bin -> host-src, first that's usable.
#    This script pulls NO docker IMAGE in any mode.
#  - docker DAEMON: NOT avoidable. Stock `nitro-cli build-enclave` only reads the
#    enclave image from the local docker daemon (`--docker-uri`); there is no
#    "feed a rootfs tar" mode. So we drop docker IMAGES, not the daemon.
#
# PCR note: changing HOW the image is produced (kaniko vs docker import) is
# itself an input change — re-measure PCR0 when switching methods. Run-to-run
# with this script, the inputs (deterministic tar + pinned nitro-cli) are fixed,
# so PCR0 is stable.
#
# Run from the `build/` dir produced by build.sh (holds ./xlayer-tee-enclave).
set -euo pipefail

# --- Pins -------------------------------------------------------------------
# Only nitro-cli (its build-enclave logic + bundled kernel/init/nsm blobs) feeds
# PCR0/PCR1, so it is the one thing that MUST be pinned.
NITRO_CLI_EXPECTED_VERSION="${NITRO_CLI_EXPECTED_VERSION:-1.3.3}"   # host-binary path asserts this
NITRO_CLI_REPO="${NITRO_CLI_REPO:-https://github.com/aws/aws-nitro-enclaves-cli.git}"
NITRO_CLI_COMMIT="${NITRO_CLI_COMMIT:-afb7264b477ad241922236dd61f1730154212034}"  # v1.3.3

WORKDIR="$(pwd)"
IMAGE="enclave:latest"
BIN_NAME="xlayer-tee-enclave"
# Must match musl/Dockerfile's CMD.
CMD_JSON='["/'"$BIN_NAME"'"]'
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

if [ ! -f "$WORKDIR/$BIN_NAME" ]; then
    echo "ERROR: run this from the build/ dir (expected ./$BIN_NAME here)." >&2
    echo "       e.g.  cd build && ./build_eif.sh" >&2
    exit 1
fi

# --- [1] Deterministic single-layer image via docker import (NO kaniko) -----
# Normalise everything that could enter the rootfs (hence PCR): the binary lands
# at /xlayer-tee-enclave with fixed uid/gid=0, mode 0744, mtime=SOURCE_DATE_EPOCH.
# A temp staging dir gives the file its exact in-image name; its (random) path
# does not affect the tar contents.
echo "==> [1/2] Building enclave image deterministically (tar + docker import; no kaniko)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
install -m 0744 "$WORKDIR/$BIN_NAME" "$STAGE/$BIN_NAME"
tar --numeric-owner --owner=0 --group=0 \
    --mtime="@${SOURCE_DATE_EPOCH}" --sort=name \
    -C "$STAGE" -cf "$WORKDIR/rootfs.tar" "$BIN_NAME"
echo "    rootfs.tar md5 = $(md5sum "$WORKDIR/rootfs.tar" | awk '{print $1}')"

docker rmi "$IMAGE" >/dev/null 2>&1 || true
# -c 'CMD …' sets the enclave entrypoint exactly like musl/Dockerfile's CMD.
docker import -c "CMD $CMD_JSON" "$WORKDIR/rootfs.tar" "$IMAGE"

# --- [2] build-enclave with a PINNED nitro-cli ------------------------------
echo "==> [2/2] nitro-cli build-enclave -> EIF + PCR"
mkdir -p "$WORKDIR/nitro_log"

run_build_enclave_host() {
    # Pinned nitro-cli already on PATH (pre-baked in the compile image).
    local ver
    ver="$(nitro-cli --version 2>/dev/null || true)"
    echo "    host nitro-cli: $ver"
    case "$ver" in
        *"$NITRO_CLI_EXPECTED_VERSION"*) : ;;  # ok: pinned version present
        *)
            echo "ERROR: host nitro-cli is not the pinned $NITRO_CLI_EXPECTED_VERSION (got: $ver)." >&2
            echo "       Bake the pinned nitro-cli into the compile image, set" >&2
            echo "       NITRO_CLI_EXPECTED_VERSION, or use NITRO_CLI_MODE=host-src." >&2
            exit 1 ;;
    esac
    mkdir -p /var/log/nitro_enclaves 2>/dev/null || true  # nitro-cli opens its log here
    nitro-cli build-enclave --docker-uri "$IMAGE" --output-file "$WORKDIR/enclave.eif" \
        | tee "$WORKDIR/build_eif.log"
}

run_build_enclave_host_src() {
    # Build the pinned nitro-cli FROM SOURCE on the host — NO docker image.
    # PCR is fixed by NITRO_CLI_COMMIT (committed blobs/x86_64 + build-enclave
    # logic); the compiled binary's own bytes are irrelevant, so a plain host
    # cargo build is fine. Needs host: git, cargo, and openssl headers + pkg-config.
    local src bin tool
    src="${NITRO_CLI_SRC_DIR:-$WORKDIR/.nitro-cli-src}"
    bin="$src/target/release/nitro-cli"

    for tool in git cargo; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "ERROR: NITRO_CLI_MODE=host-src needs '$tool' on PATH." >&2; exit 1; }
    done

    if [ ! -d "$src/.git" ]; then
        git init -q "$src"
        git -C "$src" remote add origin "$NITRO_CLI_REPO"
    fi
    if [ "$(git -C "$src" rev-parse --verify -q HEAD 2>/dev/null)" != "$NITRO_CLI_COMMIT" ]; then
        echo "==> Fetching pinned nitro-cli source ($NITRO_CLI_COMMIT)"
        git -C "$src" config http.version HTTP/1.1
        git -C "$src" config http.postBuffer 1048576000
        ( git -C "$src" fetch --depth=1 origin "$NITRO_CLI_COMMIT" \
          || { echo 'fetch retry 1'; sleep 5;  git -C "$src" fetch --depth=1 origin "$NITRO_CLI_COMMIT"; } \
          || { echo 'fetch retry 2'; sleep 10; git -C "$src" fetch --depth=1 origin "$NITRO_CLI_COMMIT"; } )
        git -C "$src" reset --hard FETCH_HEAD
    else
        echo "    nitro-cli source already at pinned commit"
    fi

    if [ ! -x "$bin" ]; then
        echo "==> Building nitro-cli from source (host cargo; binary bytes don't affect PCR)"
        ( cd "$src" && cargo build --release --locked --bin nitro-cli )
    else
        echo "    reusing cached host-built nitro-cli ($bin)"
    fi

    export NITRO_CLI_BLOBS="$src/blobs/x86_64"
    echo "    NITRO_CLI_BLOBS=$NITRO_CLI_BLOBS (pinned by commit)"
    echo "    blobs sha256 (what actually feeds PCR0/PCR1):"
    ( cd "$NITRO_CLI_BLOBS" && sha256sum -- * 2>/dev/null | sed 's/^/      /' ) || true
    mkdir -p /var/log/nitro_enclaves 2>/dev/null || true
    "$bin" build-enclave --docker-uri "$IMAGE" --output-file "$WORKDIR/enclave.eif" \
        | tee "$WORKDIR/build_eif.log"
}

NITRO_CLI_MODE="${NITRO_CLI_MODE:-auto}"
echo "    NITRO_CLI_MODE=$NITRO_CLI_MODE"
case "$NITRO_CLI_MODE" in
    host-bin) run_build_enclave_host ;;
    host-src) run_build_enclave_host_src ;;
    auto)
        # Image-free only: pinned PATH binary, else build from the pinned commit.
        if command -v nitro-cli >/dev/null 2>&1; then
            run_build_enclave_host
        elif command -v cargo >/dev/null 2>&1 && command -v git >/dev/null 2>&1; then
            run_build_enclave_host_src
        else
            echo "ERROR: no usable nitro-cli. Need either a pinned nitro-cli on PATH," >&2
            echo "       or cargo+git to build it from the pinned commit (host-src)." >&2
            exit 1
        fi ;;
    *)
        echo "ERROR: unknown NITRO_CLI_MODE='$NITRO_CLI_MODE' (want: auto|host-bin|host-src)" >&2
        exit 1 ;;
esac

# --- Persist the measurements (PCR0/1/2) next to the EIF --------------------
grep -oE '"PCR[0-9]"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]+"' "$WORKDIR/build_eif.log" \
    | sed 's/[",]//g' > "$WORKDIR/PCR.txt" || true

echo "=========================================================="
echo " EIF:  $WORKDIR/enclave.eif"
echo " PCRs:"; cat "$WORKDIR/PCR.txt" 2>/dev/null || true
echo " (same binary + same nitro-cli MUST give the same PCR0, any host)"
echo "=========================================================="
