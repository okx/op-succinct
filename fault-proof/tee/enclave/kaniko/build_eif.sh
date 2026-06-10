#!/bin/bash
# Build the enclave OCI image with Kaniko (reproducible), then assemble the EIF
# with a nitro-cli BUILT FROM A PINNED COMMIT (base's approach).
#
# Why pin nitro-cli by commit instead of using the host's:
#   `nitro-cli build-enclave` bundles the measured kernel/init/nsm blobs
#   (committed under blobs/x86_64 in aws-nitro-enclaves-cli) AND the EIF-assembly
#   logic. Both feed PCR0/PCR1. Pinning the commit fixes them -> PCR0 is the same
#   on any machine, regardless of the host's installed nitro-cli version.
#
# Note: the pinned nitro-cli runs INSIDE its own container and talks to the host
#   docker daemon via the mounted socket, so the host OS/glibc/nitro-cli version
#   are irrelevant — only the host docker daemon is used (to read enclave:latest).
#   build-enclave is a pure build op; it does NOT need the Nitro device.
#
# Run from the `build/` dir produced by build.sh (Dockerfile + xlayer-tee-enclave).
set -euo pipefail

# --- Pins -------------------------------------------------------------------
# Kaniko: the OCI image MUST be reproducible, so pin by digest.
KANIKO_IMAGE="${KANIKO_IMAGE:-gcr.io/kaniko-project/executor@sha256:4e7a52dd1f14872430652bb3b027405b8dfd17c4538751c620ac005741ef9698}"

# nitro-cli pinned by commit (base uses v1.3.3). Pins build logic + bundled blobs.
NITRO_CLI_REPO="${NITRO_CLI_REPO:-https://github.com/aws/aws-nitro-enclaves-cli.git}"
NITRO_CLI_COMMIT="${NITRO_CLI_COMMIT:-afb7264b477ad241922236dd61f1730154212034}"  # v1.3.3

# Base image used only to COMPILE + RUN the pinned nitro-cli. Its bytes do NOT
# affect PCR0 (only nitro-cli's behaviour + the committed blobs do), but pin it
# by digest anyway for a stable, offline-capable build.
NITRO_BASE_IMAGE="${NITRO_BASE_IMAGE:-amazonlinux:2023@sha256:267b42d61c8eb5537270b62ec97b73bb104708d9245d343b5eeb1d92f0f65d3d}"
NITRO_TOOL_IMAGE="nitro-cli-pinned:${NITRO_CLI_COMMIT}"

WORKDIR="$(pwd)"

# Must run from the build/ dir (produced by build.sh): it holds the simple
# enclave Dockerfile + the xlayer-tee-enclave binary. Running from the repo root
# would make kaniko pick up the repo's main multi-stage Dockerfile by mistake.
if [ ! -f "$WORKDIR/xlayer-tee-enclave" ] || [ ! -f "$WORKDIR/Dockerfile" ]; then
    echo "ERROR: run this from the build/ dir (expected ./xlayer-tee-enclave and ./Dockerfile here)." >&2
    echo "       e.g.  cd build && ./build_eif.sh" >&2
    exit 1
fi

# --- [0] Build the pinned nitro-cli tool image (cached by commit) -----------
if ! docker image inspect "$NITRO_TOOL_IMAGE" >/dev/null 2>&1; then
    echo "==> [0/3] Building pinned nitro-cli ($NITRO_CLI_COMMIT) from source"
    # VERIFY for your pinned version: the blobs path (blobs/x86_64) and the
    # NITRO_CLI_BLOBS env name — older/newer versions may differ, and base
    # applies a nitro-cli-config.patch you may also need.
    docker build --platform linux/amd64 -t "$NITRO_TOOL_IMAGE" -f - . <<DOCKERFILE
FROM ${NITRO_BASE_IMAGE}
RUN dnf install -y git rust cargo openssl-devel docker && dnf clean all
RUN git init /src && cd /src \\
 && git remote add origin ${NITRO_CLI_REPO} \\
 && git fetch --depth=1 origin ${NITRO_CLI_COMMIT} \\
 && git reset --hard FETCH_HEAD \\
 && cargo build --release --locked --bin nitro-cli \\
 && install -Dm755 target/release/nitro-cli /usr/local/bin/nitro-cli \\
 && mkdir -p /usr/share/nitro_enclaves/blobs \\
 && cp -r blobs/x86_64/* /usr/share/nitro_enclaves/blobs/ \\
 && mkdir -p /var/log/nitro_enclaves
ENV NITRO_CLI_BLOBS=/usr/share/nitro_enclaves/blobs
ENTRYPOINT []
DOCKERFILE
else
    echo "==> [0/3] Reusing pinned nitro-cli image ($NITRO_CLI_COMMIT)"
fi

# --- [1] Kaniko: Dockerfile + binary -> enclave.tar (reproducible) ----------
echo "==> [1/3] Kaniko -> enclave.tar"
docker run --rm --platform linux/amd64 \
    -v "$WORKDIR":/workspace \
    "$KANIKO_IMAGE" \
    --dockerfile=Dockerfile \
    --context=dir:///workspace \
    --destination=enclave:latest --no-push \
    --tarPath=/workspace/enclave.tar \
    --reproducible --single-snapshot
echo "    enclave.tar md5 = $(md5sum enclave.tar | awk '{print $1}')"

# --- [2] Load the image into the host docker daemon -------------------------
echo "==> [2/3] docker load enclave.tar"
docker load -i enclave.tar

# --- [3] build-enclave with the pinned nitro-cli (host docker via socket) ---
# Mount a writable log dir at /var/log/nitro_enclaves — nitro-cli opens its log
# file there at startup (E19 'Open' failure otherwise). Done at runtime so it
# works even when step [0] reused a cached tool image without that dir.
echo "==> [3/3] nitro-cli build-enclave -> EIF + PCR0 (pinned $NITRO_CLI_COMMIT)"
mkdir -p "$WORKDIR/nitro_log"
docker run --rm --platform linux/amd64 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$WORKDIR":/out \
    -v "$WORKDIR/nitro_log":/var/log/nitro_enclaves \
    "$NITRO_TOOL_IMAGE" \
    nitro-cli build-enclave --docker-uri enclave:latest --output-file /out/enclave.eif \
    | tee "$WORKDIR/build_eif.log"

# --- Persist the measurements (PCR0/1/2) next to the EIF --------------------
grep -oE '"PCR[0-9]"[[:space:]]*:[[:space:]]*"[0-9a-fA-F]+"' "$WORKDIR/build_eif.log" \
    | sed 's/[",]//g' > "$WORKDIR/PCR.txt" || true

echo "=========================================================="
echo " EIF:  $WORKDIR/enclave.eif"
echo " PCRs:"; cat "$WORKDIR/PCR.txt" 2>/dev/null || true
echo " (same binary + same NITRO_CLI_COMMIT MUST give the same PCR0, any host)"
echo "=========================================================="
