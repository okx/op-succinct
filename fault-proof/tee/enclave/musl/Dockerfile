# Enclave rootfs image for xlayer-tee-enclave (op-succinct TEE) — STATIC / SCRATCH.
#
# This image IS the enclave root filesystem: nitro-cli build-enclave packs it
# into the user ramdisk. The binary is a FULLY STATIC musl build (no libc / no
# ld.so / no shared objects), so the rootfs needs nothing else.
#
# Why scratch instead of the kaniko/ Debian variant:
#  - Smallest possible PCR0/PCR2 measurement surface — only your binary is
#    measured, no OS userland.
#  - No base image to pin or drift: there is literally no `@sha256` to track.
#  - The enclave talks to the host over vsock and makes NO outbound TLS, so it
#    needs no ca-certificates / /etc / DNS files. NSM attestation uses the
#    /dev/nsm device, which Nitro provides at runtime (not from this image).
#
# This is only viable because xlayer-tee-enclave has ZERO C dependencies
# (kzg-rs is pure Rust; no c-kzg/blst/openssl/ring), so musl links it 100%
# statically. If a future dependency pulls in a C/-sys crate that cannot static-
# link, switch back to the kaniko/ digest-pinned Debian base.
#
# Pairs with musl/build.sh, which produces target x86_64-unknown-linux-musl.
# --chown=0:0 --chmod=744 fixes uid/gid/perms so the OCI layer is deterministic.
#
# NOTE: if the binary ever needs a writable /tmp or extra device nodes, add them
# here (e.g. COPY an empty dir) — scratch has none.
FROM scratch

COPY --chown=0:0 --chmod=744 ./xlayer-tee-enclave /xlayer-tee-enclave

# xlayer-tee-enclave takes no CLI args; configured via env (VSOCK_PORT, etc.).
CMD ["/xlayer-tee-enclave"]
