# Enclave rootfs image for xlayer-tee-enclave (op-succinct TEE).
#
# This image IS the enclave root filesystem: nitro-cli build-enclave packs it
# into the user ramdisk. Mirrors tradezone's approach — glibc-dynamic binary on
# a pinned slim Debian base (NOT static musl, which is painful with c-kzg/blst/
# aws-lc-sys/ring).
#
# REPRODUCIBILITY RULES:
#  - Pin the base by DIGEST (@sha256:…), never a mutable tag.
#  - Do NOT run apt-get here — installing packages at build time pulls non-pinned
#    content and breaks reproducibility. The base image must already contain the
#    runtime libs the binary needs (check `ldd` output from build.sh: typically
#    libssl, libz, libc). If it doesn't, either bake them into a pinned base
#    image, or statically link (set OPENSSL_STATIC=1 in build.sh) and switch this
#    to `FROM scratch`.
#  - --chown=0:0 --chmod=744 fixes uid/gid/perms so the OCI layer is deterministic.

# TODO: replace with YOUR pinned, runtime-lib-containing base image (digest).
FROM <your-registry>/debian/bookworm-slim

COPY --chown=0:0 --chmod=744 ./xlayer-tee-enclave /xlayer-tee-enclave

# xlayer-tee-enclave takes no CLI args; configured via env (VSOCK_PORT, etc.).
CMD ["/xlayer-tee-enclave"]
