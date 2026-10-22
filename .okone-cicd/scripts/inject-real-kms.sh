#!/usr/bin/env bash
#
# Production-only, build-time overlay: inject the REAL ok-kms-rust SDK for the
# `--features kms` release build.
#
# The committed default manifest/lockfile point ok-kms-rust at the local
# `stubs/ok-kms-rust` fail-fast stub, so credential-less and offline checkouts
# resolve with no private git source. Only the production image build runs this
# script, which repoints that single workspace dependency line back to the real
# git source and pins its exact reviewed revision. It edits the manifest inside
# the build container only — never the committed tree.
#
# Fail-closed backstop: if this overlay is ever skipped, `--features kms` links
# the local fail-fast stub, the release binary carries the OK_KMS_STUB marker,
# and the DockerfilePro guard fails the image build (never a secret-less node,
# never plaintext).
set -euo pipefail

REV="698a016388f0ce6b618ce492b142ef77f73a22bf"
MANIFEST="Cargo.toml"
GIT_LINE='ok-kms-rust = { git = "https://gitlab.okg.com/okcoin-commons/ok-kms-rust", tag = "v1.0.1" }'

# Repoint the single workspace dependency line: local stub path -> real git source.
sed -i -E \
  's|^ok-kms-rust = \{ path = "stubs/ok-kms-rust" \}.*$|'"$GIT_LINE"'|' \
  "$MANIFEST"

# Fail loudly if the repoint did not apply (never silently link the stub in prod).
if ! grep -qF "$GIT_LINE" "$MANIFEST"; then
  echo "inject-real-kms: failed to repoint ok-kms-rust to the real git source in $MANIFEST" >&2
  exit 1
fi

# Adopt the git source into the lockfile. A targeted `cargo update -p` cannot
# switch a dependency's SOURCE (path -> git), so a full resolve must run first;
# `cargo metadata` resolves and fetches (no compile) and records the tag's exact
# commit. The build environment has gitlab.okg.com credentials, so the clone
# succeeds.
cargo metadata --format-version 1 >/dev/null

# Pin the exact reviewed revision (belt-and-suspenders: the tag already resolves
# to it; this fails loudly if the tag ever moves off the reviewed commit).
cargo update -p ok-kms-rust --precise "$REV"

echo "inject-real-kms: ok-kms-rust repointed to the real git source, pinned at $REV"
