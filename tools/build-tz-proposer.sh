#!/usr/bin/env bash
# build-tz-proposer.sh — release-build the tz-proposer binary.
#
# `bin/tz_proposer.rs` carries `required-features = ["tz"]`, so the `--features tz`
# flag is non-optional. Output lands at `target/release/tz-proposer`.
#
# Prerequisites:
#   - System deps: clang, pkg-config, libssl-dev, protobuf-compiler
#   - Private git deps reachable (either ssh-agent loaded, or run
#     `tools/cargo-ssh-to-https.sh` first to switch to the gitlab mirror)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
while [[ "$REPO_ROOT" != "/" && ! -f "$REPO_ROOT/Cargo.toml" ]]; do
  REPO_ROOT="$(dirname "$REPO_ROOT")"
done
if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
  echo "error: could not locate Cargo.toml walking up from $SCRIPT_DIR" >&2
  exit 1
fi

cd "$REPO_ROOT"
cargo build --release --features tz --bin tz-proposer

echo
echo "binary: $REPO_ROOT/target/release/tz-proposer"
ls -lh "$REPO_ROOT/target/release/tz-proposer"
