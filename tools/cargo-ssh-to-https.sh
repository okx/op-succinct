#!/usr/bin/env bash
# cargo-ssh-to-https.sh — mirror-rewrite the x2 git URL in Cargo.toml and
# Cargo.lock so cargo fetches the tradezone source from our internal GitLab
# mirror over https instead of GitHub over ssh.
#
#   ssh://git@github.com/okx/x2.git  →  https://gitlab.okg.com/xlayer-dex/tradezone.git
#
# The two repos hold the same commit graph (gitlab mirrors github), so the
# pinned `rev = ...` in Cargo.{toml,lock} resolves to byte-identical source.
#
# Use this on build hosts that can't reach GitHub via ssh (CI runners,
# docker builds without `--ssh` agent forwarding, etc.) but can reach
# gitlab.okg.com over https.
#
# Usage:
#   ./tools/cargo-ssh-to-https.sh        # run from repo root
#   ./cargo-ssh-to-https.sh              # or from anywhere — finds repo root
#
# Idempotent: re-running after rewrite is a no-op.

set -euo pipefail

SRC='ssh://git@github.com/okx/x2.git'
DST='https://gitlab.okg.com/xlayer-dex/tradezone.git'

# Resolve repo root: look for Cargo.toml walking up from script dir.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
while [[ "$REPO_ROOT" != "/" && ! -f "$REPO_ROOT/Cargo.toml" ]]; do
  REPO_ROOT="$(dirname "$REPO_ROOT")"
done
if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
  echo "error: could not locate Cargo.toml walking up from $SCRIPT_DIR" >&2
  exit 1
fi

CARGO_TOML="$REPO_ROOT/Cargo.toml"
CARGO_LOCK="$REPO_ROOT/Cargo.lock"

# Bail early if neither file references the source URL — already rewritten.
if ! grep -qF "$SRC" "$CARGO_TOML" 2>/dev/null && \
   ! grep -qF "$SRC" "$CARGO_LOCK" 2>/dev/null; then
  echo "no '$SRC' references found — nothing to rewrite"
  exit 0
fi

# Cross-platform in-place sed: BSD sed (macOS) needs an explicit empty
# backup suffix, GNU sed (Linux) doesn't.
sed_inplace() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "$@"
  else
    sed -i "$@"
  fi
}

rewrite() {
  local target="$1"
  [[ -f "$target" ]] || return 0
  # Escape `.` and `/` for sed; use `|` as the delimiter so we don't have
  # to escape slashes in the URL itself.
  local src_escaped="${SRC//./\\.}"
  sed_inplace -e "s|${src_escaped}|${DST}|g" "$target"
}

echo "rewriting $CARGO_TOML"
rewrite "$CARGO_TOML"
echo "rewriting $CARGO_LOCK"
rewrite "$CARGO_LOCK"

echo
echo "done. Verify with:"
echo "  grep -E 'git[[:space:]]*=|source = ' Cargo.toml Cargo.lock | grep -E 'x2|tradezone'"
