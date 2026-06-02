#!/bin/bash
# Install ok-kms-rust into the local cargo git cache.
#
# Use this on a test machine that can't reach gitlab.okg.com but needs to
# build the x2/tradezone workspace. After install, cargo finds the cache and
# skips network fetch for ok-kms-rust.
#
# Usage:
#   ./install-ok-kms-rust.sh                  # auto-detect cargo home
#   CARGO_HOME=/custom/cargo ./install-ok-kms-rust.sh
#
# The tarball must sit next to this script.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARBALL="$SCRIPT_DIR/ok-kms-rust-cache.tar.xz"

if [[ ! -f "$TARBALL" ]]; then
  echo "error: tarball not found at $TARBALL" >&2
  exit 1
fi

# Resolve cargo home: env var > $HOME/.cargo > /root/.cargo
CARGO_HOME=${CARGO_HOME:-}
if [[ -z "$CARGO_HOME" ]]; then
  if [[ -d "$HOME/.cargo" ]]; then
    CARGO_HOME="$HOME/.cargo"
  elif [[ -d "/root/.cargo" ]]; then
    CARGO_HOME="/root/.cargo"
  else
    echo "error: cannot locate cargo home; set CARGO_HOME explicitly" >&2
    exit 1
  fi
fi

GIT_DIR="$CARGO_HOME/git"
DB_DIR="$GIT_DIR/db/ok-kms-rust-9fb8a069048fd415"
CK_DIR="$GIT_DIR/checkouts/ok-kms-rust-9fb8a069048fd415"

if [[ -d "$DB_DIR" && -d "$CK_DIR" ]]; then
  echo "ok-kms-rust cache already present at $GIT_DIR — nothing to do"
  exit 0
fi

echo "installing ok-kms-rust cache into $GIT_DIR"
mkdir -p "$GIT_DIR"
tar xJf "$TARBALL" -C "$GIT_DIR"

if [[ ! -d "$DB_DIR" || ! -d "$CK_DIR" ]]; then
  echo "error: extraction produced unexpected layout; check $GIT_DIR" >&2
  exit 1
fi

echo "done. cargo will now find ok-kms-rust locally and skip gitlab fetch."
echo "  db:        $DB_DIR"
echo "  checkouts: $CK_DIR"
