#!/bin/bash

set -euo pipefail

# Build image:
echo "==> Installing system dependencies"
apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    cmake \
    pkg-config \
    git \
    build-essential \
    clang \
    libclang-dev \
    protobuf-compiler \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*


echo "==> Rewriting x2 SSH dep (github) to HTTPS gitlab mirror with CI credentials"
# ssh://git@github.com/okx/x2.git is a private repo; the gitlab.okg.com mirror
# is reachable from office runners using CI_JOB_TOKEN.
git config --replace-all --global url."https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.okg.com/".insteadOf "https://gitlab.okg.com/"
git config --replace-all --global url."https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.okg.com/".insteadOf "ssh://git@gitlab.okg.com/"
sed -i "s|ssh://git@github\.com/okx/x2\.git|https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.okg.com/xlayer-dex/tradezone.git|g" Cargo.toml Cargo.lock

echo "==> Building tz-proposer"
CC=clang CXX=clang++ cargo build --release --features tz,kms --bin tz-proposer

echo "==> Copying binary to build/"
mkdir -p build
cp target/release/tz-proposer build/tz-proposer
