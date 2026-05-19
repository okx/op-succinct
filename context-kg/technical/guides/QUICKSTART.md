---
name: "QUICKSTART"
description: "Quick start guide — prerequisites, build, run validity/fault-proof services locally with mock prover"
---

# Quick Start

## Prerequisites

- Rust nightly (`nightly-2025-09-15`, pinned in `rust-toolchain.toml`)
- [Just](https://github.com/casey/just) task runner
- [Foundry](https://getfoundry.sh/) (for smart contracts)
- System packages: `clang pkg-config libssl-dev libclang-dev protobuf-compiler jq`
- SP1 v6.1.0: `curl -L https://sp1.succinct.xyz | bash && ~/.sp1/bin/sp1up -v 6.1.0`

## Build

```bash
# Build validity proposer
just build bin="validity"

# Build fault-proof proposer and challenger
just build bin="proposer"
just build bin="challenger"

# Build all ELF programs (range + aggregation)
just build-elfs
```

The `just build` command sets `TMPDIR="$(pwd)/target/tmp"` to work around SP1 nested build issues with read-only cargo registry directories.

## Run (Mock Mode)

Mock mode uses `SP1MockVerifier` — no real proving, fast local iteration.

**Validity Proposer:**

```bash
# Required env vars (create .env):
L1_RPC=<l1_archive_node_url>
L2_RPC=<l2_execution_node_url>
L2_NODE_RPC=<l2_rollup_node_url>
L2OO_ADDRESS=<OPSuccinctL2OutputOracle_proxy>
PRIVATE_KEY=<deployer_key>
OP_SUCCINCT_MOCK=true

cargo run --bin validity --release
```

**Fault-Proof Proposer:**

```bash
# Required env vars (create .env.proposer):
L1_RPC=<url>
L2_RPC=<url>
L2_NODE_RPC=<url>
FACTORY_ADDRESS=<DisputeGameFactory_addr>
ANCHOR_STATE_REGISTRY_ADDRESS=<addr>
GAME_TYPE=42
PRIVATE_KEY=<key>
MOCK_MODE=true

cargo run --bin proposer --release
```

## Test

```bash
# Unit tests
just tests

# Fault-proof integration tests
just fp-integration-tests target="integration" da="ethereum"

# Contract tests (Foundry)
just forge-build && just fp-contract-tests

# E2E tests (Go, requires Docker)
cd tests && just test-e2e-sysgo
```

## Deploy Contracts (Local Testnet)

```bash
just deploy-mock-verifier env_file=".env"
just deploy-oracle env_file=".env"           # Validity mode
just deploy-fdg-contracts env_file=".env"    # Fault-proof mode
just vkeys                                    # Print verification key hashes
```

## DA Variants

Default is Ethereum DA. To build for other DA layers:

```bash
cargo build --release --features celestia
cargo build --release --features eigenda
```

Only one DA feature can be active per build (see ADR-002).

## Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| SP1 build fails with permission error | Nested build writes to read-only dir | Use `just build` (sets TMPDIR) |
| "missing trie node" | L1 archive node not fully synced | Wait for sync |
| L2 block validation failure | L1 head too close to batch posting | Increase L1 head offset buffer |
| EigenDA test fails | Missing SRS file | Symlink `utils/eigenda/host/resources → ../../../resources` |
