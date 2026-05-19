---
name: "testing"
description: "Testing topology — unit tests, integration tests, E2E tests, contract tests, and long-running tests"
---

# Testing Guide

## Test Layers

```
┌─────────────────────────────────────────────┐
│ Layer 3: E2E Tests (Go + Optimism devstack) │  tests/
│   Full L1/L2 nodes + proposer + challenger  │
├─────────────────────────────────────────────┤
│ Layer 2: Integration Tests (Rust)           │  fault-proof/tests/, utils/*/tests/
│   Real RPC calls, DA-specific logic         │
├─────────────────────────────────────────────┤
│ Layer 1: Unit Tests (Rust)                  │  Inline #[cfg(test)] modules
│   Pure logic, no external dependencies      │
└─────────────────────────────────────────────┘
```

## Layer 1: Unit Tests

```bash
just tests
# Runs: cargo t --release
# Skips: test_cycle_count_diff, test_post_to_github
```

Located inline in each crate's source files. Test aggregation logic, signer protocols, ELF embedding, and type conversions.

## Layer 2: Integration Tests

```bash
# Fault-proof integration (DA-agnostic sync tests + DA-specific tests)
just fp-integration-tests target="integration" da="ethereum"
just fp-integration-tests target="sync" da="ethereum"

# DA-specific host utility tests
just da-integration-tests da="ethereum"
just da-integration-tests da="celestia"
just da-integration-tests da="eigenda"    # Requires SRS file symlink
```

These tests call real RPCs and exercise DA-layer-specific witness generation. Requires `L1_RPC`, `L2_RPC`, `L2_NODE_RPC` env vars.

## Layer 3: E2E Tests (Go)

```bash
cd tests/

# Full suite
just test-e2e-sysgo

# Validity proposer tests only
just test-e2e-sysgo ./e2e/validity/...

# Fault-proof tests only
just test-e2e-sysgo ./e2e/faultproof/...

# Single test
just test-e2e-sysgo ./e2e/validity/... TestValidityProposer_ProveSingleRange
```

Uses Optimism devstack (`tests/optimism` submodule, `succinctlabs/optimism` fork on `op-succinct-sysgo` branch). Spins up L1/L2 nodes, deploys contracts, runs proposer/challenger.

## Contract Tests (Foundry)

```bash
just forge-build
just fp-contract-tests
# Runs: forge test in contracts/ targeting test/fp/OPSuccinctFaultDisputeGame*.t.sol
```

## Long-Running Tests

```bash
cd tests/

just long-running nodes           # L1/L2 nodes only (no proposer)
just long-running validity        # With validity proposer
just long-running faultproof      # With fault-proof proposer
just long-running faultproof-ff   # With fast finality
```

These run indefinitely for manual observation. Outputs `.env` files for connecting to the running devnet.

Optional metrics: `SYSGO_METRICS_ENABLED=true just long-running <mode>` → Grafana at `localhost:3000`, Prometheus at `localhost:9999`.

## Mock vs Real Proving

| Env Var | Value | Effect |
|---------|-------|--------|
| `OP_SUCCINCT_MOCK` | `true` | Uses `SP1MockVerifier`, no real proving |
| `SP1_PROVER` | `network` | Uses Succinct Prover Network (costs per proof) |
| `SP1_PROVER` | `cluster` | Uses self-hosted SP1 cluster |
