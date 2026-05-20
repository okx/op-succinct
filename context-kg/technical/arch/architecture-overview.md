---
name: "architecture-overview"
description: "Layer definitions, allowed/prohibited call directions, service responsibilities for op-succinct"
---
# Architecture Overview

## Layer Definitions

| Layer | Responsibilities | Allowed Calls | Prohibited Calls |
|-------|-----------------|---------------|-----------------|
| zkVM-guest (client) | Run Kona inside SP1, derive blocks, execute EVM, verify blobs, commit BootInfo | `utils/client/*`, `utils/*-client-utils`, `programs/*`, `kona-proof`, `sp1-lib` | Never call `utils/host`, `utils/signer`, `utils/proof`; no RPC; no syscalls beyond preimage oracle |
| zkVM-host (proving) | Orchestrate SP1 proving, manage ELFs, fetch RPC data, cache proofs/witnesses | `utils/host`, `utils/proof`, `utils/*-host-utils`, `scripts/prove`, `sp1-sdk` | Cannot execute as guest; cannot derive L2 state itself; never posts transactions |
| validity-proposer | Long-running service: monitor L1, request proofs, submit to `L2OutputOracle` / `DisputeGameFactory` | `proof-utils`, `signer-utils`, `host-utils`, `sqlx` (Postgres) | Never generates proofs itself; never challenges games; never depends on `fault-proof` |
| fault-proof-service | Proposer + challenger binaries against `DisputeGameFactory` / `FaultDisputeGame` | `proof-utils`, `signer-utils`, `host-utils`, alloy contract bindings | Never depends on `validity`; never builds ELF artifacts |
| remote-signer | Provide tx signatures via Web3Signer / GCP-KMS / XLayer / Local | alloy signer backends, `reqwest` (XLayer HTTP) | Never derives transactions locally; never accesses ELFs; never logs secrets |
| build-tools | Compile SP1 ELFs, embed in bindings, version metadata | `sp1-build`, file I/O | Never runs proofs; never touches RPC |
| bindings | Generate Solidity ABI bindings via `alloy-sol-types` | `alloy-sol-types` only | Never depends on other utils; read-only on ELFs |

## Service Responsibilities

| Module | Responsibility | NOT Responsible For |
|--------|---------------|---------------------|
| `op-succinct-validity` | Postgres-backed proposer daemon: enqueue range/agg proofs, submit to L2OO/DGF, manage chain lock | Generating proofs (uses `proof-utils`); signing (uses `signer-utils`); challenging games |
| `op-succinct-fp` | Fault-dispute proposer & challenger binaries; manage game DAG, prove/challenge/resolve, claim bonds. Also hosts `tz/` submodule (Cargo feature `tz`) and `tz-proposer` / `tz-challenger` binaries that target the TradeZone L2 chain via REST `/chain/confirmed_block_info` and `keccak256(blockHash ‖ stateHash)` rootClaim formula | Proposing to L2OO (different contract); managing remote-signer (uses `signer-utils`); generating SP1 proofs on the tz path in Phase 1 (suppressed via `is_owned == false` cascade — see ADR-009) |
| `op-succinct-proof-utils` | Factory: select host impl by DA feature, submit to SP1 cluster/network prover | Querying contract state; signing |
| `op-succinct-host-utils` | RPC fetching, block range planning, proof caching, metrics, telemetry | DA-specific fetching (delegated to `*-host-utils`); proof generation (delegated to `proof-utils`) |
| `op-succinct-client-utils` | Shared zkVM-guest code: boot info, oracle traits, precompiles, witness codecs | DA-specific execution (delegated to `*-client-utils`) |
| `op-succinct-ethereum-{client,host}-utils` | Ethereum-blob L2 DA derivation (`kona-derive` + `OracleBlobProvider`) | Celestia / EigenDA support |
| `op-succinct-celestia-{client,host}-utils` | Celestia DA derivation via `hana-blobstream` oracle and Celestia RPC | Ethereum / EigenDA support |
| `op-succinct-eigenda-{client,host}-utils` | EigenDA commitment verification (`hokulea`) and proof reconstruction with canoe verifier | Ethereum / Celestia support |
| `op-succinct-signer-utils` | `Signer` enum (Web3Signer / Local / GCP-KMS / XLayer) + `SignerLock` for nonce-safe sending | In-memory key management; signature caching |
| `op-succinct-proof-utils` | Submit/poll cluster proofs, abstract artifact store (Redis/S3) | Contract calls; persistent state |
| `op-succinct-build-utils` / `op-succinct-elfs` | Compile/embed SP1 ELF binaries; expose pre-built artifacts | Runtime proving; RPC |
| `op-succinct-range-utils` | Shared driver for range zkVM programs (pipeline init, executor.run, BootInfo commit) | DA-specific logic |
| `programs/range/{ethereum,celestia,eigenda}` | zkVM-guest entrypoint per DA: derive block range, commit BootInfo | Aggregation; host-side fetching |
| `programs/aggregation` | zkVM-guest aggregation: verify range proofs, chain L1 headers, emit consolidated BootInfo | DA-specific verification (delegated to range programs) |
| `scripts/prove` | CLI wrapper for manual/batch proof generation | Long-running services |
| `scripts/utils` | CLI tools for config generation, cost estimation, preflight checks | Runtime proof submission |
| `bindings` | alloy contract bindings (L2OO, DGF, FDG, AccessManager, AnchorStateRegistry) | Runtime logic |
