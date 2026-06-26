---
name: "env-vars"
description: "Environment variable reference — all configuration variables for validity proposer, fault-proof services, and signer"
---

# Environment Variables

All secrets must be read from environment variables — never hardcode (see `knowledge-base.md` [Rule]).

## Validity Proposer (`validity/src/env.rs`)

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `L1_RPC` | Yes | — | L1 Archive Node RPC URL |
| `L2_RPC` | Yes | — | L2 Execution Node (op-geth) RPC URL |
| `L2_NODE_RPC` | Yes | — | L2 Rollup Node (op-node) RPC URL |
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `L2OO_ADDRESS` | Yes | — | OPSuccinctL2OutputOracle proxy address |
| `OP_SUCCINCT_MOCK` | No | false | Use mock verifier (no real proving) |
| `SUBMISSION_INTERVAL` | No | 1800 | Min blocks between proof submissions |
| `MAX_CONCURRENT_PROOF_REQUESTS` | No | 1 | Max parallel proof requests |
| `MAX_CONCURRENT_WITNESS_GEN` | No | 1 | Max parallel witness generations |
| `AGG_PROOF_MODE` | No | plonk | Aggregation proof mode (`plonk` or `groth16`) |
| `LOOP_INTERVAL` | No | 60 | Main loop sleep interval (seconds) |
| `METRICS_PORT` | No | 8080 | Prometheus metrics port |

## Fault-Proof Services (`fault-proof/src/config.rs`)

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `L1_RPC` | Yes | — | L1 Archive Node RPC URL |
| `L2_RPC` | Yes | — | L2 Execution Node RPC URL |
| `L2_NODE_RPC` | Yes | — | L2 Rollup Node RPC URL |
| `FACTORY_ADDRESS` | Yes | — | DisputeGameFactory address |
| `ANCHOR_STATE_REGISTRY_ADDRESS` | Yes | — | AnchorStateRegistry address |
| `GAME_TYPE` | Yes | — | Dispute game type (uint32) |
| `MOCK_MODE` | No | false | Use mock verifier |
| `FAST_FINALITY_MODE` | No | false | Enable fast finality proving |
| `MAX_CONCURRENT_DEFENSE_TASKS` | No | 8 | Max parallel defense proving tasks |
| `PROPOSAL_INTERVAL_IN_BLOCKS` | No | 1800 | L2 blocks between game proposals |
| `TX_CONFIRMATION_TIMEOUT` | No | 60 | L1 tx confirmation timeout (seconds) |
| `FAST_FINALITY_PROVING_LIMIT` | No | 1 | Max fast finality proofs in parallel |
| `MALICIOUS_CHALLENGE_PERCENTAGE` | No | 0 | Testing: % of valid games to challenge |
| `PROPOSER_METRICS_PORT` | No | — | Prometheus metrics port for proposer |

## TZ Proposer Prove Path (`fault-proof/src/config.rs` + `tz/proposer.rs`, feature `tz`)

These govern the multi-range concurrent prove pipeline (PRF-49). They are **non-secret config**, read from env, validated at startup. `setup-tz-mock-devnet.sh` writes the first two into `.env.tz-proposer` (default `1`).

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `RANGE_SPLIT_COUNT` | No | 1 | Number of contiguous sub-ranges to split `(start, end]` into for proving. Validated 1–16 (`RangeSplitCount::MAX = 16`); non-numeric / `0` / `>16` → startup `Err("range splits must be between 1 and 16, got <value>")`. `1` is byte-equivalent to the pre-split single-segment path (INV-1a/1b). |
| `MAX_CONCURRENT_RANGE_PROOFS` | No | 1 | Max sub-range proofs in flight at once (`NonZeroUsize`). Effective concurrency = `min(MAX_CONCURRENT_RANGE_PROOFS, RANGE_SPLIT_COUNT)`. Decoupled from split count so you can split 16 but throttle to 4 to smooth prover pressure. |
| `TZ_BLOCKS_PER_FETCH` | No | 1000 | Block-fetch chunk size inside each sub-range (`tz_range_proof`). Absent / `0` / non-numeric → falls back to 1000. |
| `TZ_LOCAL_EXECUTE` | No | (unset) | `=1` runs a local CPU `execute(range_elf, stdin)` before the prover backend, per sub-range — diagnostic only (`tz: local execute OK/FAILED`). Unset = zero overhead. Uses the async `ProverClient::builder().cpu().build().await` API (NOT a blocking `CpuProver` ctor — see `pitfalls/concurrency.md`). |
| `TZ_SNAPSHOT_POLL_INTERVAL_SECS` | No | 5 | Poll interval while waiting on the Witness-Builder async snapshot replay (`core-flows/tz-prove-pipeline.md`). |

## Signer (`utils/signer/src/lib.rs` — `Signer::from_env()`)

Priority: XLayer (if `XLAYER_SIGNER_ENABLED=true`) → Local (if `PRIVATE_KEY` set).

CloudHSM and Web3Signer are not auto-detected from env — they must be configured programmatically via `Signer::new_web3_signer()` or `Signer::CloudHsmSigner()`.

### XLayer Remote Signer

| Variable | Required | Purpose |
|----------|----------|---------|
| `XLAYER_SIGNER_ENABLED` | Yes | Must be `true` to activate |
| `XLAYER_SIGNER_ENDPOINT` | Yes | Remote signer HTTP endpoint |
| `XLAYER_SIGNER_ADDRESS` | Yes | Signer address |
| `XLAYER_ACCESS_KEY` | Yes | API access key |
| `XLAYER_SECRET_KEY` | Yes | AES secret key (16/24/32 bytes) |
| `XLAYER_USER_ID` | No | 0 | User ID |
| `XLAYER_SYMBOL` | No | 2882 | Chain symbol |
| `XLAYER_PROJECT_SYMBOL` | No | 3011 | Project symbol |

### Local Signer

| Variable | Required | Purpose |
|----------|----------|---------|
| `PRIVATE_KEY` | Yes | Hex-encoded private key (dev/test only) |

## Prover Mode (`utils/proof/src/lib.rs`)

| Variable | Default | Purpose |
|----------|---------|---------|
| `SP1_PROVER` | network | Proving backend: `network` or `cluster` |

## Observability

| Variable | Default | Purpose |
|----------|---------|---------|
| `RUST_LOG` | (service defaults) | Log level filter; overrides built-in suppressions |
