---
name: "proof-lifecycle"
description: "Proof lifecycle pitfalls — polling, timeouts, prover-backend tracking, mode mismatches"
---
# Proof Lifecycle Pitfalls

## Auction / Proving Deadlines

[Pitfall] Two deadlines drive proof cancellation: `auction_deadline` (network prover auction) and `proving_deadline` (proof completion). If either elapses, the proposer cancels (`Cancelled`) or fails (`Failed`) the request. Trigger: under-provisioned prover network. Correct approach: tune `auction_timeout` + `proving_timeout` per environment; alert on `ProofRequestTimeoutErrorCount` spikes.

## Cluster Poll Failures

[Pitfall] `utils/proof/src/lib.rs::ClusterProofHandle.consecutive_poll_failures` counts up to `MAX_CONSECUTIVE_POLL_FAILURES = 3`. After 3 consecutive errors, the proposer transitions the request to `Failed`. Trigger: cluster gateway proxy intermittent failure. Correct approach: investigate cluster health; rerun next iteration.

## Network vs Cluster Backend Tracking

[Pitfall] `validity/src/proposer.rs` writes either `proof_request_id` (BYTEA, network mode) or `cluster_proof_handle` (JSONB, cluster mode) but the schema has no `proof_mode` column. Cross-reading the wrong field returns nonsense. Trigger: switching prover backend mid-deployment. Correct approach: add an explicit `proof_mode` column; add asserts in code paths that one and only one is populated.

## CpuProver Runtime Conflict

[Pitfall] `sp1_sdk::CpuProver` creates its own tokio runtime. Calling it from inside an async context without `tokio::task::spawn_blocking` will panic. Trigger: integrating mock proving into an async test harness. Correct approach: wrap CPU prover invocations in `spawn_blocking`. Affected module: `utils/proof/src/lib.rs::cluster_setup_keys`, `execute_multi`.

## Mock vs Real Mode Mismatch

[Pitfall] `OP_SUCCINCT_MOCK=true` env switches the prover to mock mode. Trigger: dev-mode build pointed at a real verifier contract. Correct approach: contract deployment mode must match prover mode; cross-validate at startup. Affected module: `scripts/utils/src/config_common.rs`.

## Proof Mode Coverage

[Pitfall] `utils/proof/src/lib.rs` wires Compressed (range) + Plonk (agg) modes only. Other SP1 modes exist but are not validated end-to-end. Trigger: experimenting with Groth16 or other modes. Correct approach: test in stage before production.

## tx_confirmation_timeout

[Pitfall] Both `validity` and `fault-proof` default `tx_confirmation_timeout = 60s`. On congested L1, the tx may land after the timeout; the proposer retries and submits a duplicate. Trigger: mainnet congestion. Correct approach: raise to ≥180s; add idempotency guard if retries enabled.
