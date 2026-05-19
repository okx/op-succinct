---
name: "utils-proof"
description: "Proof orchestration — factory dispatching to SP1 network or cluster prover, artifact-store abstraction, ELF selection by DA feature"
---
# utils/proof Module

## Responsibilities
- Top-level proof factory: select host impl by DA feature flag (`ethereum` / `celestia` / `eigenda`) via `cfg_if`.
- Initialize SP1 network prover or cluster prover (Redis + S3 via gateway proxy).
- Submit range / aggregation proofs and poll status with retry budget.
- Expose `ClusterProofHandle` (persisted JSON across restarts) and `ClusterProofConfig`.

## NOT Responsible For
- DA-specific RPC fetching — delegates to `utils/{ethereum,celestia,eigenda}/host`.
- Contract calls or transaction submission — `validity` / `fault-proof` do that.
- ELF artifact compilation — `utils/build` (currently external Docker pipeline).

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `ClusterProofConfig` | cluster RPC, artifact store config, gRPC client | Built once at startup |
| `ClusterProofHandle` | `proof_id`, `proof_output_id`, `consecutive_poll_failures` | Persisted in DB JSONB |
| `ClusterArtifactStore` (enum) | Redis + S3 backends | Compile-time selected |
| `initialize_host(fetcher)` | feature-gated factory | Returns `Arc<dyn OPSuccinctHost>` |

## Dependencies
- Refer to `arch/dependency.md`. Transitive into `host-utils` (feature gated) and `elfs`.

## Relevant Flows
- See `core-flows/validity-proposer-loop.md` for how proof handles travel through the proposer state machine.

## Module-Specific Pitfalls

[Rule] Must NOT enable multiple DA features simultaneously — `cfg_if` only emits one `initialize_host` impl.

[Pitfall] `CpuProver` creates its own tokio runtime — wrap calls in `spawn_blocking` inside async contexts (e.g. `cluster_setup_keys`, `execute_multi`).

[Pitfall] Cluster poll loop tracks both consecutive failures and an absolute deadline; reconstruct from DB JSON on restart so the deadline stays correct.

[Pitfall] Mode mismatch: only Compressed (range) + Plonk (agg) are wired in production; other SP1 proof modes exist but are not validated end-to-end.
