---
name: "utils-client"
description: "zkVM-guest shared utilities — boot info, oracle traits, precompiles, witness codecs"
---
# utils/client Module

## Responsibilities
- Compile-into-the-zkVM-guest crate shared by all `programs/range/*` and `programs/aggregation`.
- Define `BootInfoStruct`, `AggregationInputs`, `WitnessData`, `BlobData` — the wire contracts between host and guest.
- `BlobStore` — in-guest KZG blob verification.
- Custom EVM precompile factory (`precompiles/factory.rs`, `precompiles/mod.rs`) with cycle tracking.
- Oracle interface (`oracle/blob_provider.rs`) wrapping the preimage oracle for blob retrieval.
- Witness executor + preimage-store glue (`witness/executor.rs`, `witness/preimage_store.rs`).

## NOT Responsible For
- DA-specific block derivation (delegated to `utils/{ethereum,celestia,eigenda}/client`).
- Any host-side work — must not import `utils/host`, `utils/proof`, `utils/signer`, or `*-host-utils`.
- Reading external RPC — only the preimage oracle is permitted inside the zkVM.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `BootInfoStruct` | `l1Head`, `l2PreRoot`, `l2PostRoot`, `l2BlockNumber`, `rollupConfigHash` | ABI public-input struct |
| `AggregationInputs` | `boot_infos[]`, latest L1 checkpoint head, multi-block vkey, prover address | Aggregation guest input |
| `WitnessData` | preimage entries + blob data | Default rkyv-encoded witness |
| `BlobData` / `BlobStore` | KZG commitments, proofs, blob bytes | In-guest verifier |
| `PreimageStore` (in `witness/preimage_store.rs`) | preimage map + flushable cache | Oracle wrapper |

## Dependencies
- Refer to `arch/dependency.md`. Direct deps include `kona-proof`, `sp1-zkvm`, `sp1-lib`, `alloy-primitives` (sha3-keccak feature).

## Relevant Flows
- See `core-flows/range-program-execution.md` (executor.run + boot commit).
- See `core-flows/aggregation-proof.md` (verify range proofs + chain headers).

## Module-Specific Pitfalls

[Rule] No import of host/signer/proof crates is permitted — `cargo check` for the zkVM target fails immediately on such imports.

[Pitfall] `BlobStore::from(BlobData)` panics on `verify_blob_kzg_proof_batch` failure. Correct behaviour inside the guest — proof generation must fail fast on bad blobs.

[Pitfall] Blob iteration is LIFO (`Vec::pop` from reversed list). Provider order must be reversed before instantiation.

[Pitfall] `hash_rollup_config()` uses `serde_json::to_string_pretty` (deterministic). Mismatch with on-chain expected hash breaks proofs; keep the serialiser const across host/guest.
