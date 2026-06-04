---
name: "programs-aggregation"
description: "zkVM-guest aggregation program — verifies range proofs, chains L1 headers, emits consolidated BootInfo"
---
# programs/aggregation Module

## Responsibilities
- SP1 zkVM guest program (`#[sp1_zkvm::entrypoint!(main)]`).
- Read `AggregationInputs` from stdin (boot_infos + range_proofs + multi-block vkey + prover address).
- Dispatch per-leaf verification by proof type: SP1 leaves via `sp1_lib::verify_sp1_proof()`; TEE leaves via `verify_tee_range_proof()` (commitment rebuild + ecrecover + signer check).
- Enforce homogeneity constraint: a batch must be all-SP1 or all-TEE (`!(has_tee && has_sp1)`).
- When TEE leaves are present, read and verify a single AWS Nitro attestation (COSE_Sign1 + X.509 cert chain + root pubkey anchoring), exporting `signer` and `pcr0_hash`.
- Walk L1 headers backwards (`serde_cbor`-encoded) and verify chain continuity.
- Enforce sequencing rule: `prev.l2PostRoot == curr.l2PreRoot` (`windows(2)` iteration).
- Commit `AggregationOutputs` (consolidated BootInfo + multiBlockVKey slot: range vkey for SP1, PCR0 hash for TEE).

## NOT Responsible For
- DA-specific verification — delegated to range programs.
- Host-side work; runs only inside the zkVM.

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `AggregationInputs` | `boot_infos[]`, `range_proofs[]`, `latest_l1_checkpoint_head`, `multi_block_vkey[8]`, `prover_address` | Stdin bundle; `boot_infos` and `range_proofs` are parallel-indexed |
| `RangeProof` | `Sp1` or `Tee { signature: Vec<u8> }` | Per-leaf proof type discriminator (defined in `utils/client/src/types.rs`) |
| `AggregationOutputs` | Consolidated `BootInfo` (l1Head, l2PreRoot, l2PostRoot, l2BlockNumber, rollupConfigHash) + multiBlockVKey | Public output; multiBlockVKey carries range vkey (SP1) or PCR0 hash (TEE) |
| `VerifiedSession` | `signer: Address`, `pcr0_hash: B256` | Attestation-derived TEE session identity |

## Dependencies
- Refer to `arch/dependency.md`. Direct deps: `op-succinct-client-utils`, `sp1-lib`, `sp1-zkvm`, `serde_cbor`, `alloy-consensus` (`Header`), `k256` (ecrecover for TEE leaf signature), `p384` (cert chain signature verification), `ciborium` (COSE/CBOR parsing), `x509-parser` (certificate chain parsing).

## Relevant Flows
- See `core-flows/aggregation-proof.md`.

## Module-Specific Pitfalls

[Pitfall] L1 header chain walking is backwards (`headers.iter().rev()`). Off-by-one in the linking check (`current_hash == header.hash_slow()`) breaks the entire proof silently in production.

[Pitfall] Every boot_info's `l1Head` must appear in the reversed header chain — missing one fails verification.

[Pitfall] Sequencing assertion `prev.l2PostRoot == curr.l2PreRoot` must run on every `windows(2)` pair; skipping silently proves a malformed range.

[Pitfall] `multi_block_vkey` is serialized as `[u32; 8]` (hash_u32). Mismatch between host-computed and guest-expected layout produces a verification failure with no useful error.

[Pitfall] P-384 operations in TEE attestation cert chain verification run without SP1 precompile acceleration (no `p384` patch in `[patch.crates-io]`). This makes TEE batch proving significantly more cycle-expensive than SP1 batches. Profile with `sp1_zkvm::precompiles::cycle_tracker` before deploying TEE aggregation.

[Pitfall] Homogeneity assertion (`!(has_tee && has_sp1)`) must be checked before the dispatch loop. Mixed SP1/TEE batches would allow unverified leaves to pass. The assertion runs after sequential checks but before attestation read.

[Pitfall] TEE attestation bytes are read from stdin only when `has_tee == true`. Reading order is positional (`sp1_zkvm::io::read_vec()`); reading attestation when no TEE leaf exists corrupts the stdin stream (consumes CBOR headers bytes as attestation).

[Pitfall] `pack_range_journal` 168-byte layout (pcr0[0..32], configHash[32..64], l1OriginHash[64..96], l2BlockNumber[96..104] BE, prevOutputRoot[104..136], outputRoot[136..168]) must match the enclave signing side byte-for-byte. Field order or endianness mismatch causes silent proof failure.
