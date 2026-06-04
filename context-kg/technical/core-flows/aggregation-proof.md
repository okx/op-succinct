---
name: "aggregation-proof"
description: "zkVM-guest aggregation flow — verify SP1/TEE range proofs, chain L1 headers, emit consolidated BootInfo"
---
# Aggregation Proof Flow

## Entry Point
`#[sp1_zkvm::entrypoint!(main)]` in `programs/aggregation/src/main.rs`.

## Primary Entities
`AggregationInputs`, `BootInfoStruct[]`, `RangeProof[]` (parallel-indexed), `multi_block_vkey[8]`, `latest_l1_checkpoint_head`, `prover_address`, `AggregationOutputs`, `VerifiedSession` (TEE only).

## State Transitions
N/A — single-shot guest program.

## Normal Flow Steps

| Step | Action | Module |
|------|--------|--------|
| 1 | Read `AggregationInputs` from stdin (includes `range_proofs[]` parallel-indexed with `boot_infos[]`) | `utils/client/src/types.rs` |
| 2 | Read L1 headers (serde_cbor encoded list) | `programs/aggregation/src/main.rs` |
| 3 | Assert parallel-index: `boot_infos.len() == range_proofs.len()` and non-empty | aggregation `main.rs` |
| 4 | Sequencing assert (`windows(2)`): `prev.l2PostRoot == curr.l2PreRoot` for every consecutive pair | aggregation `main.rs` |
| 5 | Homogeneity check: `!(has_tee && has_sp1)` — batch must be all-SP1 or all-TEE | aggregation `main.rs` |
| 6 | If TEE batch: read attestation bytes from stdin, verify AWS Nitro attestation (COSE/X.509/cert chain/root pubkey), export `VerifiedSession { signer, pcr0_hash }` | `tee/mod.rs`, `tee/attestation.rs`, `tee/cert_chain.rs` |
| 7 | Per-leaf dispatch: SP1 → `sp1_lib::verify_sp1_proof(multi_block_vkey, &boot_info_hash)`; TEE → `verify_tee_range_proof(boot_info, signature, pcr0_hash, signer)` | aggregation `main.rs`, `tee/crypto.rs` |
| 8 | Walk L1 headers backwards (`headers.iter().rev()`) — each `current_hash` must equal next header's `hash_slow()` | aggregation `main.rs` |
| 9 | Every `boot_info.l1Head` must appear in the reversed header chain (continuity check) | aggregation `main.rs` |
| 10 | Construct `AggregationOutputs` — vkey slot: SP1 → `B256::from(u32_to_u8(multi_block_vkey))`, TEE → `pcr0_hash` — and commit to public output | aggregation `main.rs` |

## Exception Branches

| Trigger | State Change | Compensation |
|---------|-------------|-------------|
| `verify_sp1_proof` fails for any range | guest panic | None — root cause is bad range proof or vkey mismatch |
| TEE leaf ecrecover signer mismatch | guest panic | None — enclave signing key does not match attestation |
| Attestation verification fails (expired cert, wrong root, bad signature) | guest panic | None — invalid or stale attestation document |
| Mixed SP1+TEE batch submitted | guest panic (homogeneity assertion) | None — proposer must submit homogeneous batches |
| L1 header chain breaks (`current_hash != header.hash_slow()`) | guest panic | None — regenerate aggregation with correct header bundle |
| Missing `boot_info.l1Head` in header chain | guest panic | None — ensure full header chain back to earliest `l1Head` |
| Sequencing mismatch | guest panic | None — re-bundle ranges; do not skip blocks |

## Flow-Specific Pitfalls

[Pitfall] Off-by-one in header linking silently breaks proof. Validation must traverse in reverse and compare `hash_slow()` strictly.

[Pitfall] `multi_block_vkey` is `[u32; 8]` (hash_u32 layout). Host-computed and guest-expected layouts must match byte-for-byte.

[Pitfall] All ranges must share the same `multi_block_vkey` — proofs from different range program versions cannot be aggregated together.

[Pitfall] Attestation bytes are read positionally from stdin (`sp1_zkvm::io::read_vec()`) only when `has_tee == true`. Reading attestation when no TEE leaf exists corrupts the stdin stream by consuming the CBOR header bytes.

[Pitfall] `pack_range_journal` 168-byte layout must match the enclave signing side byte-for-byte. Field order and endianness (l2BlockNumber is big-endian) are critical.
