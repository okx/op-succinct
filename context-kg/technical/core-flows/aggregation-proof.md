---
name: "aggregation-proof"
description: "zkVM-guest aggregation flow — verify SP1/TEE range proofs, chain L1 headers, emit consolidated BootInfo"
---
# Aggregation Proof Flow

## Entry Point
`#[sp1_zkvm::entrypoint!(main)]` in `programs/aggregation/src/main.rs`.

## Primary Entities
`AggregationInputs`, `BootInfoStruct[]`, `RangeProof[]`, `multi_block_vkey[8]`, `latest_l1_checkpoint_head`, `prover_address`, `AggregationOutputs`, `VerifiedSession`, `TrustAnchors`.

## State Transitions
N/A — single-shot guest program.

## Normal Flow Steps

| Step | Action | Module |
|------|--------|--------|
| 1 | Read `AggregationInputs` from stdin (includes `range_proofs[]` parallel-indexed with `boot_infos[]`) | `utils/client/src/types.rs` |
| 2 | Read L1 headers (serde_cbor encoded list) | `programs/aggregation/src/main.rs` |
| 3 | Assert `boot_infos.len() == range_proofs.len()` and `!boot_infos.is_empty()` | aggregation `main.rs` |
| 4 | Sequencing assert (`windows(2)`): `prev.l2PostRoot == curr.l2PreRoot` for every consecutive pair | aggregation `main.rs` |
| 5 | Detect TEE leaves: if any `RangeProof::Tee` present, read attestation bytes from stdin | aggregation `main.rs` |
| 6 | (TEE path) Run `verify_attestation`: COSE_Sign1 parse → AttestationDoc parse/validate → CertChain verify (P-384 sigs, expiry, root anchor) → extract `VerifiedSession { signer, pcr0_hash }` | `tee/attestation.rs`, `tee/cose.rs`, `tee/cert_chain.rs` |
| 7 | Per-range dispatch loop: `Sp1` → `sp1_lib::verify_sp1_proof(multi_block_vkey, &boot_info_hash)`, `Tee` → `verify_tee_range_proof(boot_info, signature, pcr0_hash, signer)` | `main.rs`, `tee/range_proof.rs` |
| 8 | Walk L1 headers backwards (`headers.iter().rev()`) — each `current_hash` must equal next header's `hash_slow()` | aggregation `main.rs` |
| 9 | Every `boot_info.l1Head` must appear in the reversed header chain (continuity check) | aggregation `main.rs` |
| 10 | Select `multiBlockVKey`: if TEE present → `pcr0_hash`, else → `u32_to_u8(multi_block_vkey)` | aggregation `main.rs` |
| 11 | Construct `AggregationOutputs { consolidated_boot_info, multi_block_vkey }` and commit to public output | aggregation `main.rs` |

## Exception Branches

| Trigger | State Change | Compensation |
|---------|-------------|-------------|
| `boot_infos.len() != range_proofs.len()` | guest panic | None — host must provide parallel-indexed arrays |
| `verify_sp1_proof` fails for any SP1 range | guest panic | None — root cause is bad range proof or vkey mismatch |
| Attestation COSE_Sign1 parse fails (bad tag, wrong array length, non-96-byte signature) | guest panic | None — attestation bytes are malformed |
| AttestationDoc validation fails (wrong digest, missing PCR0, bad pubkey, zero timestamp) | guest panic | None — attestation document is invalid or tampered |
| Certificate chain verification fails (expired cert, wrong algorithm, bad signature, untrusted root) | guest panic | None — cert chain does not anchor to AWS Nitro root |
| TEE range proof signer mismatch (`ecrecover` result ≠ session signer) | guest panic | None — range was not signed by the attested enclave |
| L1 header chain breaks (`current_hash != header.hash_slow()`) | guest panic | None — regenerate aggregation with correct header bundle |
| Missing `boot_info.l1Head` in header chain | guest panic | None — ensure full header chain back to earliest `l1Head` |
| Sequencing mismatch | guest panic | None — re-bundle ranges; do not skip blocks |

## Flow-Specific Pitfalls

[Pitfall] Off-by-one in header linking silently breaks proof. Validation must traverse in reverse and compare `hash_slow()` strictly.

[Pitfall] `multi_block_vkey` is `[u32; 8]` (hash_u32 layout). Host-computed and guest-expected layouts must match byte-for-byte.

[Pitfall] All ranges must share the same `multi_block_vkey` — proofs from different range program versions cannot be aggregated together.

[Pitfall] `AggregationInputs` serialization is positional (bincode via `sp1_zkvm::io`). Adding `range_proofs` field breaks backwards compatibility — guest and host must be deployed atomically. Mixed-version is not a valid state.

[Pitfall] Attestation bytes are read from stdin ONLY when at least one `RangeProof::Tee` is present. The read order is: `AggregationInputs` → L1 headers → attestation bytes (conditional). Host and guest must agree on this protocol.
