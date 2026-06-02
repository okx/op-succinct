---
name: "programs-aggregation"
description: "zkVM-guest aggregation program — verifies SP1 and TEE range proofs, chains L1 headers, emits consolidated BootInfo"
---
# programs/aggregation Module

## Responsibilities
- SP1 zkVM guest program (`#[sp1_zkvm::entrypoint!(main)]`).
- Read `AggregationInputs` from stdin (boot_infos + range_proofs + multi-block vkey + prover address).
- Per-range dispatch: `RangeProof::Sp1` → `sp1_lib::verify_sp1_proof()`, `RangeProof::Tee` → `verify_tee_range_proof()`.
- When any TEE leaf is present, read attestation bytes from stdin and run full AWS Nitro attestation verification (COSE_Sign1 → cert chain → root anchor) to extract `VerifiedSession` (signer address + PCR0 hash).
- Walk L1 headers backwards (`serde_cbor`-encoded) and verify chain continuity.
- Enforce sequencing rule: `prev.l2PostRoot == curr.l2PreRoot` (`windows(2)` iteration).
- Select `multiBlockVKey` output slot: `pcr0_hash` when TEE present, `u32_to_u8(vkey)` when SP1-only.
- Commit `AggregationOutputs` (consolidated BootInfo + multi-block vkey).

## NOT Responsible For
- DA-specific verification — delegated to range programs.
- Host-side work; runs only inside the zkVM.
- TEE/mixed-leaf host stdin construction (only SP1-only path is implemented on host side).

## Core Entities

| Entity | Key Fields | Description |
|--------|-----------|-------------|
| `RangeProof` | `Sp1` (unit), `Tee { signature: Vec<u8> }` | Per-range proof variant; `Tee` carries 65-byte secp256k1 ECDSA signature |
| `AggregationInputs` | `boot_infos[]`, `range_proofs[]`, `latest_l1_checkpoint_head`, `multi_block_vkey[8]`, `prover_address` | Stdin bundle; `boot_infos` and `range_proofs` are parallel-indexed |
| `AggregationOutputs` | Consolidated `BootInfo` (l1Head, l2PreRoot, l2PostRoot, l2BlockNumber, rollupConfigHash) + multiBlockVKey | Public output; `multiBlockVKey` carries `pcr0_hash` when TEE or `vkey` when SP1-only |
| `VerifiedSession` | `signer: Address`, `pcr0_hash: B256` | Extracted from attestation; used for per-range signer verification and output slot |
| `TrustAnchors` | `aws_root_pubkey: [u8; 96]` | P-384 root public key for AWS Nitro Enclave root cert anchor |
| `CoseSign1` | `protected`, `payload`, `signature` | COSE_Sign1 envelope (RFC 8152); accepts Tag(18) and plain array forms |
| `AttestationDoc` | `module_id`, `timestamp`, `digest`, `pcrs`, `certificate`, `cabundle`, `public_key` | AWS Nitro attestation document fields extracted from CBOR |
| `CertChain` | `certs: Vec<DER>` | X.509 certificate chain; validates P-384 signatures, expiry, basicConstraints, root anchor |

## Dependencies
- Refer to `arch/dependency.md`. Direct deps: `op-succinct-client-utils`, `sp1-lib`, `sp1-zkvm`, `serde_cbor` (L1 headers), `alloy-consensus` (`Header`), `ciborium` (COSE/attestation CBOR), `k256` (secp256k1 ecrecover, SP1-patched), `p384` (cert chain P-384 ECDSA, no SP1 patch), `x509-parser` (DER certificate parsing).

## Relevant Flows
- See `core-flows/aggregation-proof.md`.

## Module-Specific Pitfalls

[Pitfall] L1 header chain walking is backwards (`headers.iter().rev()`). Off-by-one in the linking check (`current_hash == header.hash_slow()`) breaks the entire proof silently in production.

[Pitfall] Every boot_info's `l1Head` must appear in the reversed header chain — missing one fails verification.

[Pitfall] Sequencing assertion `prev.l2PostRoot == curr.l2PreRoot` must run on every `windows(2)` pair; skipping silently proves a malformed range.

[Pitfall] `multi_block_vkey` is serialized as `[u32; 8]` (hash_u32). Mismatch between host-computed and guest-expected layout produces a verification failure with no useful error.

[Pitfall] `pack_range_journal` 168-byte commitment layout (`pcr0(32)|configHash(32)|l1Head(32)|l2BlockNumber(8 BE)|l2PreRoot(32)|l2PostRoot(32)`) must be byte-exact with the enclave signing side. A single-byte offset error causes `ecrecover` to yield a garbage address, producing a silent "signer mismatch" failure with no indication of which field is misaligned. Golden vector tests (DM-4.11/DM-4.12) are the primary defense.
**Trigger**: modifying field order, padding, or endianness in either guest or enclave packing code.
**Correct**: always update golden vector test data when changing the packing layout; run the ecrecover roundtrip test (DM-4.13) to verify end-to-end.
**Module**: `programs/aggregation/src/tee/crypto.rs`
**Source**: review-finding F-06 (Adversarial Review #3, TD Risk R-1)
**Date**: 2026-06-02
**Hit count**: 1

[Pitfall] In zkVM guest code, `.expect("msg with {i}")` does NOT interpolate `{i}` — `.expect()` takes a literal `&str`, not a format string. In this codebase where `assert!`/`expect()` is mandated for guest verification failures (see knowledge-base.md), non-interpolated panic messages lose the only diagnostic available (there is no runtime logging in zkVM). Use `assert!(cond, "cert {}: failed", i)` or `.unwrap_or_else(|| panic!("cert {}: failed", i))` when dynamic context (loop indices, field names) is needed.
**Trigger**: writing `.expect()` with `{variable}` syntax in guest code, especially in loops.
**Correct**: use `assert!` with format args, or `unwrap_or_else` with `panic!` macro.
**Module**: `programs/aggregation/src/tee/cert_chain.rs`
**Source**: review-finding F-01 (Code Review M-3)
**Date**: 2026-06-02
**Hit count**: 1
