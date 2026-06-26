---
name: "ADR-012-tz-prove-parallel-not-unified"
description: "tz proposer prove path mirrors the generic split→buffer_unordered→aggregate pipeline but is kept as a parallel implementation, NOT unified with generic prove_game via a shared trait — the structural duplication is intentional (bounded-context: Solidity ABI vs bincode)."
---

# ADR-012 — Keep `tz_prove` parallel to generic `prove_game` (do NOT unify via trait)

Status: Accepted
Date: 2026-06-25

## Context

PRF-49 refactored `fault-proof/src/tz/proposer.rs::tz_prove` to split `(start, end]`
into N (1–16) contiguous sub-ranges, prove each concurrently via
`stream::iter(tasks).buffer_unordered(min(max_concurrent_range_proofs, N)).try_collect()`,
reorder by index, and aggregate N compressed range proofs into one aggregation proof.

This makes `tz_prove` **structurally mirror** the generic non-tz
`prove_game` (`fault-proof/src/proposer.rs:1240-1262`): both now follow
`split → buffer_unordered → reorder → aggregate`. A natural reaction is to extract a
shared generic pipeline (a `ProofPipelineSource` / `RangeProofStdinProvider` trait) to
remove the duplication.

The two paths differ in **bounded context**, not just surface code:

- **Decode strategy**: the tz path decodes range-proof public values via **Solidity ABI**
  (`BootInfoStruct::abi_decode`), while the generic path uses **bincode**
  (`public_values.read()`). See `core-flows/tz-prove-pipeline.md` invariant #1.
- **Witness source**: tz pulls a `DexState` snapshot + tz blocks over the Witness-Builder
  REST replay protocol; generic uses the host-CLI witness path.
- **Aggregation stdin shape**: tz's `aggregation_stdin` writes no L1-head headers;
  generic `get_agg_proof_stdin` (`utils/host/src/proof.rs`) does.
- **Return shapes** and per-segment bodies differ accordingly.

## Decision

Keep `tz_prove` and generic `prove_game` as **two parallel implementations**. Do NOT
unify them under a shared trait in this change. Reuse only the genuinely-shared,
context-free primitives that already exist: `RangeSplitCount::split`, `AggregationInputs`,
`SignerLock`, and the tz-local `aggregation_stdin` helper.

## Consequences

- **[Decision]** The `tz_prove` ↔ `prove_game` structural similarity is **Coincidental /
  different-bounded-context** duplication, **NOT** Knowledge Duplication. Code reviewers
  MUST NOT flag it as a reuse/DRY violation — a shared abstraction would require
  caller-specific conditional params (decode strategy, witness source, agg-stdin shape)
  that re-introduce the coupling the split was meant to avoid.
- A future "altitude refactor" to unify the two pipelines via a strategy trait is tracked
  as a **non-blocking** future item (PRD Open Items), to be done deliberately, not as a
  drive-by.
- **Maintenance cost**: enhancements to the generic path (retry, metrics, richer error
  context) are NOT automatically inherited by tz — they must be mirrored by hand. Anyone
  improving one path should check whether the other needs the same change.
- N=1 stays byte-equivalent to the pre-refactor single-segment path (INV-1a/1b), so the
  refactor is a zero-coordination rollback (set `RANGE_SPLIT_COUNT=1`).

Source: review-finding F-07 (Adversarial Review A-15 §"Duplication"/Context-KG Impact deferral; Code Review A-08 R2 "Duplication Assessment (BE-G26)" → "Correctly NOT flagged"; PRD A-13 Open Items)
