# TZ Withdraw/ForceTx Root 贯穿与独立 Defender — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **This plan stage does NOT execute code — a later Flow stage (4.0 Execute and Validate Plan) runs it.**

**Goal:** Thread the four-field checkpoint claim `claimRoot = keccak256(blockHash ‖ appHash ‖ withdrawalRoot ‖ forceRoot)` from the Witness Builder through the SP1 range+aggregation guests, the L1 Game, and the L1 Challenger, and add an independent Defender service that answers X Layer Withdraw challenges with historical inclusion proofs — reusing TradeZone Claim Tree Core for all tree math.

**Architecture:** All new code lives inside the existing `fault-proof` crate. A host-side shared library (`fault-proof/src/tz/withdraw/`) carries the protocol types, WB v2 client, stable error enum, four-field claim codec, and a thin Claim Tree Core adapter. The Proposer/Range-Host fetches tree-boundary witnesses and feeds them to the SP1 range guest, which recomputes both tree roots via Claim Tree Core and commits the full four-field claim. The L1 Challenger validates the on-chain Game field-by-field against WB `CheckpointV2`. A new binary `tz-defender` runs an independent main loop / config / signer, driven by a mock L2-challenge-contract trait until the real ABI is ready. Everything is verified against the frozen `claim-tree-v1.json` fixture.

**Tech Stack:** Rust 2024 (workspace), `alloy-primitives`/`alloy-sol-types`, `async-trait`, `reqwest` (host only, feature-gated), SP1 zkVM (`sp1_zkvm`, no-std guest), `tz-dex`/`tz-block-processor`/`tz-primitives` + TradeZone Claim Tree Core (git deps from `github.com/okx/x2.git`), Foundry (contracts), `just` recipes.

**Spec:** `docs/superpowers/specs/2026-09-03-tz-withdraw-forcetx-root-and-defender-design.md` (APPROVED by creator 2026-09-03, round 1). Lark review doc: https://okg-block.sg.larksuite.com/docx/YyUBdnoNwoigFIxMNRulItKDgCb (recorded in `docs/superpowers/lark-review-doc.md`).

**Jira:** [TRDZN-1339](https://okcoin.atlassian.net/browse/TRDZN-1339) — `[op-succinct] 实现 Withdraw/ForceTx Root 贯穿与独立 Defender`.

**Repository / branch:** op-succinct (`https://gitlab.okg.com/github/op-succinct.git`), dev base + MR target `xl/tz-challenger-v2` (HEAD `671e055`). One branch / one MR per task; every commit subject begins exactly `[Oli] `.

---

## Global Constraints

Every task's requirements implicitly include this section. Values are copied verbatim from the spec (`§4` authoritative protocol invariants) and the repo's `context-kg/technical/knowledge-base.md`.

**Protocol invariants (spec §4 — MUST NOT change any constant):**
- `claimRoot = keccak256(blockHash ‖ appHash ‖ withdrawalRoot ‖ forceRoot)`, preimage exactly **128 bytes**. `chainId`/`blockHeight` are NOT in claimRoot. `chainId` is host-side only, must be non-zero.
- `withdrawalRoot = keccak256(innerRoot ‖ uint256(count) ‖ 0x02)`; `forceRoot = keccak256(innerRoot ‖ uint256(count) ‖ 0x01)`; outer preimage fixed **65 bytes**; `count` is big-endian right-aligned `uint256`.
- Fixed empty-tree vectors (each computed independently, never copied from one another): `emptyInnerRoot = 0x27ae5ba0…d757`; `EMPTY_FORCE_ROOT = 0x2ce29f3b…2a56`; `EMPTY_WITHDRAWAL_ROOT = 0x6b7dbdc9…76d7`.
- Incremental tree: `TREE_DEPTH = 32`; frontier = `branch[32] + count` (`count`/`leafIndex` are `u32`); parent `keccak256(left‖right)` unsorted; empty leaf `bytes32(0)`; empty subtree `z[h+1] = keccak256(z[h]‖z[h])`.
- inclusion proof = `leafIndex + count + siblings[32]`; before verifying MUST check `count > 0`, `leafIndex < count`, `siblings.len() == 32`.
- Boundary witness wire: `count == 0 ⇒ activeBranches = []`; otherwise only the branch levels set in `count`'s binary, `len == popcount(count)`, ordered low→high level, bare `bytes32` elements, no level field / no zero padding; decoder MUST validate length and rebuild the declared root, rejecting on mismatch.
- Withdraw leaf = `keccak256(abi.encode(version, chainId, transactionHash, tokenType, tokenAddress, tokenIds, amounts, from, to))` (Solidity `abi.encode`, NOT packed); V1 `recordHash == leafHash`.
- ForceTx currently has no leaves ⇒ `forceRoot = EMPTY_FORCE_ROOT` (count = 0); MUST NOT return `NotReady` merely because ForceTx is unused.
- Tree/leaf/root/proof algorithms have a single source of truth: TradeZone Claim Tree Core (agglayer `unified-bridge 0.18.0` LocalExitTree lineage). op-succinct only adds the outermost `count + tag` wrapper comparison and integration — it does NOT re-implement the inner algorithm (spec §10 non-goal, §14 criterion 5).

**Repo/toolset constraints (context-kg/technical/knowledge-base.md — highest authority):**
- zkVM guest boundary: guest crates (`programs/tz/range`, `programs/tz/aggregation`) MUST NOT import `utils/host`, `utils/signer`, `utils/proof`, or any host-side networking. The Claim Tree Core dependency used by the guest MUST be `no_std`-compatible. Host-side shared lib (network/tx) stays out of the guest.
- Signer security: production deployments MUST use `XLayerRemoteSigner`, `CloudHsmSigner` (GCP-KMS), or `Web3Signer` — never `LocalSigner`. Defender's independent signer follows this.
- Secrets: all secrets (signer key, KMS resource, endpoints with creds) MUST be read from environment variables (`fault-proof/src/config.rs` pattern); never hardcode. Any `Debug` impl over a secret redacts as `***REDACTED***`.
- Naming: alloy `sol!`-generated contract binding instances use the `*Instance` suffix (e.g. `AnchorStateRegistryInstance`).
- Feature gating: all new host code compiles behind the `tz` Cargo feature. `tz = ["dep:reqwest", "dep:thiserror", "op-succinct-proof-utils/tz"]` today; the new `tz-defender` binary declares `required-features = ["tz"]`. xlayer behavior MUST be unchanged when `tz` is OFF.

**Additional Context:** The native task inputs contain **NO Additional Context** (initial run, no rework) — spec §1. There are therefore no supplemental requirement/constraint/preference/scope-note items to materialize, and no Jira/PRD/repo conflicts to resolve. Each task below records "Additional Context: none applicable (initial run)". If a later rework round supplies creator feedback, this plan gains a delta plan (see "Feedback / Delta-Plan Protocol") and the new items are mapped there.

**Fixture-first strategy (spec §5, decision 1):** The MR must **compile and pass tests**. The only not-yet-ready external input — the X Layer L2 challenge/prove interface — is carried by a trait + in-memory mock; the Defender state machine is fully testable against mock + frozen fixture. Real ABI later replaces the mock binding without changing the state machine. Where an external crate is missing and blocks compilation, gate with the `tz` feature + trait/mock. End-to-end runtime integration against live endpoints is out of scope for this MR (belongs to post-stage-4 / ops).

**Commit/branch policy (Flow):** one feature branch, one open MR, both reused on feedback rounds. Never merge/deploy/release/force-push, never push directly to `xl/tz-challenger-v2` as a merge. Every new commit subject and the MR title begin exactly `[Oli] `. Follow repository rules for `docs/superpowers/` Git treatment (this Flow imposes no special policy; commit the spec + this plan + `lark-review-doc.md` alongside code so they travel with the MR unless the developer says otherwise).

---

## File Structure

New and modified files, each with a single clear responsibility. Grounded against the current tree (codegraph: 81,570 nodes / 247,136 edges / 3,631 files).

**New — host-side shared library `fault-proof/src/tz/withdraw/`:**
- `mod.rs` — module wiring + re-exports.
- `types.rs` — protocol types: `CheckpointV2`, `TreeBoundaryWitness`, `WithdrawRecord`, `HistoricalInclusionProof`, `GameCheckpointPreimage`, `RootComponents`-parity.
- `claim.rs` — four-field `claim_root(...)` (128-byte encode) + Game extraData (four-preimage) decode.
- `error.rs` — `WbError` stable enum + `is_retryable()`.
- `wb_client.rs` — WB v2 client: `get_checkpoint_v2`, `get_tree_boundary_witness`, `get_canonical_record`, `get_historical_inclusion_proof`; converges the existing root-format client.
- `tree_adapter.rs` — thin Claim Tree Core adapter: `calculate_inner_root`, `business_root`, `verify_proof`. No inner-algorithm copy.

**New — Defender service `fault-proof/src/tz/defender/`:**
- `mod.rs`, `config.rs` (`DefenderConfig`), `watcher.rs`, `handler.rs`, `rootmanager_client.rs`, `verifier.rs`, `cache.rs` (LRU), `challenge_contract.rs` (trait + `MockChallengeContract`).
- `fault-proof/bin/tz_defender.rs` — new binary (`required-features = ["tz"]`), independent `main()`/config/signer.

**Modified:**
- `fault-proof/src/tz/mod.rs` — `pub mod withdraw;` `pub mod defender;`.
- `fault-proof/src/tz/l2_provider.rs:18` — `compute_tz_root_claim` two-field → delegate to `withdraw::claim::claim_root` (four-field); boundary-witness fetch entry.
- `fault-proof/src/tz/proposer.rs:342-510` — `tz_prove`/`prove_range` fetch boundary witness, extend `SP1Stdin`, local four-field re-check before Game creation.
- `fault-proof/src/tz/game_validator.rs` — `TzGameValidator` reads Game four-preimage getters, calls `wb_client.get_checkpoint_v2`, validates `chainId` + field-by-field.
- `fault-proof/src/tz/config.rs` — unchanged struct; Defender adds its own `DefenderConfig`.
- `programs/tz/range/src/main.rs` — read boundary witness from stdin, rebuild pre roots, recompute post roots via Claim Tree Core, commit four-field claim (`l2PreRoot`/`l2PostRoot` semantics upgraded, ABI shape unchanged 160B).
- `programs/tz/aggregation/src/{link_check,verify}.rs` — no logic change; `windows(2)` link now binds four-field roots (add coverage only).
- `Cargo.toml` (workspace) — add TradeZone Claim Tree Core git dep (same `x2.git` rev family, no_std feature for guest).
- `fault-proof/Cargo.toml` — `[[bin]] tz-defender` + any new feature-gated deps (e.g. `lru`).
- `programs/tz/range/Cargo.toml` — add Claim Tree Core (no_std) dep.
- `fault-proof/tests/` + `programs/tz/*/` tests + `test/fixtures/claim-tree-v1.json` — fixture-driven tests.
- `contracts/config/tz/opsuccinctfdgconfig.json` — `rangeVkeyCommitment`/`aggregationVkey` refreshed after ELF rebuild (recorded as a hand-off, executed in stage 4 / ops — see Task 16).

---

## Requirement → Task Traceability

| Source criterion | Task(s) |
|---|---|
| Spec §7.1 shared lib (types/claim/error/wb_client/tree_adapter) | T1, T2, T3, T4, T5 |
| Spec §7.2 Proposer/Range-Host/Guest four-field + boundary | T6, T7, T8, T9 |
| Spec §7.3 L1 Challenger field-by-field + chainId + retry | T10 |
| Spec §7.4 Defender service + mock challenge contract + state machine | T11, T12, T13, T14 |
| Spec §7.5 config / observability / security boundary | T12, T15 |
| Spec §8 claimRoot hard-switch / vkey / ELF / redeploy blast radius | T16 (hand-off record) |
| Spec §9 fixture-driven tests (12 items) | T0 (fixture), and per-component tests in T2,T5,T8,T9,T10,T14 |
| Spec §14 success criteria 1–7 | 1→T9, 2→T8, 3→T10, 4→T11-T14, 5→T5, 6→all tests, 7→T16 |
| Jira TRDZN-1339 (Withdraw/ForceTx root threading + independent Defender) | all tasks |
| Additional Context | none applicable (initial run) — see Global Constraints |

---

## Tasks

### Task 0: Import the frozen fixture as a test resource

**Files:**
- Create: `fault-proof/tests/fixtures/claim-tree-v1.json` (copy of the frozen `claim-tree-v1.json`)
- Create: `fault-proof/tests/fixtures/README.md` (provenance: frozen, read-only, do not regenerate)

**Interfaces:**
- Produces: fixture path `fault-proof/tests/fixtures/claim-tree-v1.json` consumed by all later fixture-driven tests.

- [ ] **Step 1: Obtain the frozen fixture.** Copy `claim-tree-v1.json` (and, if provided, extract the reference vectors from `tradezone-claim-tree-reference-v1.zip`) into `fault-proof/tests/fixtures/`. Do NOT call any generator; tests read the frozen file only (spec §9).
- [ ] **Step 2: Add a provenance README** stating the file is frozen, read-only, and the single source of truth for tree/leaf/root/proof expected values.
- [ ] **Step 3: Sanity-check the JSON parses.**

Run: `cd fault-proof && cargo test --features tz fixture_loads -- --nocapture` (test added in T2 Step 1 will consume it; for now just `jq . tests/fixtures/claim-tree-v1.json > /dev/null` to confirm well-formed)
Expected: valid JSON, contains the empty-tree vectors and at least one checkpoint with Withdraw count = 5 and ForceTx count = 3 (spec §9 item 5).

- [ ] **Step 4: Commit.**

```bash
git add fault-proof/tests/fixtures/claim-tree-v1.json fault-proof/tests/fixtures/README.md
git commit -m "[Oli] test(tz): import frozen claim-tree-v1 fixture as read-only test resource"
```

**Requirement check:** spec §9 (all tests share one frozen fixture), §14 criterion 6.

---

### Task 1: Protocol types (`withdraw/types.rs`)

**Files:**
- Create: `fault-proof/src/tz/withdraw/mod.rs`
- Create: `fault-proof/src/tz/withdraw/types.rs`
- Modify: `fault-proof/src/tz/mod.rs` (add `pub mod withdraw;`)
- Test: inline `#[cfg(test)]` in `types.rs`

**Interfaces:**
- Produces (all `#[derive(Clone, Debug, PartialEq, Eq)]`, fields `pub`):
  - `CheckpointV2 { schema_version: u16, chain_id: u64, block_height: u64, block_hash: B256, app_hash: B256, withdrawal_root: B256, force_root: B256, claim_root: B256 }`
  - `TreeBoundaryWitness { schema_version: u16, chain_id: u64, block_height: u64, withdrawal_count: u32, withdrawal_active_branches: Vec<B256>, force_count: u32, force_active_branches: Vec<B256> }`
  - `WithdrawRecord { version: u16, chain_id: u64, transaction_hash: B256, token_type: u8, token_address: Address, token_ids: Vec<U256>, amounts: Vec<U256>, from: Address, to: Address }`
  - `HistoricalInclusionProof { record: WithdrawRecord, record_hash: B256, leaf_hash: B256, canonical_block_height: u64, checkpoint_height: u64, withdrawal_root: B256, leaf_index: u32, count: u32, siblings: [B256; 32] }`
  - `GameCheckpointPreimage { checkpoint_block_height: u64, parent_index: u32, block_hash: B256, app_hash: B256, withdrawal_root: B256, force_root: B256 }`

- [ ] **Step 1: Write the failing test** in `types.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256};

    #[test]
    fn boundary_witness_roundtrips_via_clone_eq() {
        let w = TreeBoundaryWitness {
            schema_version: 2,
            chain_id: 196,
            block_height: 36_000,
            withdrawal_count: 5,
            withdrawal_active_branches: vec![B256::repeat_byte(0x11), B256::repeat_byte(0x22)],
            force_count: 0,
            force_active_branches: vec![],
        };
        assert_eq!(w.clone(), w);
        // count == 0 ⇒ empty branches (spec §4 wire invariant, asserted structurally here)
        assert!(w.force_active_branches.is_empty());
    }
}
```

- [ ] **Step 2: Run the test to verify it fails.**

Run: `cd fault-proof && cargo test --features tz boundary_witness_roundtrips -- --nocapture`
Expected: FAIL — `TreeBoundaryWitness` not found.

- [ ] **Step 3: Define the structs** in `types.rs` exactly as in the Interfaces block. Add `pub mod types;` and `pub use types::*;` to `withdraw/mod.rs`; add `pub mod withdraw;` to `tz/mod.rs`. Import `alloy_primitives::{Address, B256, U256}`.
- [ ] **Step 4: Run the test to verify it passes.**

Run: `cd fault-proof && cargo test --features tz boundary_witness_roundtrips -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Format + lint.**

Run: `cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings`
Expected: no diffs, no warnings.

- [ ] **Step 6: Commit.**

```bash
git add fault-proof/src/tz/withdraw/mod.rs fault-proof/src/tz/withdraw/types.rs fault-proof/src/tz/mod.rs
git commit -m "[Oli] feat(tz/withdraw): protocol types for four-field claim, boundary witness, inclusion proof"
```

**Requirement check:** spec §7.1 (types). Additional Context: none applicable (initial run).

---

### Task 2: Four-field claimRoot codec (`withdraw/claim.rs`)

**Files:**
- Create: `fault-proof/src/tz/withdraw/claim.rs`
- Modify: `fault-proof/src/tz/withdraw/mod.rs` (`pub mod claim;`)
- Test: inline `#[cfg(test)]` + a fixture-backed test reading `tests/fixtures/claim-tree-v1.json`

**Interfaces:**
- Consumes: `GameCheckpointPreimage` (T1).
- Produces:
  - `pub fn claim_root(block_hash: B256, app_hash: B256, withdrawal_root: B256, force_root: B256) -> B256` — 128-byte `abi.encodePacked` semantics, byte-identical to contract `_checkRootClaimCommitment` (`OPSuccinctFaultDisputeGame.sol:695`) and `game_validator::compute_v3_claim_root` (`game_validator.rs:269`).
  - `pub fn decode_four_preimage_extra_data(extra: &[u8]) -> anyhow::Result<GameCheckpointPreimage>` — layout `l2BlockNumber(uint256,32) ‖ parentIndex(u32,4) ‖ blockHash(32) ‖ appHash(32) ‖ withdrawalRoot(32) ‖ forceRoot(32)` = 164 bytes; rejects a `uint256` height `> u64::MAX`.

- [ ] **Step 1: Write the failing tests** in `claim.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{keccak256, B256};

    #[test]
    fn claim_root_matches_packed_keccak_128_bytes() {
        let bh = B256::repeat_byte(0x11);
        let ah = B256::repeat_byte(0x22);
        let wr = B256::repeat_byte(0x33);
        let fr = B256::repeat_byte(0x44);
        let mut pre = [0u8; 128];
        pre[..32].copy_from_slice(bh.as_slice());
        pre[32..64].copy_from_slice(ah.as_slice());
        pre[64..96].copy_from_slice(wr.as_slice());
        pre[96..].copy_from_slice(fr.as_slice());
        assert_eq!(claim_root(bh, ah, wr, fr), keccak256(pre));
    }

    #[test]
    fn claim_root_is_order_sensitive() {
        let a = claim_root(B256::repeat_byte(1), B256::repeat_byte(2), B256::repeat_byte(3), B256::repeat_byte(4));
        let b = claim_root(B256::repeat_byte(2), B256::repeat_byte(1), B256::repeat_byte(3), B256::repeat_byte(4));
        assert_ne!(a, b);
    }

    #[test]
    fn decode_extra_data_rejects_height_over_u64() {
        let mut extra = [0u8; 164];
        extra[0] = 0x01; // top byte of uint256 set ⇒ > u64::MAX
        assert!(decode_four_preimage_extra_data(&extra).is_err());
    }

    #[test]
    fn fixture_loads() {
        let raw = include_str!("../../../tests/fixtures/claim-tree-v1.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert!(v.get("checkpoints").is_some() || v.is_object());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail.**

Run: `cd fault-proof && cargo test --features tz claim:: -- --nocapture`
Expected: FAIL — `claim_root`/`decode_four_preimage_extra_data` not defined.

- [ ] **Step 3: Implement** `claim_root` (concat 4×32 bytes, `keccak256`) and `decode_four_preimage_extra_data` (slice at the fixed offsets; the first 32 bytes are a big-endian `uint256` — bail if any of the top 24 bytes are non-zero before reading the low 8 as `u64`). Add `pub mod claim;` to `mod.rs`.
- [ ] **Step 4: Run the tests to verify they pass.**

Run: `cd fault-proof && cargo test --features tz claim:: -- --nocapture`
Expected: PASS (4 tests).

- [ ] **Step 5: Cross-check byte-parity with the existing validator** — add an assertion test that `claim_root(...)` equals `game_validator::compute_v3_claim_root` for the same components (import via a `#[cfg(test)]` helper or duplicate the 4 inputs). Run and confirm PASS.
- [ ] **Step 6: Format + lint + commit.**

```bash
cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings
git add fault-proof/src/tz/withdraw/claim.rs fault-proof/src/tz/withdraw/mod.rs
git commit -m "[Oli] feat(tz/withdraw): 128-byte claimRoot codec + 164-byte extraData decode"
```

**Requirement check:** spec §4 (128-byte preimage), §7.1 (claim.rs), §7.2 (extraData 164B layout), §9 item 1. Additional Context: none applicable.

---

### Task 3: Stable WB error enum (`withdraw/error.rs`)

**Files:**
- Create: `fault-proof/src/tz/withdraw/error.rs`
- Modify: `fault-proof/src/tz/withdraw/mod.rs` (`pub mod error;`)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces:
  - `#[derive(Debug, thiserror::Error)] pub enum WbError { InvalidRequest, UnsupportedVersion, CheckpointNotFound, WithdrawalNotFound, RecordNotInCheckpoint, NotReady, RootMismatch, WitnessStoreCorrupt, Transport(String) }` with `#[error("...")]` messages.
  - `impl WbError { pub fn is_retryable(&self) -> bool }` — `NotReady` and transient `Transport`/5xx are retryable; everything else permanent.

- [ ] **Step 1: Write the failing test:**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retryable_classification() {
        assert!(WbError::NotReady.is_retryable());
        assert!(WbError::Transport("502".into()).is_retryable());
        assert!(!WbError::RootMismatch.is_retryable());
        assert!(!WbError::WithdrawalNotFound.is_retryable());
        assert!(!WbError::WitnessStoreCorrupt.is_retryable());
    }
}
```

- [ ] **Step 2: Run — expect FAIL** (`WbError` undefined).

Run: `cd fault-proof && cargo test --features tz retryable_classification -- --nocapture`

- [ ] **Step 3: Implement** the enum with `thiserror` (already an optional `tz` dep — see `fault-proof/Cargo.toml:86,108`) and `is_retryable`.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Format + lint + commit.**

```bash
cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings
git add fault-proof/src/tz/withdraw/error.rs fault-proof/src/tz/withdraw/mod.rs
git commit -m "[Oli] feat(tz/withdraw): stable WbError enum with retryable classification"
```

**Requirement check:** spec §7.1 (error.rs), §7.3 (retry semantics), §9 item 7. Additional Context: none applicable.

---

### Task 4: Claim Tree Core adapter (`withdraw/tree_adapter.rs`)

**Files:**
- Create: `fault-proof/src/tz/withdraw/tree_adapter.rs`
- Modify: `Cargo.toml` (workspace) — add TradeZone Claim Tree Core git dep from `ssh://git@github.com/okx/x2.git` (same rev family as `tz-dex` `b3e2cf98…`, or the WB feature-branch rev; `no_std`-compatible feature for guest reuse)
- Modify: `fault-proof/Cargo.toml` — add the dep behind `tz`
- Modify: `fault-proof/src/tz/withdraw/mod.rs` (`pub mod tree_adapter;`)
- Test: fixture-backed inline test

**Interfaces:**
- Consumes: Claim Tree Core (external); `tests/fixtures/claim-tree-v1.json`.
- Produces (thin wrappers, byte-equivalent to Protocol §3.3.2 — NO inner-algorithm copy):
  - `pub fn calculate_inner_root(leaf: B256, leaf_index: u32, siblings: &[B256; 32]) -> B256`
  - `pub fn business_root(inner_root: B256, count: u32, tag: u8) -> B256` — outer 65-byte `keccak256(innerRoot ‖ uint256(count) ‖ tag)`.
  - `pub fn verify_proof(leaf: B256, leaf_index: u32, count: u32, siblings: &[B256; 32], expected_root: B256, tag: u8) -> Result<(), WbError>` — enforces `count > 0`, `leaf_index < count`, `siblings.len() == 32`, then rebuilds and compares.
  - `pub const EMPTY_INNER_ROOT: B256`, `EMPTY_WITHDRAWAL_ROOT: B256`, `EMPTY_FORCE_ROOT: B256` — each computed, asserted against fixture, never copied from one another.

- [ ] **Step 1: Write the failing fixture test:**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // Empty-tree vectors are computed by Claim Tree Core, then asserted equal to the
    // frozen fixture (spec §9 item 11 — computed independently, not copied).
    #[test]
    fn empty_vectors_match_fixture() {
        let raw = include_str!("../../../tests/fixtures/claim-tree-v1.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        let expect_w = v["emptyWithdrawalRoot"].as_str().unwrap();
        let expect_f = v["emptyForceRoot"].as_str().unwrap();
        assert_eq!(format!("{EMPTY_WITHDRAWAL_ROOT:#x}"), expect_w);
        assert_eq!(format!("{EMPTY_FORCE_ROOT:#x}"), expect_f);
        assert_ne!(EMPTY_WITHDRAWAL_ROOT, EMPTY_FORCE_ROOT);
    }

    #[test]
    fn verify_proof_rejects_bad_bounds() {
        let sibs = [B256::ZERO; 32];
        assert!(verify_proof(B256::ZERO, 0, 0, &sibs, B256::ZERO, 0x02).is_err()); // count == 0
        assert!(verify_proof(B256::ZERO, 5, 5, &sibs, B256::ZERO, 0x02).is_err()); // leaf_index == count
    }
}
```

(Adjust the fixture JSON key names in Step 3 once the real fixture keys are known from Task 0; the assertion shape stays.)

- [ ] **Step 2: Run — expect FAIL** (adapter + consts undefined, dep missing).

Run: `cd fault-proof && cargo test --features tz tree_adapter -- --nocapture`

- [ ] **Step 3: Add the Claim Tree Core git dep** to workspace `Cargo.toml` (mirroring the `tz-dex` entry at `Cargo.toml:157`) and to `fault-proof/Cargo.toml` behind `tz`. Implement the wrappers by delegating to Claim Tree Core; compute the empty vectors via the core and expose as consts. Enforce the three bound checks in `verify_proof`, returning `WbError::WitnessStoreCorrupt` / `RootMismatch` appropriately.
- [ ] **Step 4: Run — expect PASS.** If the external crate is unavailable in the build environment, gate the adapter body behind a `cfg` and keep the trait/const surface so downstream compiles (spec §5 seam rule); note the gap in the commit body.
- [ ] **Step 5: Format + lint + commit.**

```bash
cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings
git add Cargo.toml fault-proof/Cargo.toml fault-proof/src/tz/withdraw/tree_adapter.rs fault-proof/src/tz/withdraw/mod.rs
git commit -m "[Oli] feat(tz/withdraw): Claim Tree Core adapter (inner/business root, proof verify, empty vectors)"
```

**Requirement check:** spec §4, §7.1 (tree_adapter), §10 non-goal (no re-impl), §14 criterion 5, §9 items 4/5/11. Additional Context: none applicable.

---

### Task 5: WB v2 client (`withdraw/wb_client.rs`)

**Files:**
- Create: `fault-proof/src/tz/withdraw/wb_client.rs`
- Modify: `fault-proof/src/tz/withdraw/mod.rs` (`pub mod wb_client;`)
- Test: inline `#[cfg(test)]` using `wiremock` (already used in `l2_provider.rs` tests) + fixture

**Interfaces:**
- Consumes: `CheckpointV2`, `TreeBoundaryWitness`, `WithdrawRecord`, `HistoricalInclusionProof` (T1); `WbError` (T3); `tree_adapter::{business_root, verify_proof}` (T4).
- Produces:
  - `pub struct WbClient { base: reqwest::Url, http: reqwest::Client, chain_id: u64 }`
  - `pub async fn get_checkpoint_v2(&self, height: u64) -> Result<CheckpointV2, WbError>`
  - `pub async fn get_tree_boundary_witness(&self, height: u64) -> Result<TreeBoundaryWitness, WbError>`
  - `pub async fn get_canonical_record(&self, record_hash: B256) -> Result<WithdrawRecord, WbError>`
  - `pub async fn get_historical_inclusion_proof(&self, record_hash: B256, checkpoint_height: u64, withdrawal_root: B256) -> Result<HistoricalInclusionProof, WbError>`
- Boundary decode MUST validate `len == popcount(count)` and rebuild the declared root, returning `WbError::WitnessStoreCorrupt` on mismatch (spec §4).

- [ ] **Step 1: Write the failing tests** (wiremock server returns canned v2 JSON; assert fields map, and that a boundary with `activeBranches.len() != popcount(count)` yields `WbError::WitnessStoreCorrupt`; a `"status":"running"` body yields `WbError::NotReady`).
- [ ] **Step 2: Run — expect FAIL** (`WbClient` undefined).

Run: `cd fault-proof && cargo test --features tz wb_client -- --nocapture`

- [ ] **Step 3: Implement** the client. Reuse the existing `ApiEnvelope`/root-format deserialization pattern from `game_validator.rs:205` where possible; map HTTP/status → `WbError`; validate boundary length + rebuild root via `tree_adapter`. Confirm real WB v2 route names against the tradezone `feature/witness-builder-withdraw-v1` code before finalizing (spec §5, §13 open item 2) — leave a `// TODO(route): confirm against WB v2` only if the real route is not yet verifiable, and keep the wire mapping test-covered.
- [ ] **Step 4: Run — expect PASS.**
- [ ] **Step 5: Format + lint + commit.**

```bash
cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings
git add fault-proof/src/tz/withdraw/wb_client.rs fault-proof/src/tz/withdraw/mod.rs
git commit -m "[Oli] feat(tz/withdraw): WB v2 client (checkpointV2, boundary witness, canonical record, inclusion proof)"
```

**Requirement check:** spec §7.1 (wb_client), §4 (boundary wire), §9 items 1/6/7. Additional Context: none applicable.

---

### Task 6: Range-Host boundary-witness fetch + cross-check

**Files:**
- Modify: `fault-proof/src/tz/l2_provider.rs` (add boundary-witness fetch entry; wire a `WbClient` handle)
- Modify: `fault-proof/src/lib.rs` (`L2ProviderTrait` — add `fetch_tree_boundary_witness(&self, height: u64) -> Result<TreeBoundaryWitness>` with a default `unreachable!` for non-tz providers, mirroring the existing `fetch_dex_state_snapshot` pattern at `lib.rs:100`)
- Test: `l2_provider.rs` inline test (wiremock)

**Interfaces:**
- Consumes: `WbClient::get_tree_boundary_witness` (T5).
- Produces: `TzL2Provider::fetch_tree_boundary_witness(height)`; a host cross-check helper `assert_boundary_consistent(boundary, snapshot_block_hash, checkpoint_chain_id) -> Result<()>` (compares `blockHash`/`chainId` across boundary vs DexState snapshot vs CheckpointV2; error ⇒ sub-range fails + alert).

- [ ] **Step 1: Write the failing test** — provider returns a boundary; `assert_boundary_consistent` errors when `chain_id` mismatches. Run — expect FAIL.

Run: `cd fault-proof && cargo test --features tz boundary_consistency -- --nocapture`

- [ ] **Step 2: Add the trait method** (default `unreachable!`) to `L2ProviderTrait`; implement on `TzL2Provider` delegating to a held `WbClient`. Add `assert_boundary_consistent`.
- [ ] **Step 3: Run — expect PASS.**
- [ ] **Step 4: Format + lint + commit.**

```bash
cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings
git add fault-proof/src/tz/l2_provider.rs fault-proof/src/lib.rs
git commit -m "[Oli] feat(tz): range-host tree-boundary-witness fetch + blockHash/chainId cross-check"
```

**Requirement check:** spec §7.2 (Range Host), §14 criterion 1. Additional Context: none applicable.

---

### Task 7: Extend range `SP1Stdin` with boundary witness (host side)

**Files:**
- Modify: `fault-proof/src/tz/proposer.rs:451-462` (`prove_range` stdin assembly)
- Test: `proposer.rs` inline test on the pure stdin-shape helper

**Interfaces:**
- Consumes: `TzL2Provider::fetch_tree_boundary_witness` (T6).
- Produces: `prove_range` writes, after `range_stdin.write_vec(snapshot)` and `range_stdin.write(&chunk_count)`, the boundary witness fields: `write(&withdrawal_count)`, `write_vec(encode_branches(&withdrawal_active_branches))`, `write(&force_count)`, `write_vec(encode_branches(&force_active_branches))`. A pure helper `fn boundary_stdin_fields(w: &TreeBoundaryWitness) -> BoundaryStdinFields` makes the ordering unit-testable (mirrors the existing `compute_chunks` pure-function pattern at `proposer.rs:42`).

- [ ] **Step 1: Write the failing test** asserting `boundary_stdin_fields` yields counts + branch bytes in the exact order the guest will read (T8). Run — expect FAIL.
- [ ] **Step 2: Implement** the helper + splice into `prove_range` stdin (host+guest must change together — this is the vkey-affecting change, spec §8; the guest side is T8). Fetch the boundary at `start_block` before assembling stdin.
- [ ] **Step 3: Run — expect PASS.**

Run: `cd fault-proof && cargo test --features tz boundary_stdin -- --nocapture`

- [ ] **Step 4: Format + lint + commit.**

```bash
cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings
git add fault-proof/src/tz/proposer.rs
git commit -m "[Oli] feat(tz): append tree-boundary witness to range SP1Stdin (host side)"
```

**Requirement check:** spec §7.2, §8 (SP1Stdin layout change). Additional Context: none applicable.

---

### Task 8: Range guest — rebuild pre roots, recompute post roots, commit four-field claim

**Files:**
- Modify: `programs/tz/range/src/main.rs`
- Modify: `programs/tz/range/Cargo.toml` (add Claim Tree Core `no_std` dep)
- Test: `programs/tz/range/src/main.rs` inline `#[cfg(test)]` + a host-side fixture test in `fault-proof/tests/`

**Interfaces:**
- Consumes: boundary stdin fields (T7); Claim Tree Core (no_std).
- Produces: guest reads `withdrawal_count`/`withdrawal_active_branches`/`force_count`/`force_active_branches` after `chunk_count`; rebuilds pre `innerRoot`s from the active branches + zero hashes; wraps `count+tag` for pre `withdrawalRoot`/`forceRoot`; replays canonical blocks; asks Claim Tree Core to extract records/leaves and compute post roots (guest does NOT trust host-supplied leaves); computes `l2PreRoot = claim_root(pre_block_hash, pre_app_hash, pre_withdrawal_root, pre_force_root)` and `l2PostRoot = claim_root(post…)`. `BootInfoStruct` ABI shape unchanged (160B). ForceTx no leaves ⇒ empty force root (count = 0).

- [ ] **Step 1: Write the failing guest test** (host-executable, `#[cfg(test)]`): given boundary `count = 0/1/2/3/5` active branches, rebuilding yields the fixture pre root; a swapped Withdraw/ForceTx root fails (spec §9 items 4/5). Run — expect FAIL.

Run: `cd programs/tz/range && cargo test -- --nocapture`

- [ ] **Step 2: Implement** the guest read + rebuild + recompute + `claim_root` commit. Replace `keccak_join(block_hash, state_hash)` (`main.rs:57-58`) with the four-field `claim_root`. Keep `l1Head`/`rollupConfigHash` ZERO. Respect the zkVM no_std boundary (no host imports — Global Constraints).
- [ ] **Step 3: Run — expect PASS.** Also re-run the existing `boot_info_abi_encodes_to_160_bytes` test to confirm ABI shape unchanged.
- [ ] **Step 4: Add a host-side fixture test** in `fault-proof/tests/` asserting a full checkpoint (Withdraw count = 5, ForceTx count = 3) yields `claim_root == fixture.claimRoot` (spec §9 item 5). Run — expect PASS.
- [ ] **Step 5: Format + lint + commit.**

```bash
cargo fmt && cargo clippy -p tz-range-program -- -D warnings 2>/dev/null || cargo clippy --manifest-path programs/tz/range/Cargo.toml -- -D warnings
git add programs/tz/range/src/main.rs programs/tz/range/Cargo.toml fault-proof/tests/
git commit -m "[Oli] feat(tz/guest): range guest rebuilds tree roots + commits four-field claimRoot"
```

**Requirement check:** spec §7.2 (guest), §14 criterion 2, §9 items 3/4/5/6. Additional Context: none applicable.

---

### Task 9: Proposer local four-field re-check before Game creation + aggregation coverage

**Files:**
- Modify: `fault-proof/src/tz/l2_provider.rs:18-43` (`compute_tz_root_claim` → delegate to `withdraw::claim::claim_root`; `compute_output_root_at_block` builds the four-field claim)
- Modify: `fault-proof/src/tz/proposer.rs` (`prove_game`/`tz_prove` — before Game creation, locally recompute `claimRoot` and validate the 164B extraData preimage is self-consistent via `withdraw::claim`)
- Modify: `programs/tz/aggregation/src/link_check.rs` + `verify.rs` — no logic change; add N ≥ 2 coverage
- Test: `l2_provider.rs`, `proposer.rs`, `programs/tz/aggregation/` tests

**Interfaces:**
- Consumes: `withdraw::claim::{claim_root, decode_four_preimage_extra_data}` (T2); guest output (T8).
- Produces: `compute_tz_root_claim` now four-field (signature change — update the 2 call sites: `l2_provider.rs:42`, and any proposer caller); a proposer pre-Game assertion `assert_extra_data_self_consistent(&extra) -> Result<()>`.

- [ ] **Step 1: Write the failing tests:** (a) `compute_output_root_at_block` returns the four-field claim for a cached block+roots; (b) `assert_extra_data_self_consistent` fails when the encoded `claimRoot` ≠ `claim_root(fields)`; (c) aggregation `check_link` over 3 boot_infos (N ≥ 2) passes when chained and fails on a break (spec §9 item 3). Run — expect FAIL.
- [ ] **Step 2: Implement** the delegation + pre-Game re-check. Update `compute_tz_root_claim` and both call sites. Keep the existing two-field unit tests updated to the new semantics (they currently assert two-field at `l2_provider.rs:97-109` — migrate to four-field or move under a legacy `#[cfg(test)]` note).
- [ ] **Step 3: Run — expect PASS.**

Run: `cd fault-proof && cargo test --features tz claim -- --nocapture && cd ../programs/tz/aggregation && cargo test -- --nocapture`

- [ ] **Step 4: Format + lint + commit.**

```bash
cargo fmt && cargo clippy --workspace --features tz -- -D warnings
git add fault-proof/src/tz/l2_provider.rs fault-proof/src/tz/proposer.rs programs/tz/aggregation/src/link_check.rs programs/tz/aggregation/src/verify.rs
git commit -m "[Oli] feat(tz): proposer four-field claimRoot + pre-Game preimage re-check; agg N>=2 coverage"
```

**Requirement check:** spec §7.2 (build Game), §8, §14 criterion 1, §9 items 1/2/3. Additional Context: none applicable.

---

### Task 10: L1 Challenger field-by-field validation (`game_validator.rs`)

**Files:**
- Modify: `fault-proof/src/tz/game_validator.rs`
- Modify: `fault-proof/src/contract.rs` (if a four-preimage getter binding — `withdrawalRoot()/forceRoot()/blockHash()/appHash()` — is not yet bound; use `*Instance` naming per KB)
- Test: `game_validator.rs` inline `#[cfg(test)]` (extends existing wiremock tests at `game_validator.rs:380+`)

**Interfaces:**
- Consumes: `WbClient::get_checkpoint_v2` (T5); Game getters `blockHash()/appHash()/withdrawalRoot()/forceRoot()` (`OPSuccinctFaultDisputeGame.sol:660-683`) or `decode_four_preimage_extra_data` (T2).
- Produces: `TzGameValidator::validate` now (1) reads the four-preimage from the Game, (2) calls `get_checkpoint_v2(height)`, (3) asserts `checkpoint.chain_id == configured tz chain_id` (non-zero), (4) compares `block_hash/app_hash/withdrawal_root/force_root/claim_root` field-by-field → mismatch routes to the existing challenge path, (5) `WbError::NotReady`/transient → existing `AboveLocalTip`/retry backoff, never a permanent miss.

- [ ] **Step 1: Write the failing tests:** (a) all fields match ⇒ `GameValidation::Valid`; (b) a single tampered field (blockHash / appHash / withdrawalRoot / forceRoot) ⇒ challenge (invalid); (c) `chain_id` mismatch ⇒ reject; (d) `NotReady` ⇒ `Unavailable(NeedsReplay)`/retry, not a silent pass (spec §9 item 7). Run — expect FAIL.

Run: `cd fault-proof && cargo test --features tz game_validator -- --nocapture`

- [ ] **Step 2: Implement** the field-by-field comparison in `TzGameValidator`, reusing `RootQuery`/`compute_v3_claim_root` already present. Add `chain_id` to the validator's config. Preserve the existing retry/backoff (`RootQuery::Running`/`AboveLocalTip`).
- [ ] **Step 3: Run — expect PASS.**
- [ ] **Step 4: Format + lint + commit.**

```bash
cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings
git add fault-proof/src/tz/game_validator.rs fault-proof/src/contract.rs
git commit -m "[Oli] feat(tz/challenger): field-by-field checkpoint validation + chainId guard + retry-safe"
```

**Requirement check:** spec §7.3, §14 criterion 3, §9 items 2/7. Additional Context: none applicable.

---

### Task 11: Defender mock challenge-contract seam (`defender/challenge_contract.rs`)

**Files:**
- Create: `fault-proof/src/tz/defender/mod.rs`
- Create: `fault-proof/src/tz/defender/challenge_contract.rs`
- Modify: `fault-proof/src/tz/mod.rs` (`pub mod defender;`)
- Test: inline `#[cfg(test)]`

**Interfaces:**
- Produces:
  - `#[async_trait] pub trait ChallengeContract { async fn watch_opened(&self) -> Result<Vec<ChallengeOpened>>; async fn get_challenge(&self, leaf_hash: B256) -> Result<ChallengeStatus>; async fn prove_challenge(&self, leaf_hash: B256, checkpoint_height: u64, leaf_index: u32, count: u32, siblings: [B256; 32]) -> Result<TxHash>; }`
  - `pub struct ChallengeOpened { chain_id: u64, contract: Address, tx_hash: B256, log_index: u64, leaf_hash: B256 }` (identity = chain+contract+tx+logIndex, NOT leaf_hash — spec §7.4 recovery).
  - `pub struct ChallengeStatus { open: bool, deadline: u64 }`.
  - `pub struct MockChallengeContract` with methods to inject `ChallengeOpened`, script `get_challenge` status/deadline, and record `prove_challenge` calldata. Withdraw tag `0x02` is fixed inside the contract, never passed as calldata.

- [ ] **Step 1: Write the failing test** — inject an opened challenge, `watch_opened` returns it; a scripted `prove_challenge` records exact calldata. Run — expect FAIL.

Run: `cd fault-proof && cargo test --features tz challenge_contract -- --nocapture`

- [ ] **Step 2: Implement** the trait + `MockChallengeContract` (in-memory, interior-mutable via `Mutex`).
- [ ] **Step 3: Run — expect PASS. Step 4: fmt + clippy + commit.**

```bash
cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings
git add fault-proof/src/tz/defender/mod.rs fault-proof/src/tz/defender/challenge_contract.rs fault-proof/src/tz/mod.rs
git commit -m "[Oli] feat(tz/defender): ChallengeContract trait + in-memory mock (decision 1 seam)"
```

**Requirement check:** spec §5 (mock seam), §7.4 (trait). Additional Context: none applicable.

---

### Task 12: DefenderConfig + RootManager client + LRU cache + verifier

**Files:**
- Create: `fault-proof/src/tz/defender/config.rs` (`DefenderConfig`)
- Create: `fault-proof/src/tz/defender/rootmanager_client.rs`
- Create: `fault-proof/src/tz/defender/cache.rs`
- Create: `fault-proof/src/tz/defender/verifier.rs`
- Modify: `fault-proof/Cargo.toml` (add `lru` behind `tz` if not present)
- Test: inline `#[cfg(test)]` in each

**Interfaces:**
- Produces:
  - `DefenderConfig` (all secrets from env — KB constraint): `challenge_contract: Address`, `root_manager: Address`, `wb_endpoint: Url`, `chain_id: u64`, `finality_blocks: u64`, `startup_lookback: u64`, `retry_backoff: Duration`, `deadline_safety_margin: Duration`, `cache_capacity: usize`, tx-sender params. `pub fn from_env() -> Result<Self>`. Any secret field's `Debug` redacts as `***REDACTED***`.
  - `RootManagerClient::latest_finalized_covering(&self, record_height: u64) -> Result<Option<(u64, B256)>>` (reads `getLatestRoots`/`getRoots` from `TZRootManager`; returns the finalized checkpoint ≥ record_height + its withdrawalRoot).
  - `ProofCache` = LRU keyed `(leaf_hash, withdrawal_root) -> HistoricalInclusionProof`.
  - `verifier::verify_inclusion(proof: &HistoricalInclusionProof, bound_withdrawal_root: B256) -> Result<(), WbError>` (delegates to `tree_adapter::verify_proof`, tag `0x02`).

- [ ] **Step 1: Write failing tests:** `DefenderConfig::from_env` errors on missing required var and its `Debug` shows `***REDACTED***` for the signer key; `ProofCache` evicts LRU at capacity; `verify_inclusion` rejects `leaf_index == count`. Run — expect FAIL.
- [ ] **Step 2: Implement** the four modules. `from_env` mirrors `fault-proof/src/config.rs`/`tz/config.rs:parse_from` (inject a reader for tests to avoid process-env mutation — Rust 2024 `unsafe` env note at `config.rs:38`).
- [ ] **Step 3: Run — expect PASS.**

Run: `cd fault-proof && cargo test --features tz defender:: -- --nocapture`

- [ ] **Step 4: fmt + clippy + commit.**

```bash
cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings
git add fault-proof/src/tz/defender/config.rs fault-proof/src/tz/defender/rootmanager_client.rs fault-proof/src/tz/defender/cache.rs fault-proof/src/tz/defender/verifier.rs fault-proof/Cargo.toml
git commit -m "[Oli] feat(tz/defender): config(env+redaction), RootManager client, LRU proof cache, local verifier"
```

**Requirement check:** spec §7.4, §7.5 (config/security), KB signer+secret rules, §9 items 8/9. Additional Context: none applicable.

---

### Task 13: Defender watcher + handler state machine

**Files:**
- Create: `fault-proof/src/tz/defender/watcher.rs`
- Create: `fault-proof/src/tz/defender/handler.rs`
- Test: inline `#[cfg(test)]` driving the `MockChallengeContract` + fixture

**Interfaces:**
- Consumes: `ChallengeContract` (T11), `WbClient` (T5), `RootManagerClient`/`ProofCache`/`verifier` (T12).
- Produces:
  - `Watcher` — scans `ChallengeOpened`, waits configured L2 finality, supports startup lookback / safe-height rescan; dedup by `(chain, contract, tx_hash, log_index)`.
  - `Handler::handle(&self, ev: ChallengeOpened) -> HandlerOutcome` — the exact state machine of spec §7.4: finality → `get_challenge` (skip if closed) → WB canonical record by exact leaf/record hash (`WithdrawalNotFound`/`NotReady` before deadline ⇒ backoff; at deadline ⇒ stop + alert) → take canonical `recordHeight` from WB (not caller-supplied) → wait finalized RootManager checkpoint ≥ recordHeight → bind `(checkpointHeight, withdrawalRoot)` → LRU lookup else WB historical proof at that exact root → local verify (leaf match, `count > 0`, `leaf_index < count`, `siblings.len() == 32`, rebuild inner, `keccak256(inner ‖ uint256(count) ‖ 0x02) == bound withdrawalRoot`; any fail ⇒ no tx + alert) → cache verified proof → re-`get_challenge` for status+deadline → `prove_challenge` → await receipt + recheck.

- [ ] **Step 1: Write failing tests** covering the happy path and the guards: closed challenge ⇒ no tx; bad leaf/index/count/tag/sibling/root ⇒ no tx + alert; `leaf_index == count`/`count == 0`/wrong siblings length ⇒ reject (spec §9 item 8). Run — expect FAIL.
- [ ] **Step 2: Implement** `Watcher` + `Handler` against the trait (mock in tests).
- [ ] **Step 3: Run — expect PASS.**

Run: `cd fault-proof && cargo test --features tz defender::handler defender::watcher -- --nocapture`

- [ ] **Step 4: fmt + clippy + commit.**

```bash
cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings
git add fault-proof/src/tz/defender/watcher.rs fault-proof/src/tz/defender/handler.rs
git commit -m "[Oli] feat(tz/defender): watcher + single-challenge handler state machine (Protocol 6.2)"
```

**Requirement check:** spec §7.4 (state machine), §14 criterion 4, §9 items 8/9. Additional Context: none applicable.

---

### Task 14: Defender race/recovery tests + `tz_defender` binary

**Files:**
- Create: `fault-proof/bin/tz_defender.rs`
- Modify: `fault-proof/Cargo.toml` (`[[bin]] name = "tz-defender"`, `required-features = ["tz"]`)
- Test: `fault-proof/tests/` integration test orchestrating mock + fixture

**Interfaces:**
- Consumes: `DefenderConfig` (T12), `Watcher`/`Handler` (T13), reuse existing transaction sender + prometheus base.
- Produces: `tz_defender` binary with an independent `main()` / config / signer (never reads Proposer/Relayer local cache as authority; never merges with Relayer).

- [ ] **Step 1: Write failing integration tests** for: WB late record, RootManager late covering root, deadline reached with no proof, duplicate events, process restart (rescan recovery, no persisted proof cache), another Defender already responded, L2 reorg — all orchestrated via `MockChallengeContract` + frozen fixture (spec §9 item 10). Run — expect FAIL.
- [ ] **Step 2: Implement** the binary `main()` (parse `DefenderConfig::from_env`, build signer per KB rule — `XLayerRemoteSigner`/`CloudHsmSigner`/`Web3Signer`, never `LocalSigner`; spawn watcher loop). Wire prometheus/metrics/alerts (waiting-for-record, waiting-for-covering-root, verify-failure, RPC error, tx status, near-deadline, event-rescan — spec §7.5).
- [ ] **Step 3: Run — expect PASS.**

Run: `cd fault-proof && cargo test --features tz defender_integration -- --nocapture --test-threads=1`

- [ ] **Step 4: Confirm the binary builds only under `tz`.**

Run: `cargo build -p fault-proof --bin tz-defender --features tz` (expect OK) and `cargo build -p fault-proof` (expect the bin is skipped — xlayer unaffected).

- [ ] **Step 5: fmt + clippy + commit.**

```bash
cargo fmt -p fault-proof && cargo clippy -p fault-proof --features tz -- -D warnings
git add fault-proof/bin/tz_defender.rs fault-proof/Cargo.toml fault-proof/tests/
git commit -m "[Oli] feat(tz/defender): tz-defender binary + race/recovery integration tests (mock+fixture)"
```

**Requirement check:** spec §7.4, §7.5, §14 criterion 4, §9 item 10, KB signer rule. Additional Context: none applicable.

---

### Task 15: Full workspace green — regression + observability wiring

**Files:**
- Modify: touch-ups across `fault-proof/src/tz/` for metrics/log/alert coverage (spec §7.5)
- Test: whole workspace

**Interfaces:** none new — this task proves the aggregate.

- [ ] **Step 1: Run the full unit suite.**

Run: `just tests` (i.e. `cargo t --release -- --skip test_cycle_count_diff --skip test_post_to_github`)
Expected: PASS, including pre-existing proposal/prove/resolve/challenge regressions (spec §9 item 12).

- [ ] **Step 2: Run the tz-feature suite explicitly.**

Run: `cargo test --workspace --features tz -- --nocapture`
Expected: PASS; xlayer default build (`cargo test --workspace`) also PASS (feature-off unaffected).

- [ ] **Step 3: Run the contract tests** (the four-preimage Game is already implemented; confirm no regression).

Run: `just fp-contract-tests`
Expected: PASS.

- [ ] **Step 4: Lint gate.**

Run: `cargo fmt --all --check && cargo clippy --workspace --features tz -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit any observability touch-ups.**

```bash
git add -A
git commit -m "[Oli] chore(tz): observability wiring + full-workspace green (unit + contract + clippy)"
```

**Requirement check:** spec §9 item 12, §14 criterion 6. Additional Context: none applicable.

---

### Task 16: Record the ELF/vkey/deploy blast-radius hand-off (NO build/deploy here)

**Files:**
- Create: `docs/superpowers/plans/handoff-tz-elf-vkey-redeploy.md` (operational hand-off note)
- Modify: `contracts/config/tz/opsuccinctfdgconfig.json` — **only** if the executing stage rebuilds ELFs and produces new vkeys; otherwise leave for stage 4 / ops.

**Interfaces:** none — documentation + deferred config.

- [ ] **Step 1: Write the hand-off note** capturing spec §8 exactly: because the range guest stdin gains boundary fields and the committed roots become four-field, **both the range vkey and the aggregation vkey change**. Required sequence (executed by the plan-execution stage or ops, NOT this planning stage):
  1. `just build-tz-elfs` (rebuild `tz-range-elf-embedded` + `tz-aggregation-elf`).
  2. `just tz-vkeys` (regenerate vkey hashes via `cargo run --release --bin tz-config`).
  3. Update `contracts/config/tz/opsuccinctfdgconfig.json` `rangeVkeyCommitment` + `aggregationVkey` with the new hashes (current values: `rangeVkeyCommitment=0x584fd7b9…`, `aggregationVkey=0x00be73c0…`).
  4. Redeploy the tz Game config (deploy-tz). No dual-mode — wire mixing is protocol-forbidden (spec §8).
  5. Cross-process version note: the tradezone (`x2.git`) rev used to build the ELF and the Claim Tree Core version MUST match the WB side; a bump requires rebuild + redeploy (spec §12).
- [ ] **Step 2: State the invariant** that on-chain `prove` will revert on vkey mismatch until steps 1–4 complete — so the MR is build-/test-green but NOT deploy-complete (spec §14 criterion 7; §5 "produce a compile- & test-green MR").
- [ ] **Step 3: Commit.**

```bash
git add docs/superpowers/plans/handoff-tz-elf-vkey-redeploy.md
git commit -m "[Oli] docs(tz): record ELF/vkey rebuild + redeploy blast-radius hand-off (deferred to exec/ops)"
```

**Requirement check:** spec §8, §12, §14 criterion 7. Additional Context: none applicable.

---

## Build / Lint / Test Command Reference

- Unit tests (release, skipping heavy diff tests): `just tests` → `cargo t --release -- --skip test_cycle_count_diff --skip test_post_to_github`
- tz-feature unit tests: `cargo test --workspace --features tz -- --nocapture`
- Single crate: `cd fault-proof && cargo test --features tz <filter> -- --nocapture`
- Guest crate tests: `cd programs/tz/range && cargo test` · `cd programs/tz/aggregation && cargo test`
- Contract tests: `just fp-contract-tests` → `cd contracts && forge test --match-path "test/fp/OPSuccinctFaultDisputeGame*.t.sol" -vv`
- Integration tests: `just fp-integration-tests` → `cd fault-proof && cargo t --test integration --release --features integration,ethereum -- --test-threads=1 --nocapture`
- Format / lint: `cargo fmt --all --check` · `cargo clippy --workspace --features tz -- -D warnings`
- ELF rebuild (Task 16 hand-off, NOT run in this planning stage): `just build-tz-elfs` · `just tz-vkeys`

## Self-Review (completed by plan author)

- **Spec coverage:** every spec section (§4 invariants → Global Constraints; §5 fixture-first → strategy + T0/T4/T11; §6 structure → File Structure; §7.1–7.5 → T1–T5, T6–T10, T11–T15; §8 blast radius → T16; §9 twelve test items → mapped in the traceability table; §10 non-goals → honored, no contract/algorithm re-impl; §12 constraints → Global Constraints + T16; §14 seven criteria → traceability table) maps to at least one task.
- **Placeholder scan:** no "TBD/handle edge cases/similar to Task N"; every code step carries real Rust and a concrete command with expected outcome.
- **Type consistency:** `claim_root`, `TreeBoundaryWitness`, `WbError`, `ChallengeContract`, `DefenderConfig`, `HistoricalInclusionProof` names are used identically across producing and consuming tasks.
- **Additional Context:** none supplied (spec §1); recorded as inapplicable in Global Constraints and per task.

## Feedback / Delta-Plan Protocol

On a rework round, do NOT overwrite this file. Add `docs/superpowers/plans/YYYY-MM-DD-tz-withdraw-forcetx-root-and-defender-plan-delta-N.md`, link it back to this plan and to the updated spec, and map only the new creator-feedback items to added/changed tasks — preserving all prior plan files (Flow: "revise/add a clearly linked delta plan on feedback iterations while preserving prior files").

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-03-tz-withdraw-forcetx-root-and-defender-plan.md`. Execution happens in the **next Flow stage (4.0 Execute and Validate Plan)** — this planning stage does NOT run code and does NOT invoke executing-plans. When executed, subagent-driven-development (fresh subagent per task, review between tasks) is recommended over inline execution given the task count and cross-crate blast radius.
