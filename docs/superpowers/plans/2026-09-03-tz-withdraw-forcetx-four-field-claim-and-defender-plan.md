# Withdraw/ForceTx Four-Field claimRoot & Independent Defender — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Do NOT start executing until stage 3.0 (Prepare Feature Branch) has produced the working branch.

**Goal:** Thread the two new roots `withdrawalRoot` and `forceRoot` — together with the existing `blockHash`/`appHash` — into a single 128-byte four-field `claimRoot` that flows from the Witness Builder CheckpointV2/boundary witness through the SP1 range guest, L1 Game `extraData`, and the L1 Challenger; and add an independent L2 Defender service that answers X Layer Withdraw challenges using authoritative RootManager roots plus Witness Builder historical inclusion proofs.

**Architecture:** Keep the existing Proposer / L1 Challenger / Range Guest / aggregation / Game main flows intact. Add a shared protocol/codec + Witness Builder client layer under `fault-proof/src/tz/`, upgrade the four field-carrying seams (guest public values, proposer `extraData`, challenger comparison), and add a fourth binary `tz-defender` with its own main loop / config / signer. **All** leaf extraction, Merkle append, root and proof computation come from the TradeZone `tz-witness` crate (extractor `extract_withdrawals` in `tz-block-processor`) — op-succinct never implements a second tree/root/proof algorithm.

**Tech Stack:** Rust (nightly-2025-09-15), SP1 zkVM (okx/sp1 `feat/gateway-proxy-v6.1.0`), `alloy` primitives/providers, `reqwest`, `tokio`, `thiserror`, Foundry/`forge` (contract tests, non-goal to modify), `just` task runner. Upstream data crates: `tz-witness` / `tz-block-processor` / `tz-dex` / `tz-primitives` from `gitlab.okg.com/xlayer-dex/tradezone`.

**Spec:** `docs/superpowers/specs/2026-09-03-tz-withdraw-forcetx-four-field-claim-and-defender-design.md` (approved design A1-01). Lark review doc: `docs/superpowers/lark-review-doc.md` (`https://okg-block.sg.larksuite.com/docx/EpBwdZvH8oiXq6x0V0JlgQaXgxb`). Protocol/ABI authority: the four Lark docs listed in Spec §0 (conflict → Protocol body + frozen `claim-tree-v1.json` fixture).

> **Approval note:** The design file's status line reads "待创作者审批"; this is a stale brainstorming-round string. Per the Flow, stage 1.0 → 2.0 only advances on creator approval, so approval is established by the stage transition. No source conflict exists; this plan proceeds on the approved design.

---

## Global Constraints

Every task's requirements implicitly include this section. Values copied verbatim from the Spec.

- **Repo / branch:** `github/op-succinct` @ `xl/tz-challenger-v2` — both the development base and the MR target. Maintain exactly **one** feature branch and **one** open MR. Never merge / deploy / release / force-push / push directly to the target branch.
- **Commit & MR titles:** every new commit subject and the MR title begin exactly with `[Oli] `. Jira `TRDZN-1339` is the PR-metric linkage.
- **Single computation source:** the tree/root/proof algorithm lives **only** in `tz-witness`; the leaf extractor (`extract_withdrawals` / `normalize_withdraw`) lives in `tz-block-processor`. Never reimplement Merkle/root/proof/leaf-encoding in op-succinct. Dependency direction is single: `tz-block-processor → tz-witness → tz-primitives`; `tz-witness` must never `use tz_block_processor`.
- **claimRoot formula (128-byte preimage, order fixed):** `claimRoot = keccak256(abi.encodePacked(blockHash, appHash, withdrawalRoot, forceRoot))`. `blockHeight` is NOT in the claimRoot. Field order is always `blockHash, appHash, withdrawalRoot, forceRoot` — never reorder.
- **Sub-root formulas (65-byte preimages):** `withdrawalRoot = keccak256(abi.encodePacked(withdrawalInnerRoot, uint256(withdrawalCount), 0x02))`; `forceRoot = keccak256(abi.encodePacked(forceInnerRoot, uint256(forceCount), 0x01))`. Tags `0x01`/`0x02` are fixed and contract-side; callers never pass a tag.
- **Incremental tree:** `TREE_DEPTH = 32`; state = `branch[32] + count` (`count`/`leafIndex` are `u32`); empty leaf = `bytes32(0)`; `z[h+1] = keccak256(z[h] ‖ z[h])`; parent = `keccak256(left ‖ right)` (unsorted). Inclusion proof = `leafIndex + count + siblings[32]`. **Proof hard rules:** `count > 0`, `leafIndex < count`, `siblings.len() == 32`.
- **Empty-tree vectors (each language asserts, never copies across):** `emptyInnerRoot = 0x27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757`; `EMPTY_FORCE_ROOT = 0x2ce29f3bbe826db4f8ba37a99421dec3b9b590d06fd6b77b706c8a8606de2a56`; `EMPTY_WITHDRAWAL_ROOT = 0x6b7dbdc90c57dd6d1cc0ce495b921b274ffccbba3813e018b7cc843f4f6876d7`. ForceTx with no leaves ⇒ `forceRoot = EMPTY_FORCE_ROOT` (non-zero, meaning "tree exists, count=0"); never treat as NotReady.
- **Boundary witness wire:** `count == 0` ⇒ `activeBranches = []`; else only the branch levels set in `count`'s binary, length `== popcount(count)`, ordered low→high level, each fixed `bytes32`, no level field, no zero-hash padding. Decoder must validate length and rebuild the claimed root; mismatch ⇒ reject.
- **chainId:** NOT in CheckpointV2 and NOT in claimRoot/boundary. It is returned at the **top level** of the checkpoint RPC response (`SnapshotQueryResponse.chain_id`, bare `u64`, non-zero) and used only for host/challenger cross-checks that data belongs to the correct TZ chain.
- **Dependency pin:** tz-* crates use a **fixed `rev=<commit>`** (not `branch=`). Resolve the exact commit from `feature/witness-builder-withdraw-v1` HEAD at implementation time and write it back into this plan and `Cargo.toml`.
- **SP1 guest compile gate (hard):** before expanding guest work, the range guest must pass `cargo check` on the **SP1 guest target** (`rayon` disabled under zkvm/tee feature, `verify_pool=None` compiles, `tz-primitives` deps compile under guest). No paper-only claims.
- **Non-goals:** do NOT implement/refactor L1/L2 contracts (integrate against the final ABI in `contracts/src/fp` only); do NOT implement a second Claim/Merkle tree; Defender does NOT create L1 Games, generate Withdrawal Roots, or perform timeout settlement; do NOT change appHash execution semantics or checkpoint cadence.
- **Toolchain / prove ELF change:** any guest program change alters the SP1 range ELF and `rangeVkeyCommitment`; the ELF must be rebuilt and the fdg-config vkey commitment updated (Task 9). Toolchain is pinned `nightly-2025-09-15`.

### Standard command reference (used by every task)

- Format: `cargo fmt --all`
- Lint: `cargo clippy -p op-succinct-fp --features tz --all-targets -- -D warnings`
- Rust unit tests (tz): `cargo test -p op-succinct-fp --features tz`
- Guest unit tests (host target): `cargo test -p tz-range-program` / `cargo test -p tz-aggregation-program` (package names per `programs/tz/*/Cargo.toml`)
- SP1 guest compile gate: `cd programs/tz/range && ~/.sp1/bin/cargo-prove prove build --elf-name tz-range-elf-embedded --output-directory ../../../elf` (or the crate's `cargo prove` check path)
- Build tz ELFs: `just build-tz-elfs`  ·  Regenerate vkeys: `just tz-vkeys` (`cargo run --release --bin tz-config`)
- Contract tests (non-goal to modify, run for regression): `just fp-contract-tests`
- FP integration tests: `just fp-integration-tests`

---

## File Structure (created / modified)

**Created**
- `fault-proof/src/tz/protocol/mod.rs` — protocol module root; re-exports types + `compute_claim_root`.
- `fault-proof/src/tz/protocol/claim_root.rs` — four-field claimRoot / sub-root codec (single implementation).
- `fault-proof/src/tz/protocol/checkpoint.rs` — `CheckpointV2`, `SnapshotQueryResponse`, `TreeBoundaryWitness`.
- `fault-proof/src/tz/protocol/record.rs` — `CanonicalRecord`, `HistoricalInclusionProof`, `WithdrawRecord` (mirror), Game extraData four-field preimage type.
- `fault-proof/src/tz/protocol/error.rs` — stable `WitnessError` enum + retryability classifier.
- `fault-proof/src/tz/witness_client.rs` — Witness Builder 4-endpoint read client.
- `fault-proof/src/tz/defender/mod.rs` — Defender module root.
- `fault-proof/src/tz/defender/watcher.rs` — `ChallengeOpened` watcher (+ startup lookback rescan).
- `fault-proof/src/tz/defender/handler.rs` — per-challenge handler task.
- `fault-proof/src/tz/defender/verifier.rs` — local proof verifier (wraps `tz_witness::verify_proof`).
- `fault-proof/src/tz/defender/cache.rs` — LRU proof cache keyed `(leafHash, withdrawalRoot)`.
- `fault-proof/src/tz/defender/config.rs` — `TzDefenderConfig`.
- `fault-proof/bin/tz_defender.rs` — the fourth binary.
- `tests/tz_cross_language/` (or `fault-proof/tests/tz_cross_language.rs`) — Solidity↔Rust fixture parity harness.

**Modified**
- `Cargo.toml:155-158` — switch tz-* git source to tradezone feature branch, fixed rev; add `tz-witness`.
- `fault-proof/Cargo.toml` — add `[[bin]] tz-defender`; add `lru` (Defender cache) under the `tz` feature; extend `tz` feature deps if needed.
- `fault-proof/src/tz/mod.rs:21-24` — add `pub mod protocol; pub mod witness_client; pub mod defender;`.
- `fault-proof/src/tz/l2_provider.rs:18-43` — replace/augment two-field root with four-field `compute_claim_root`; upgrade `compute_output_root_at_block`.
- `fault-proof/src/tz/proposer.rs:63-108,420-501` — boundary plumbing into `range_stdin`; 164-byte four-field `extra_data`; pre-submit local re-verify.
- `fault-proof/src/tz/chain_client.rs` — extend for CheckpointV2/schemaVersion=2 + top-level chainId parse (or delegate to `witness_client.rs`).
- `fault-proof/src/tz/game_validator.rs:90-267` — schemaVersion=2 query, top-level chainId guard, field-by-field comparison.
- `fault-proof/src/tz/config.rs` — Proposer-side chainId if needed; keep `TzConfig` shape.
- `fault-proof/src/config.rs:405-430` — add `chain_id: u64` to `TzGameValidatorConfig`.
- `programs/tz/range/src/main.rs` — four-field claimRoot pre/post; boundary private inputs; `tz-witness` append/root + `extract_withdrawals`.
- fdg-config (deployment config carrying `rangeVkeyCommitment`) — updated in Task 9.

---

## Task 1: Switch tz-* dependency source to tradezone feature branch + add `tz-witness` + guest compile gate

Satisfies **AC-1**, **AC-3** and Spec §8. This is foundational and the largest landing risk (Spec §12); do it first and prove the guest still compiles before any behavior change.

**Files:**
- Modify: `Cargo.toml:155-158`
- Modify: `fault-proof/Cargo.toml` (if `tz-witness` is consumed by fault-proof)
- Test: guest compile gate (command-based, no unit test file)

**Interfaces:**
- Consumes: nothing (baseline).
- Produces: workspace deps `tz-block-processor`, `tz-dex`, `tz-primitives`, **`tz-witness`** all resolving to `gitlab.okg.com/xlayer-dex/tradezone` at one fixed `rev`. Downstream tasks import `tz_witness::{calculate_inner_root, business_root, verify_proof, <append API>}` and `tz_block_processor::extract_withdrawals`.

- [ ] **Step 1: Resolve the exact commit of the feature branch**

Run and record the HEAD commit of `feature/witness-builder-withdraw-v1`:
```bash
git ls-remote https://gitlab.okg.com/xlayer-dex/tradezone.git refs/heads/feature/witness-builder-withdraw-v1
```
Write the resolved 40-hex `<REV>` into this plan (replace every `<REV>` below) and into `Cargo.toml`.

- [ ] **Step 2: Edit `Cargo.toml` dependency source (fixed rev, not branch)**

Replace lines 155-158:
```toml
# tradezone (range guest deps) — TradeZone GitLab feature branch, fixed rev (WB Withdraw/Force work)
tz-block-processor = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "<REV>", features = ["tee"] }
tz-dex             = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "<REV>", features = ["zkvm"] }
tz-primitives      = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "<REV>" }
tz-witness         = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "<REV>" }
```
> Verify the crate names/paths (`crates/witness`) and required feature flags against the branch's `Cargo.toml` before committing (Spec §7.4: re-verify target branch at implementation time).

- [ ] **Step 3: Lock the workspace and confirm resolution**

Run: `cargo update -p tz-witness --precise <REV>` is not needed (rev-pinned); instead run `cargo metadata --format-version 1 >/dev/null` and confirm all four crates resolve to `<REV>` with no `b3e2cf98` remnant:
```bash
grep -n "tradezone" Cargo.lock | head ; ! grep -q "x2.git" Cargo.lock && echo "OK: no x2 remnant"
```
Expected: four `tradezone` entries at `<REV>`, no `x2.git`.

- [ ] **Step 4: Host-target build gate**

Run: `cargo build -p op-succinct-fp --features tz`
Expected: compiles (extractor `extract_withdrawals` + `tz-witness` API now present on the branch).

- [ ] **Step 5: SP1 guest-target compile gate (hard, Spec §8)**

Run: `cd programs/tz/range && ~/.sp1/bin/cargo-prove prove build --elf-name tz-range-elf-embedded --output-directory ../../../elf`
Expected: guest ELF builds — proving `rayon` is disabled under zkvm/tee, `verify_pool=None` compiles, and `tz-primitives` (chrono / serde_json / base64 / rust_decimal) compile under the guest target. If it fails, stop and resolve feature-flag gating before proceeding (this gate protects all later guest tasks).

- [ ] **Step 6: Commit**
```bash
git add Cargo.toml Cargo.lock fault-proof/Cargo.toml
git commit -m "[Oli] deps: source tz-* from tradezone feature branch (fixed rev), add tz-witness"
```

**Requirement check:** AC-1/AC-3 satisfied (source switched off x2 mirror to tradezone feature branch, fixed rev); `tz-witness` available; guest compiles. Spec §8 "编译门槛" met.

---

## Task 2: Shared protocol types + single claimRoot codec

Satisfies Spec §5.1 (types + `compute_claim_root`), §2 (frozen formulas), §6 (invariants).

**Files:**
- Create: `fault-proof/src/tz/protocol/mod.rs`, `claim_root.rs`, `checkpoint.rs`, `record.rs`, `error.rs`
- Modify: `fault-proof/src/tz/mod.rs:21-24` (add `pub mod protocol;`)
- Test: inline `#[cfg(test)]` in `claim_root.rs`, `checkpoint.rs`, `error.rs`

**Interfaces:**
- Consumes: `tz-witness` types (Task 1) for `WithdrawRecord` mirror shape; `alloy_primitives::{B256, U256, keccak256}`.
- Produces (exact signatures later tasks rely on):
  - `pub fn compute_claim_root(block_hash: B256, app_hash: B256, withdrawal_root: B256, force_root: B256) -> B256` (128-byte preimage).
  - `pub fn compute_withdrawal_root(inner: B256, count: u32) -> B256` (65-byte, tag `0x02`); `pub fn compute_force_root(inner: B256, count: u32) -> B256` (65-byte, tag `0x01`).
  - `pub const EMPTY_INNER_ROOT/EMPTY_FORCE_ROOT/EMPTY_WITHDRAWAL_ROOT: B256`.
  - `pub struct CheckpointV2 { pub schema_version: u8, pub block_height: u64, pub block_hash: B256, pub app_hash: B256, pub withdrawal_root: B256, pub force_root: B256, pub claim_root: B256 }`.
  - `pub struct SnapshotQueryResponse { pub checkpoint: CheckpointV2, pub chain_id: u64 }`.
  - `pub struct TreeBoundaryWitness { pub schema_version: u8, pub block_height: u64, pub block_hash: B256, pub withdrawal_count: u32, pub withdrawal_active_branches: Vec<B256>, pub force_count: u32, pub force_active_branches: Vec<B256> }`.
  - `pub struct HistoricalInclusionProof { pub record: WithdrawRecord, pub record_hash: B256, pub leaf_hash: B256, pub canonical_block_height: u64, pub checkpoint_height: u64, pub withdrawal_root: B256, pub leaf_index: u32, pub count: u32, pub siblings: [B256; 32] }`.
  - `pub struct GameExtraData { pub l2_block_number: U256, pub parent_index: u32, pub block_hash: B256, pub app_hash: B256, pub withdrawal_root: B256, pub force_root: B256 }` with `encode_packed() -> [u8;164]` and `decode(&[u8]) -> Result<Self, WitnessError>`.
  - `pub enum WitnessError { InvalidRequest, UnsupportedVersion, CheckpointNotFound, WithdrawalNotFound, RecordNotInCheckpoint, NotReady, RootMismatch, WitnessStoreCorrupt }` + `pub fn is_retryable(&self) -> bool` (`NotReady` ⇒ true).

- [ ] **Step 1: Add module declaration** — in `fault-proof/src/tz/mod.rs` after line 24 add `pub mod protocol;`.

- [ ] **Step 2: Write failing test for `compute_claim_root` (128-byte order + tamper sensitivity)** in `claim_root.rs`:
```rust
#[test]
fn claim_root_is_128_byte_ordered_keccak() {
    let (bh, ah, wr, fr) = (B256::repeat_byte(0x11), B256::repeat_byte(0x22), B256::repeat_byte(0x33), B256::repeat_byte(0x44));
    let mut pre = [0u8; 128];
    pre[..32].copy_from_slice(bh.as_slice());
    pre[32..64].copy_from_slice(ah.as_slice());
    pre[64..96].copy_from_slice(wr.as_slice());
    pre[96..].copy_from_slice(fr.as_slice());
    assert_eq!(compute_claim_root(bh, ah, wr, fr), keccak256(pre));
}
#[test]
fn claim_root_changes_if_any_field_swapped() {
    let f = [B256::repeat_byte(1), B256::repeat_byte(2), B256::repeat_byte(3), B256::repeat_byte(4)];
    let base = compute_claim_root(f[0], f[1], f[2], f[3]);
    assert_ne!(base, compute_claim_root(f[1], f[0], f[2], f[3])); // block/app swap
    assert_ne!(base, compute_claim_root(f[0], f[1], f[3], f[2])); // withdrawal/force swap
}
```

- [ ] **Step 3: Run to verify failure** — `cargo test -p op-succinct-fp --features tz claim_root` → FAIL (`compute_claim_root` not defined).

- [ ] **Step 4: Implement `claim_root.rs`** — `compute_claim_root` (128B), `compute_withdrawal_root`/`compute_force_root` (65B with `uint256(count)` big-endian + tag byte), and the three empty-tree constants.

- [ ] **Step 5: Write failing test for the empty-tree constants** — each constant asserted by independent computation (per Spec §2 "各自计算断言"), e.g. rebuild `EMPTY_WITHDRAWAL_ROOT = compute_withdrawal_root(EMPTY_INNER_ROOT, 0)` and assert it equals the frozen literal.

- [ ] **Step 6: Run tests to verify pass** — `cargo test -p op-succinct-fp --features tz claim_root` → PASS.

- [ ] **Step 7: Write `checkpoint.rs` / `record.rs` types + serde** with a failing round-trip test: JSON with U256-as-decimal-string and `0x`-hex fixed-length hashes decodes into `SnapshotQueryResponse` and re-encodes identically; a top-level `chainId` of `0` is rejected.

- [ ] **Step 8: Write `GameExtraData::encode_packed`/`decode` with a failing test** asserting `encode_packed().len() == 164` and byte layout matches the contract getters (`l2BlockNumber` 32B, `parentIndex` 4B, then `blockHash`,`appHash`,`withdrawalRoot`,`forceRoot`), and that `decode(encode_packed())` round-trips. Cross-reference `contracts/src/fp/OPSuccinctFaultDisputeGame.sol:660-705`.

- [ ] **Step 9: Write `error.rs` `WitnessError` + `is_retryable` with a failing test** asserting `NotReady.is_retryable()` and the others' classification.

- [ ] **Step 10: Run all protocol tests to verify pass** — `cargo test -p op-succinct-fp --features tz protocol` → PASS.

- [ ] **Step 11: fmt + clippy + commit**
```bash
cargo fmt --all && cargo clippy -p op-succinct-fp --features tz --all-targets -- -D warnings
git add fault-proof/src/tz/protocol fault-proof/src/tz/mod.rs
git commit -m "[Oli] tz/protocol: four-field claimRoot codec, CheckpointV2/boundary/proof types, stable error enum"
```

**Requirement check:** Spec §5.1 types + `compute_claim_root` (single impl replacing the two-field path conceptually), §2 frozen formulas/constants, extraData 164-byte layout matches contract ABI.

---

## Task 3: Witness Builder read client (4 endpoints + stable error parsing)

Satisfies Spec §5.1 WB client, §2 boundary wire semantics, §7.2.

**Files:**
- Create: `fault-proof/src/tz/witness_client.rs`
- Modify: `fault-proof/src/tz/mod.rs` (add `pub mod witness_client;`)
- Test: inline `#[cfg(test)]` using `wiremock` (pattern already used in `chain_client.rs:377-527`).

**Interfaces:**
- Consumes: `protocol::{CheckpointV2, SnapshotQueryResponse, TreeBoundaryWitness, CanonicalRecord, HistoricalInclusionProof, WitnessError}` (Task 2).
- Produces:
  - `pub struct WitnessClient { base_url: Url, client: reqwest::Client }`, `WitnessClient::new(base_url) -> Result<Self>`.
  - `async fn get_checkpoint_v2(&self, height: u64) -> Result<SnapshotQueryResponse, WitnessError>` — `GET /chain/dex_state_snapshot?height={H}&format=root&schemaVersion=2` (flat response w/ four fields + top-level `chainId`).
  - `async fn get_boundary_witness(&self, height: u64) -> Result<TreeBoundaryWitness, WitnessError>` (endpoint name per branch, semantics per Spec §4.2).
  - `async fn get_canonical_record(&self, record_hash: B256) -> Result<CanonicalRecord, WitnessError>` — `GET /chain/witness/withdrawals/{recordHash}`.
  - `async fn get_inclusion_proof(&self, record_hash: B256, checkpoint_height: u64, withdrawal_root: B256) -> Result<HistoricalInclusionProof, WitnessError>` — `GET /chain/witness/withdrawal-proof?recordHash&checkpointHeight&withdrawalRoot`.

- [ ] **Step 1: Add `pub mod witness_client;`** to `fault-proof/src/tz/mod.rs`.

- [ ] **Step 2: Write failing test — checkpoint v2 happy path** (wiremock): a `format=root&schemaVersion=2` response with four roots + top-level `chainId` decodes into `SnapshotQueryResponse` and recomputes `claim_root` via `compute_claim_root` matching the response's `claimRoot`.

- [ ] **Step 3: Run to verify failure** — `cargo test -p op-succinct-fp --features tz witness_client` → FAIL.

- [ ] **Step 4: Implement `get_checkpoint_v2`** — build URL, send, map HTTP/`code`/status → `WitnessError`, decode flat body, verify `claim_root == compute_claim_root(...)` else `WitnessError::RootMismatch`.

- [ ] **Step 5: Write failing tests for boundary/record/proof** — including boundary wire invariants: `count == 0 ⇒ activeBranches == []`; otherwise `activeBranches.len() == count.count_ones()`; a length-mismatched boundary is rejected (`RootMismatch`).

- [ ] **Step 6: Implement the three remaining endpoints** with `WitnessError` mapping (`CheckpointNotFound`/`WithdrawalNotFound`/`RecordNotInCheckpoint`/`NotReady`/`UnsupportedVersion`/`WitnessStoreCorrupt`).

- [ ] **Step 7: Write failing test — error classification & retryability** — `NotReady` and transient reqwest errors map to `is_retryable()==true`; `WithdrawalNotFound` maps to non-retryable.

- [ ] **Step 8: Run all client tests → PASS**; fmt + clippy.

- [ ] **Step 9: Commit**
```bash
git add fault-proof/src/tz/witness_client.rs fault-proof/src/tz/mod.rs
git commit -m "[Oli] tz/witness_client: 4 read endpoints (checkpointV2/boundary/record/proof) + stable error mapping"
```

**Requirement check:** Spec §5.1 four endpoints + error enum; §2 boundary length invariant enforced at decode.

---

## Task 4: SP1 range guest — four-field claimRoot + boundary reconstruction + tz-witness append/root

Satisfies Spec §5.2 (guest), §6 (Guest self-computes post root, does not trust Host), §10 (贯穿不丢 / 篡改必败 / boundary还原 / 双树独立).

**Files:**
- Modify: `programs/tz/range/src/main.rs`
- Test: inline `#[cfg(test)]` in the guest crate (host-target tests) + guest ELF build gate.

**Interfaces:**
- Consumes: `range_stdin` layout from Task 5 (`snapshot`, `chunk_count`, block chunks, **plus** per-sub-range-start `(withdrawal_count, withdrawal_active_branches)` and `(force_count, force_active_branches)`); `tz_witness` append/root API; `tz_block_processor::extract_withdrawals`; `protocol::{compute_claim_root, compute_withdrawal_root, compute_force_root, EMPTY_FORCE_ROOT}` (or guest-local equals — guest asserts constants itself).
- Produces: `BootInfoStruct { l2PreRoot = pre claimRoot(128B), l2PostRoot = post claimRoot(128B), .. }` (existing slots, four-field semantics).

- [ ] **Step 1: Guest compile gate before edits** — run the SP1 guest build (Task 1 Step 5) to confirm a clean baseline.

- [ ] **Step 2: Write failing host-target test — boundary → pre inner root** — feed `count = 0/1/2/3/5` active-branch vectors, reconstruct `withdrawalInnerRoot` via `tz_witness`, and assert `compute_withdrawal_root(inner, count)` equals the expected root; `count==0 ⇒ EMPTY_WITHDRAWAL_ROOT`, `forceCount==0 ⇒ EMPTY_FORCE_ROOT`.

- [ ] **Step 3: Run to verify failure** — `cargo test -p tz-range-program boundary` → FAIL.

- [ ] **Step 4: Read the two boundary inputs** — extend `main()` after `chunk_count` to read `(withdrawalCount, activeBranches)` and `(forceCount, activeBranches)` for the sub-range start; reconstruct pre `withdrawalInnerRoot`/`forceInnerRoot` via `tz_witness`, then pre `withdrawalRoot`/`forceRoot`; combine with pre `blockHash`+`appHash` into `l2PreRoot = compute_claim_root(...)` (128B) — replacing the 64-byte `keccak_join` at `main.rs:57`.

- [ ] **Step 5: Extract + append during replay** — after each `process_block`, call `tz_block_processor::extract_withdrawals` on the canonical `BlockResult`, feed records to `tz_witness` to append leaves and advance frontier/count for both trees; the guest **must not** trust any Host-provided leaf list or post root.

- [ ] **Step 6: Compute post claimRoot** — after the replay loop, compute post `withdrawalRoot`/`forceRoot` from `tz_witness` state and set `l2PostRoot = compute_claim_root(end_block_hash, end_app_hash, post_withdrawal_root, post_force_root)` — replacing `main.rs:58`.

- [ ] **Step 7: Write failing test — tamper any field ⇒ different post claimRoot** — swapping withdrawal/force roots or reusing a count changes `l2PostRoot`.

- [ ] **Step 8: Run host-target guest tests → PASS**.

- [ ] **Step 9: SP1 guest ELF build gate (hard)** — `just build-tz-range-elf`; expected: builds with the new `tz-witness`/`extract_withdrawals` imports under the guest target.

- [ ] **Step 10: fmt + commit**
```bash
git add programs/tz/range/src/main.rs
git commit -m "[Oli] tz range guest: four-field pre/post claimRoot from boundary + tz-witness append/root"
```

**Requirement check:** Spec §5.2 guest points 1-5; §6 Guest self-computes post root; §10 boundary还原 / 双树独立 / 篡改必败.

---

## Task 5: Range host / Proposer — boundary plumbing, 164-byte extraData, four-field claimRoot, pre-submit re-verify

Satisfies Spec §5.2 (host/proposer), §6, §10 (贯穿不丢), §7.

**Files:**
- Modify: `fault-proof/src/tz/proposer.rs:63-108` (`handle_game_creation` extraData), `:420-501` (`tz_range_proof` stdin)
- Modify: `fault-proof/src/tz/l2_provider.rs:18-43` (four-field `compute_output_root_at_block`)
- Modify: `fault-proof/src/tz/chain_client.rs` (checkpoint w/ withdrawal/force roots at anchor) or use `witness_client` (Task 3)
- Test: inline `#[cfg(test)]` (extend the existing `compute_chunks`/reorder tests + wiremock provider tests in `l2_provider.rs`).

**Interfaces:**
- Consumes: `witness_client::WitnessClient` (Task 3), `protocol::{GameExtraData, compute_claim_root}` (Task 2), `TreeBoundaryWitness` (Task 2).
- Produces: `range_stdin` including the two boundary inputs per sub-range start (Task 4 reads them); 164-byte `extra_data`; four-field anchor `claimRoot`.

- [ ] **Step 1: Write failing test — four-field `compute_output_root_at_block`** in `l2_provider.rs`: given a cached/queried CheckpointV2 with all four roots at `height`, the returned root equals `compute_claim_root(block_hash, app_hash, withdrawal_root, force_root)` (not the two-field `compute_tz_root_claim`).

- [ ] **Step 2: Run to verify failure** → FAIL.

- [ ] **Step 3: Upgrade `compute_output_root_at_block`** — fetch CheckpointV2 (via `witness_client` or extended `chain_client`) at the anchor height and return `compute_claim_root(...)`. Keep the two-field `compute_tz_root_claim` only as a wire-v1 compat helper if still referenced; new path uses `compute_claim_root`.

- [ ] **Step 4: Write failing test — 164-byte extraData** — `handle_game_creation` builds `extra_data` via `GameExtraData::encode_packed()` (len 164) whose decoded four fields recompute the game `rootClaim`; assert length 164 and that `compute_claim_root(decoded)` equals `output_root`.

- [ ] **Step 5: Replace the extraData construction** at `proposer.rs:72` — from `(next_l2_block_number_for_proposal, parent_game_index).abi_encode_packed()` (36B) to `GameExtraData{ l2_block_number, parent_index, block_hash, app_hash, withdrawal_root, force_root }.encode_packed()` (164B), sourcing the four roots from the anchor CheckpointV2.

- [ ] **Step 6: Add pre-submit local re-verify** — before `create_game`, decode the just-built `extra_data`, recompute `compute_claim_root`, and assert it equals `output_root`; bail on mismatch (never submit an inconsistent game).

- [ ] **Step 7: Plumb boundary witnesses into `range_stdin`** — in `tz_range_proof` (`proposer.rs:451-460`), after `write_vec(snapshot)` and `write(&chunk_count)`, fetch the two `TreeBoundaryWitness` (withdrawal + force) for the sub-range start via `witness_client` and `write` their `(count, active_branches)` in the exact order Task 4 reads them. Cross-check boundary/snapshot/canonical `blockHeight`/`blockHash` agree; verify `chainId` from the **checkpoint response top level** (boundary carries none).

- [ ] **Step 8: Run proposer + provider tests → PASS**; ensure `compute_chunks`/reorder/concurrency tests (`proposer.rs:551-729`) still pass unchanged.

- [ ] **Step 9: fmt + clippy + commit**
```bash
git add fault-proof/src/tz/proposer.rs fault-proof/src/tz/l2_provider.rs fault-proof/src/tz/chain_client.rs
git commit -m "[Oli] tz proposer/host: 164B four-field extraData, four-field anchor claimRoot, boundary plumbing + pre-submit re-verify"
```

**Requirement check:** Spec §5.2 host points 1-5; §10 贯穿不丢 (WB→Rust→stdin→extraData order preserved); §6 chainId only cross-checked at host, not in claimRoot.

---

## Task 6: L1 Challenger — schemaVersion=2 + top-level chainId guard + field-by-field comparison

Satisfies Spec §5.3, §4, §5.5, §10 (Challenger).

**Files:**
- Modify: `fault-proof/src/tz/game_validator.rs:90-267` (`validate`, `TzRootClient::query`, `validate_ready_response`)
- Modify: `fault-proof/src/config.rs:405-430` (add `chain_id` to `TzGameValidatorConfig`)
- Modify: `fault-proof/bin/tz_challenger.rs:53,66` (pass `chain_id` into validator)
- Test: inline `#[cfg(test)]` (extend the existing wiremock suite `game_validator.rs:315-806`).

**Interfaces:**
- Consumes: `protocol::{CheckpointV2, compute_claim_root}`, `GameExtraData` (to read the game's four fields).
- Produces: `TzGameValidator` that (a) sends `schemaVersion=2`, (b) guards `chain_id`, (c) compares each of `blockHash/appHash/withdrawalRoot/forceRoot` and `rootClaim == claimRoot`.

- [ ] **Step 1: Write failing test — chainId guard** — a checkpoint response whose top-level `chainId` != configured `chain_id` yields `GameValidation::Unavailable(..)` (do not advance / do not challenge on wrong-chain data); server received the `schemaVersion=2` query param.

- [ ] **Step 2: Run to verify failure** → FAIL.

- [ ] **Step 3: Add `chain_id: u64` to `TzGameValidatorConfig`** (`config.rs:405`) parsed from env (e.g. `TZ_CHAIN_ID`, reject `0`), logged in `log()`; thread it through `TzGameValidator::new` and `tz_challenger.rs:66`.

- [ ] **Step 4: Send `schemaVersion=2` and parse top-level chainId** — extend `TzRootClient::query` (`game_validator.rs:186-248`) to append `schemaVersion=2` and decode a `SnapshotQueryResponse` (four fields + `chainId`); add the chainId guard in `validate`.

- [ ] **Step 5: Write failing test — field-by-field comparison** — read the game's `withdrawalRoot`/`forceRoot` from `extraData`; for a checkpoint where any single field differs, `validate` returns the existing challenge outcome (`Invalid(OutputRootMismatch)`), and where all four match, `Valid`; also assert `rootClaim == compute_claim_root(...)`.

- [ ] **Step 6: Implement field-by-field comparison** — compare `blockHash/appHash/withdrawalRoot/forceRoot` individually plus `rootClaim == claimRoot`; any mismatch → existing challenge path.

- [ ] **Step 7: Preserve retry semantics** — `NotReady` / transient RPC failures keep the game pending and retry with back-off (reuse `Unavailable` semantics); assert a single cache-miss/RPC failure never permanently drops a game (extend an existing `Unavailable`/retry test).

- [ ] **Step 8: Run challenger tests → PASS** (existing suite `game_validator.rs:412-806` still green).

- [ ] **Step 9: fmt + clippy + commit**
```bash
git add fault-proof/src/tz/game_validator.rs fault-proof/src/config.rs fault-proof/bin/tz_challenger.rs
git commit -m "[Oli] tz challenger: schemaVersion=2 query, top-level chainId guard, field-by-field claim comparison"
```

**Requirement check:** Spec §5.3 points 1-4; §4 field-by-field + chainId; §10 Challenger (tamper any field ⇒ challenge; chainId mismatch ⇒ no advance; NotReady retry, no missed detection).

---

## Task 7: Independent L2 Defender service (module + fourth binary + config)

Satisfies Spec §5.4 (D1 packaging), §5.5 (config/observability), §7.3, §11, §10 (Defender).

**Files:**
- Create: `fault-proof/src/tz/defender/{mod.rs,watcher.rs,handler.rs,verifier.rs,cache.rs,config.rs}`
- Create: `fault-proof/bin/tz_defender.rs`
- Modify: `fault-proof/Cargo.toml` (register `[[bin]] tz-defender`; add `lru` under `tz`)
- Modify: `fault-proof/src/tz/mod.rs` (add `pub mod defender;`)
- Test: inline `#[cfg(test)]` per submodule + wiremock for WB/RootManager clients.

**Interfaces:**
- Consumes: `witness_client::WitnessClient` (record + proof), `protocol::{HistoricalInclusionProof, compute_withdrawal_root, WitnessError}`, `tz_witness::verify_proof`, existing signer / nonce / receipt helpers (reuse `SignerLock` as in `tz_challenger.rs`), a RootManager client (against `ITZRootManager` ABI — read-only latest/finalized covering root), and the external Withdraw challenge ABI (Spec §7.3: `ChallengeOpened(leafHash, responseDeadline)` / `getChallenge(leafHash)->(resolutionStatus:u8, responseDeadline:u64)` / `proveChallenge(leafHash, checkpointBlockHeight:u64, leafIndex:u32, count:u32, siblings:bytes32[32])`).
- Produces: `bin/tz-defender` binary; `TzDefenderConfig`; a local verifier + LRU cache.

- [ ] **Step 1: Add `pub mod defender;`** to `fault-proof/src/tz/mod.rs`; add `[[bin]] name = "tz-defender" path = "bin/tz_defender.rs"` to `fault-proof/Cargo.toml` and `lru` to the `tz` feature deps.

- [ ] **Step 2: Write failing test — local verifier accepts a valid proof / rejects malformed** in `verifier.rs`: wraps `tz_witness::verify_proof` with the hard rules — `count>0`, `leafIndex<count`, `siblings.len()==32`, rebuild innerRoot, and `compute_withdrawal_root(inner, count) == bound RootManager withdrawalRoot` (tag `0x02` fixed inside). Assert reject on wrong `leafHash`, `leafIndex==count`, `count==0`, wrong sibling, and root mismatch.

- [ ] **Step 3: Run to verify failure** → FAIL; then **implement `verifier.rs`** → PASS.

- [ ] **Step 4: Write failing test — LRU cache keyed `(leafHash, withdrawalRoot)`** in `cache.rs`: same key hits; a changed `withdrawalRoot` misses; capacity eviction works; only verified proofs are inserted. Implement `cache.rs` → PASS.

- [ ] **Step 5: Write failing test — `TzDefenderConfig::from_env`** in `config.rs` covering the required fields (Spec §5.5): challenge contract, RootManager, WB endpoint, chain id, finality, lookback, retry/back-off, deadline safety margin, cache capacity, tx-sender params; reject missing/invalid. Implement → PASS.

- [ ] **Step 6: Write failing test — handler happy path (wiremock/mock chain)** in `handler.rs`: `ChallengeOpened` → wait L2 finality → `getChallenge` (skip if not responsible / past deadline) → WB record by exact `leafHash/recordHash` → wait latest-finalized RootManager `checkpointHeight >= recordHeight` → bind `checkpointHeight + withdrawalRoot` → cache/WB proof → local verify → **re-check `getChallenge` state+deadline** → `proveChallenge` → wait canonical receipt → re-check final state. Implement the state machine → PASS.

- [ ] **Step 7: Write failing tests — race/recovery no-false-submit** (Spec §5.4 恢复与竞态, §10 Defender): events keyed by `(chain, contract, transactionHash, logIndex)` (not leafHash); already-responded / challenge-ended / L2-reorg / deadline-passed ⇒ no submit; deadline reached with no record/covering-root/valid-proof ⇒ **alert only, no losing tx, no timeout settlement**; restart re-scans events (proof cache not persisted). Implement → PASS.

- [ ] **Step 8: Write `watcher.rs`** (scan `ChallengeOpened`, wait finality, startup lookback rescan) + `bin/tz_defender.rs` (own main loop / config / signer / metrics, mirroring `tz_proposer.rs`/`tz_challenger.rs` bootstrap) with a smoke test that the bin wires config→watcher→handler.

- [ ] **Step 9: Add metrics/alert coverage** (Spec §5.5): waiting-for-record, waiting-for-covering-root, proof-verify-failure, RPC error, tx status, near-deadline, event rescan.

- [ ] **Step 10: Build all four bins** — `cargo build -p op-succinct-fp --features tz --bins`; expected `proposer`, `challenger`, `tz-proposer`, `tz-challenger`, `tz-defender` all build. fmt + clippy.

- [ ] **Step 11: Commit**
```bash
git add fault-proof/src/tz/defender fault-proof/bin/tz_defender.rs fault-proof/Cargo.toml fault-proof/src/tz/mod.rs
git commit -m "[Oli] tz defender: independent tz-defender bin + watcher/handler/verifier/cache/config"
```

**Requirement check:** Spec §5.4 process flow + D1 packaging; §5.5 config/observability; §7.3 external ABI binding; §11 non-goals (no game creation, no root generation, no timeout settlement); §10 Defender scenarios.

---

## Task 8: Cross-language parity, integration, and regression tests

Satisfies Spec §10 (WB↔Guest 一致, 跨语言, 回归) and §10 fixture rules.

**Files:**
- Create: `fault-proof/tests/tz_cross_language.rs` (or `tests/tz_cross_language/`)
- Modify: existing integration test entrypoints as needed
- Test: this task IS tests.

**Interfaces:**
- Consumes: everything above; frozen `claim-tree-v1.json` fixture (Solidity gate); `tz_witness` (SP1/Defender share it, so no separate golden vector).

- [ ] **Step 1: Write cross-language parity test** — the Defender Rust verifier (`tz_witness::verify_proof`) and the Solidity harness agree on the frozen `claim-tree-v1.json` fixture for at least: ERC20, ERC1155 batch, empty-tree rejection, wrong tag, `leafIndex==count`. Per §10: Solidity uses the frozen fixture as gate; SP1/Defender reuse `tz-witness` (same-source as WB) and do **not** call a generator or maintain hand-written expected constants.

- [ ] **Step 2: Run cross-language test** — `cargo test -p op-succinct-fp --features tz cross_language` (+ `just fp-contract-tests` for the Solidity side) → PASS.

- [ ] **Step 3: Write "贯穿不丢 / 篡改必败 / 多 sub-range / 双树独立" integration test** — a fixed checkpoint with Withdraw count=5 / ForceTx count=3 threads four-field pre/post claimRoot across multiple sub-ranges and links via aggregation; tampering any field fails guest/aggregation/Game/Challenger; swapping roots or reusing a count fails.

- [ ] **Step 4: Run FP integration + regression** — `just fp-integration-tests`; confirm original proposal/prove/resolve/challenge regression tests still pass.

- [ ] **Step 5: Commit**
```bash
git add fault-proof/tests
git commit -m "[Oli] tests: cross-language fixture parity + four-field threading/tamper/multi-range/dual-tree integration"
```

**Requirement check:** Spec §10 test-and-acceptance mapping fully covered; §10 fixture-usage rules honored.

---

## Task 9: Rebuild guest ELFs, regenerate vkeys, update fdg-config vkey commitment

Satisfies Spec §5.2 note (ELF/vkey change), §12 (delivery coordination). Delivery/validation task — no source logic change.

**Files:**
- Modify: `elf/` outputs (generated), fdg-config deployment config carrying `rangeVkeyCommitment`.
- Test: command-based validation.

- [ ] **Step 1: Rebuild tz ELFs** — `just build-tz-elfs`. Expected: `tz-range-elf-embedded` and `tz-aggregation-elf` regenerated.

- [ ] **Step 2: Regenerate vkeys** — `just tz-vkeys` (`cargo run --release --bin tz-config`). Record the new `rangeVkeyCommitment` / aggregation vkey.

- [ ] **Step 3: Update fdg-config** — write the new `rangeVkeyCommitment` into the deployment config the proposer reads (`game_impl.rangeVkeyCommitment()` on-chain must match the loaded ELF; see `proposer.rs:175`). Do NOT modify contracts; this is config only.

- [ ] **Step 4: Validate** — run `just fp-contract-tests` and a mock proposer/challenger smoke (`just start fp-tz` per ci-env skill) to confirm the new vkey commitment is consistent end-to-end.

- [ ] **Step 5: Commit**
```bash
git add elf fdg-config <config-path>
git commit -m "[Oli] build: rebuild tz range/agg ELFs + update rangeVkeyCommitment for four-field guest"
```

**Requirement check:** Spec §5.2 ⚠️ note + §12 ELF/vkey coordination.

---

## Additional Context — task/validation mapping

Per the Flow, each applicable Additional Context item is mapped to the task or validation that satisfies it; inapplicable items are recorded with reasons. All three items in Spec §1.2 are applicable.

| AC | Statement (Spec §1) | Applicable? | Satisfied by |
|----|----------------------|-------------|--------------|
| **AC-1** | WB / `tz-witness` / extractor upstream lives on tradezone branch `feature/witness-builder-withdraw-v1` | Yes | **Task 1** (dep source) + **Tasks 4/5** consume `tz-witness` + `extract_withdrawals` from that branch. |
| **AC-2** | Contracts are in `xl/tz-challenger-v2` `contracts/src/fp` (final ABI authority); non-goal to modify | Yes (as constraint) | **Validation-only**: Tasks 5/6/7 integrate against existing getters/`_verifyRootClaimPreimage` (`OPSuccinctFaultDisputeGame.sol:660-705`), `ITZRootManager`, `ITZClaimGame`; Global Constraints forbid contract changes. Withdraw challenge contract is external X Layer ABI (Task 7 binds to it, does not implement it). |
| **AC-3** | Use tradezone GitLab dev branch, not the x2 github mirror; fixed rev | Yes | **Task 1** Steps 1-3 (switch source off `x2.git` rev `b3e2cf98`, pin `<REV>` on the feature branch). |

**Inapplicable Additional Context items:** none. (Spec §1.2 confirms all three are applicable and non-conflicting with Jira/PRD/repo facts; AC-3 aligns with op-succinct Spec §8.4.)

---

## Self-Review

**1. Spec coverage:**
- §0/§2 formulas & frozen constants → Task 2 (codec + empty-tree constants). §5.1 types + WB client → Tasks 2, 3. §5.2 guest → Task 4; host/proposer → Task 5. §5.3 challenger → Task 6. §5.4 Defender → Task 7. §5.5 config/observability → Tasks 6, 7. §6 invariants → Tasks 4, 5, 8. §7 external ABI → Tasks 6, 7 (integrate-only). §8 deps + guest compile gate → Task 1. §10 tests → Task 8 (+ per-task TDD). §11 non-goals → Global Constraints + Task 7. §12/§5.2 ELF/vkey → Task 9. §1 Additional Context → mapping table. No uncovered section.

**2. Placeholder scan:** the only intentional placeholder is `<REV>` (resolved in Task 1 Step 1, then written back). Endpoint names for boundary/record/proof are per the branch's actual routes (Spec §7.4 requires re-verification at implementation time) — flagged in Task 3. No "TBD/handle edge cases/write tests for the above" placeholders.

**3. Type consistency:** `compute_claim_root(block_hash, app_hash, withdrawal_root, force_root)` is used identically in Tasks 2, 4, 5, 6. `GameExtraData` (164B) defined in Task 2, consumed in Tasks 5, 6. `WitnessError`/`is_retryable` defined in Task 2, consumed in Tasks 3, 6, 7. `WitnessClient` methods defined in Task 3, consumed in Tasks 5, 7. `TzGameValidatorConfig.chain_id` added in Task 6 and consumed by `tz_challenger.rs`. No signature drift.

## Execution Handoff

Do NOT begin execution until stage 3.0 has prepared the feature branch. When execution starts, prefer **Subagent-Driven** (superpowers:subagent-driven-development): fresh subagent per task with review between tasks, given the breadth (protocol → guest → host → challenger → defender → tests → ELF). Task 1 is a hard gate — do not start Task 4+ until the SP1 guest compile gate (Task 1 Step 5) is green.
