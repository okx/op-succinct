# TRDZN-1339 R2 — Align to Latest Witness Builder + Complete Four-Field/Guest — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Do NOT start executing until stage 3.0 has reused the existing feature branch. This plan runs against the **feature branch `xl/trdzn-1339/0903-0830`** (MR !102), which already contains the `fault-proof/src/tz/withdraw/` module — NOT the bare `xl/tz-challenger-v2` base.

**This is the CURRENT plan (Revision 2 delta).** It supersedes and clearly links the prior plan; prior files are preserved, not deleted:
- Prior plan (R1, greenfield `protocol/` layout — now superseded): `docs/superpowers/plans/2026-09-03-tz-withdraw-forcetx-four-field-claim-and-defender-plan.md`
- Prior ops hand-off (deferred dep switch + ELF/vkey, resolved rev): `docs/superpowers/plans/handoff-tz-elf-vkey-redeploy.md`
- Spec (approved, Revision 2): `docs/superpowers/specs/2026-09-03-tz-withdraw-forcetx-four-field-claim-and-defender-design.md`

**Goal:** Correct the 5 deviations the creator flagged on MR !102 so op-succinct's four-field `claimRoot` path and Witness Builder client match the **latest** WB implementation (tz-witness split commit `e56881eb29879166752294c87b207a23bb2dcc26`), and complete the still-deferred SP1 guest wiring + dependency switch + ELF/vkey rebuild.

**Architecture:** The direction (four-field `claimRoot` threading + independent Defender, D1 packaging), the contracts, and the already-approved module boundaries are UNCHANGED and remain approved. MR !102 already implemented — host-side, green (203 lib + 3 integration tests) — the shared library `fault-proof/src/tz/withdraw/` (`wb_client.rs`, `types.rs`, `tree_adapter.rs`, `claim.rs`, `error.rs`, `mod.rs`), the WB v2 read client, the L1 Challenger chainId guard + four-field comparison, the WB-backed `compute_output_root_at_block`, the boundary fetch/stdin helpers + 164-byte extraData, and the full independent Defender (`src/tz/defender/` + `bin/tz_defender.rs`). This plan is a **delta**: it fixes where MR !102 was written against older protocol wording instead of the latest WB code, and lands the guest/ELF work that was toolchain-gated.

**Root cause (Spec Revision 2 §R2.0):** MR !102's build environment could not pull the private tradezone crate, so `wb_client.rs` was stubbed against documented wire shapes and `tree_adapter.rs` copied the tree algorithm locally; the guest was never wired. The latest WB split the tree into `tz-witness` and moved chainId to the response top level. All 5 feedback items share this root cause and converge once `tz-witness` (fixed rev) is the single tree source.

**Tech Stack:** Rust (nightly-2025-09-15), SP1 zkVM (okx/sp1 `feat/gateway-proxy-v6.1.0`), `alloy` primitives/providers, `reqwest`, `tokio`, `thiserror`, Foundry/`forge`, `just`. Upstream crates: `tz-witness` / `tz-block-processor` / `tz-dex` / `tz-primitives` from `gitlab.okg.com/xlayer-dex/tradezone` @ fixed rev `e56881eb29879166752294c87b207a23bb2dcc26`.

---

## Global Constraints

Every task's requirements implicitly include this section. Values copied verbatim from the Spec (Revision 2 + §2).

- **Repo / branch:** `github/op-succinct`. Development base and MR target is `xl/tz-challenger-v2`; the live work sits on feature branch `xl/trdzn-1339/0903-0830` (MR !102, reviewed SHA `6a7203f07`, base `671e055`). Reuse the SAME branch and the SAME open MR !102 (branch stage reuses, does not recreate). Never merge / deploy / release / force-push / push directly to the target branch.
- **Commit & MR titles:** every new commit subject and the MR title begin exactly `[Oli] `. Jira `TRDZN-1339` is the PR-metric linkage.
- **Single computation source (AC-1):** the tree/root/proof algorithm lives ONLY in `tz-witness` (`crates/witness`; deps = `tz-primitives` + `thiserror` only); the leaf extractor `extract_withdrawals` lives in `tz-block-processor`. op-succinct must NOT keep a second implementation. Dependency direction single: `tz-block-processor → tz-witness → tz-primitives`; `tz-witness` never `use tz_block_processor`.
- **Fixed dependency rev (resolved):** `rev = e56881eb29879166752294c87b207a23bb2dcc26` (the `tz-witness` split commit on `feature/witness-builder-withdraw-v1`; `crates/witness`, `witness.rs`, `zkvm_snapshot.rs` verified readable at this rev). Use `rev=` (NOT `branch=`).
- **claimRoot (128-byte preimage, order fixed):** `claimRoot = keccak256(abi.encodePacked(blockHash, appHash, withdrawalRoot, forceRoot))`; `blockHeight` NOT included; order never changes.
- **Sub-roots (65-byte preimages):** `withdrawalRoot = keccak256(abi.encodePacked(withdrawalInnerRoot, uint256(withdrawalCount), 0x02))`; `forceRoot = keccak256(abi.encodePacked(forceInnerRoot, uint256(forceCount), 0x01))`. Tags fixed contract-side.
- **Incremental tree:** `TREE_DEPTH = 32`; `count`/`leafIndex` are `u32`; empty leaf `bytes32(0)`; `z[h+1]=keccak256(z[h]‖z[h])`; parent `keccak256(left‖right)` unsorted. **Proof hard rules:** `count > 0`, `leafIndex < count`, `siblings.len() == 32`.
- **Empty-tree vectors (each language asserts independently, never copies):** `emptyInnerRoot = 0x27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757`; `EMPTY_FORCE_ROOT = 0x2ce29f3bbe826db4f8ba37a99421dec3b9b590d06fd6b77b706c8a8606de2a56`; `EMPTY_WITHDRAWAL_ROOT = 0x6b7dbdc90c57dd6d1cc0ce495b921b274ffccbba3813e018b7cc843f4f6876d7`. Empty ForceTx ⇒ `forceRoot = tz_witness::merkle::empty_force_root()` (= `EMPTY_FORCE_ROOT`, non-zero) — never NotReady.
- **chainId placement (R2 #2/#3):** NOT in `CheckpointV2`, NOT in `TreeBoundaryWitness`, NOT in `claimRoot`/boundary. It appears ONLY at the FLAT top level of the checkpoint RPC response: `SnapshotQueryResponse.chainId: Option<u64>` (populated only for v2). Used only for host/challenger "correct TZ chain" cross-checks.
- **Checkpoint wire is FLAT (R2 #1/#3):** request must send `format=root` AND `schemaVersion=2`. Server does `schema_version.unwrap_or(1)`, so omitting ⇒ v1; only `schemaVersion==2` returns the v2 body. Response is flat camelCase `SnapshotQueryResponse { stateAvailable, status, canonicalBlockHash, claimRoot?, appHash?, withdrawalRoot?, localTip?, schemaVersion?(=2), chainId?:u64 }` — **NO nested `components` object**. `status` snake_case ∈ `ready | running | above_local_tip | no_base_snapshot | capacity_unavailable | failed`; only `ready` usable, `running`/`above_local_tip` ⇒ NotReady (retryable).
- **Boundary wire (R2 #2):** `TreeBoundaryResponse { schemaVersion, blockHeight, blockHash, withdrawalCount:u32, withdrawalActiveBranches:[bytes32], forceCount:u32, forceActiveBranches:[bytes32] }` — no chainId. Validate `activeBranches.len() == count.count_ones()` and rebuild the declared root; mismatch ⇒ reject.
- **Record/Proof routes + shapes (R2 secondary):** record `GET /chain/witness/withdrawals/{recordHash}` → `WithdrawalLookupResponse { protocolVersion, recordHash, canonicalBlockHeight:u64, leafIndex:u32, record }` where `record: WithdrawRecordResponse { version, chainId, transactionHash, rawTradezoneWithdrawal { tokenType, tokenAddress, tokenIds[], amounts[], from, to } }` (record fields NESTED under `rawTradezoneWithdrawal`). Proof `GET /chain/witness/withdrawal-proof?recordHash&checkpointHeight&withdrawalRoot` → `WithdrawalProofResponse { protocolVersion, recordHash, leafHash, canonicalBlockHeight, checkpointHeight, withdrawalRoot, count:u32, leafIndex:u32, record, siblings:[bytes32;32] }`. `WithdrawRecord`/`RawTradezoneWithdrawal` come from `tz_witness::withdrawal` — no separate leaf encoding.
- **SP1 guest compile gate (hard, Spec §8):** the range guest must pass `cargo check`/`cargo-prove prove build` on the SP1 guest target (`tz-witness` depends only on `tz-primitives`+`thiserror`, no rayon/heavy runtime). No paper-only claims.
- **Dependency-fetch precondition (Spec §12, top risk):** MR !102's deviations root-caused to the build env not pulling the private tradezone crate. Before Task 1, verify the environment can `cargo` fetch `gitlab.okg.com/xlayer-dex/tradezone@e56881eb2`. If it cannot, do NOT fall back to a local tree copy — record an explicit blocker (repro + required SSH/HTTPS creds + rev) and escalate.
- **Non-goals:** no L1/L2 contract implementation/refactor (integrate the final ABI in `contracts/src/fp` only); no second Merkle/tree/root/proof in op-succinct; Defender never creates L1 Games, generates Withdrawal Roots, or does timeout settlement; no change to appHash execution semantics or checkpoint cadence.
- **ELF/vkey:** guest changes alter the range ELF + `rangeVkeyCommitment` (and aggregation vkey); rebuild ELFs and update the on-chain/config vkey (Task 7). Toolchain pinned `nightly-2025-09-15`.

### Standard command reference

- Format: `cargo fmt --all` · Lint: `cargo clippy -p op-succinct-fp --features tz --all-targets -- -D warnings`
- Unit tests (tz): `cargo test -p op-succinct-fp --features tz`
- Host build gate: `cargo build -p op-succinct-fp --features tz`
- SP1 guest compile gate: `cd programs/tz/range && ~/.sp1/bin/cargo-prove prove build --elf-name tz-range-elf-embedded --output-directory ../../../elf`
- Build tz ELFs: `just build-tz-elfs` · Regenerate vkeys: `just tz-vkeys` (`cargo run --release --bin tz-config`)
- Contract regression: `just fp-contract-tests` · FP integration: `just fp-integration-tests`

---

## File Structure (this delta)

**Modify (existing MR !102 files on the feature branch)**
- `fault-proof/src/tz/withdraw/wb_client.rs` — checkpoint request adds `schemaVersion=2`; `CheckpointDto` flat + top-level `chainId` (drop nested `components`); `BoundaryDto` drops `chain_id` + its `!=0` check; real routes for record/proof/boundary; record maps nested `rawTradezoneWithdrawal`; `status` snake_case set.
- `fault-proof/src/tz/withdraw/types.rs` — `CheckpointV2` and `TreeBoundaryWitness` drop `chain_id`; add host-side `CheckpointV2Envelope { checkpoint: CheckpointV2, chain_id: u64 }` assembled from the flat top-level fields.
- `fault-proof/src/tz/withdraw/tree_adapter.rs` — delete local `business_root`/`calculate_inner_root`/`verify_proof`/`zero_hashes`/`root_from_frontier`/`empty_*`; delegate to `tz_witness::merkle` + `tz_witness::checkpoint`.
- `fault-proof/src/tz/withdraw/error.rs` — align error taxonomy to the real `status` + route failures (keep the stable `WbError`/`WitnessError` variants used by callers).
- `fault-proof/src/tz/game_validator.rs` — parse the FLAT v2 body (not nested `components`); send `schemaVersion=2`; top-level `chainId` guard; field-by-field comparison (preserve retry semantics).
- `fault-proof/src/tz/defender/verifier.rs` — re-point local verify to `tz_witness::merkle::verify_proof` (keep behavior; drop reliance on the local `tree_adapter` algorithm once deleted).
- `programs/tz/range/src/main.rs` — integrate `tz-witness`: boundary → pre inner roots → pre four-field claimRoot; `extract_withdrawals` + `tz-witness` → post four-field claimRoot; replace the two-field `keccak_join`.
- `Cargo.toml` (workspace root) — switch tz-* source to tradezone GitLab, fixed rev; add `tz-witness`.
- `fault-proof/Cargo.toml` — declare `tz-witness` dependency (host + guest paths).
- fdg-config carrying `rangeVkeyCommitment` / `aggregationVkey` — updated in Task 7 (config only; not a contract change).

**Not re-created (already correct on MR !102, keep as-is unless a task says otherwise):** `claim.rs` (128B claimRoot + 164B extraData codec), Defender module skeleton (`watcher.rs`/`handler.rs`/`cache.rs`/`config.rs` + `bin/tz_defender.rs`), the challenger's field-by-field comparison structure, the proposer boundary/stdin/extraData helpers.

---

## Task 1: Establish `tz-witness` (fixed rev) as the single tree source + guest compile gate

Fixes R2 #4 (root cause) and completes the deferred dep switch (handoff §2/§3). Satisfies AC-1/AC-3, Spec §8/§12.

**Files:** Modify `Cargo.toml` (root, ~lines 155-158), `fault-proof/Cargo.toml`. Test: dependency resolution + host build + SP1 guest compile gate (command-based).

**Interfaces:**
- Consumes: nothing.
- Produces: `tz-block-processor`, `tz-dex`, `tz-primitives`, `tz-witness` all resolving to `gitlab.okg.com/xlayer-dex/tradezone` @ `e56881eb2…`. Downstream tasks import `tz_witness::{merkle, checkpoint, withdrawal}` and `tz_block_processor::extract_withdrawals`.

- [ ] **Step 1: Verify dependency fetch precondition** — `git ls-remote https://gitlab.okg.com/xlayer-dex/tradezone.git e56881eb29879166752294c87b207a23bb2dcc26` resolves, and the environment can `cargo` fetch it (SSH or HTTPS-with-`insteadOf`). If it cannot: STOP, record the blocker (repro + creds + rev) and escalate per Global Constraints — do NOT reinstate a local tree copy.

- [ ] **Step 2: Switch the source + pin the rev** in root `Cargo.toml`:
```toml
# tradezone (range guest deps) — TradeZone GitLab feature branch, fixed rev (WB Withdraw/Force work)
tz-block-processor = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "e56881eb29879166752294c87b207a23bb2dcc26", features = ["tee"] }
tz-dex             = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "e56881eb29879166752294c87b207a23bb2dcc26", features = ["zkvm"] }
tz-primitives      = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "e56881eb29879166752294c87b207a23bb2dcc26" }
tz-witness         = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "e56881eb29879166752294c87b207a23bb2dcc26" }
```
Verify the crate paths (`crates/witness`) + feature flags against the branch's own `Cargo.toml` before committing (Spec §7.4).

- [ ] **Step 3: Declare `tz-witness` for fault-proof** — add `tz-witness = { workspace = true }` under `fault-proof/Cargo.toml` `[dependencies]` (and the guest crate `programs/tz/range/Cargo.toml`), so both host and guest can call it.

- [ ] **Step 4: Resolve + confirm no x2 remnant** — `cargo metadata --format-version 1 >/dev/null`; expected all four crates at `e56881eb2…` and `! grep -q "x2.git" Cargo.lock`.

- [ ] **Step 5: Host build gate** — `cargo build -p op-succinct-fp --features tz` → compiles.

- [ ] **Step 6: SP1 guest compile gate (hard)** — `cd programs/tz/range && ~/.sp1/bin/cargo-prove prove build --elf-name tz-range-elf-embedded --output-directory ../../../elf` → guest builds (proves `tz-witness` trims under the guest target). If it fails, resolve feature gating before any later task.

- [ ] **Step 7: Commit**
```bash
git add Cargo.toml Cargo.lock fault-proof/Cargo.toml programs/tz/range/Cargo.toml
git commit -m "[Oli] deps: pin tz-* to tradezone rev e56881eb2 + add tz-witness (single tree source)"
```

**Requirement check:** R2 #4 root cause resolved; AC-1/AC-3 satisfied; Spec §8 guest gate green; §12 fetch precondition explicitly gated.

---

## Task 2: `wb_client.rs` — checkpoint `schemaVersion=2`, flat body, real routes, snake_case status

Fixes R2 #1 and the secondary route/status deviations.

**Files:** Modify `fault-proof/src/tz/withdraw/wb_client.rs`. Test: inline `#[cfg(test)]` wiremock (pattern already in the file / `chain_client.rs`).

**Interfaces:**
- Consumes: `types::{CheckpointV2, CheckpointV2Envelope, TreeBoundaryWitness}` (Task 3), `WbError` (Task 5-adjacent, existing).
- Produces: `get_checkpoint_v2(height) -> Result<CheckpointV2Envelope, WbError>`, `get_tree_boundary_witness(height) -> Result<TreeBoundaryWitness, WbError>`, `get_canonical_record(record_hash)`, `get_inclusion_proof(record_hash, checkpoint_height, withdrawal_root)`.

- [ ] **Step 1: Write failing test — checkpoint sends `schemaVersion=2` and parses the FLAT v2 body** — wiremock asserts the outbound query contains `format=root` AND `schemaVersion=2`; a flat response (`stateAvailable/status=ready/canonicalBlockHash/claimRoot/appHash/withdrawalRoot/schemaVersion=2/chainId`) decodes; recomputing `checkpoint_v2_claim_root(blockHash, appHash, withdrawalRoot, forceRoot)` equals `claimRoot`. A response with `schemaVersion` absent/`=1` yields `WbError::UnsupportedVersion`.

- [ ] **Step 2: Run to verify failure** — `cargo test -p op-succinct-fp --features tz wb_client` → FAIL (missing `schemaVersion=2` / still expects nested `components`).

- [ ] **Step 3: Add `schemaVersion=2` + flatten** — in `get_checkpoint_v2`, append `.append_pair("schemaVersion", "2")`; change `CheckpointDto` to the flat camelCase shape (no nested `components`); parse top-level `chainId` into the envelope; classify `schema_version != Some(2)` as `UnsupportedVersion`.

- [ ] **Step 4: Fix routes + status set** — record route `chain/witness/withdrawals/{recordHash}`; proof `chain/witness/withdrawal-proof`; boundary `query_tree_boundary?height` (replace the guessed `chain/canonical_record` / `chain/historical_inclusion_proof`); map `status` to the snake_case set (`ready|running|above_local_tip|no_base_snapshot|capacity_unavailable|failed`), `running`/`above_local_tip` ⇒ `NotReady`.

- [ ] **Step 5: Map nested record** — `get_canonical_record` decodes `WithdrawalLookupResponse` with `record.rawTradezoneWithdrawal.{tokenType,tokenAddress,tokenIds,amounts,from,to}` (nested), not a flat `RecordDto`.

- [ ] **Step 6: Run wb_client tests → PASS**; fmt + clippy.

- [ ] **Step 7: Commit**
```bash
git add fault-proof/src/tz/withdraw/wb_client.rs
git commit -m "[Oli] tz/withdraw/wb_client: send schemaVersion=2, flat checkpoint body, real routes + snake_case status + nested record"
```

**Requirement check:** R2 #1 + secondary route/record/status deviations fixed; matches R2.1-B/C/D wire.

---

## Task 3: `types.rs` — drop `chain_id` from `CheckpointV2`/`TreeBoundaryWitness`; add host envelope

Fixes R2 #3 (and the boundary-struct half of #2).

**Files:** Modify `fault-proof/src/tz/withdraw/types.rs`. Test: inline serde round-trip tests.

**Interfaces:**
- Produces: `CheckpointV2 { schema_version:u16, block_height:u64, block_hash, app_hash, withdrawal_root, force_root, claim_root }` (7 fields, mirrors `tz_witness::checkpoint::CheckpointV2`, **no chain_id**); `CheckpointV2Envelope { checkpoint: CheckpointV2, chain_id: u64 }`; `TreeBoundaryWitness { schema_version, block_height, block_hash, withdrawal_count:u32, withdrawal_active_branches:Vec<B256>, force_count:u32, force_active_branches:Vec<B256> }` (**no chain_id**).

- [ ] **Step 1: Write failing test — structs have no `chain_id`; envelope carries it** — assert `CheckpointV2` has exactly the 7 fields (a compile-time construction test) and that `CheckpointV2Envelope { checkpoint, chain_id }` is the only place chainId lives; `TreeBoundaryWitness` construction has no chainId.

- [ ] **Step 2: Run to verify failure** → FAIL (structs still hold `chain_id`).

- [ ] **Step 3: Remove `chain_id`** from `CheckpointV2` and `TreeBoundaryWitness`; add `CheckpointV2Envelope`.

- [ ] **Step 4: Run tests → PASS**; ensure `game_validator.rs` / `wb_client.rs` references compile against the new shapes (fixed in Tasks 2, 4).

- [ ] **Step 5: Commit**
```bash
git add fault-proof/src/tz/withdraw/types.rs
git commit -m "[Oli] tz/withdraw/types: drop chain_id from CheckpointV2/TreeBoundaryWitness; add host envelope"
```

**Requirement check:** R2 #3 fixed; struct set aligns with `tz_witness::checkpoint::CheckpointV2`.

---

## Task 4: `tree_adapter.rs` + boundary — delete local algorithm; delegate to `tz-witness`; drop boundary chainId

Fixes R2 #4 (delegation) and completes R2 #2 (boundary validation without chainId).

**Files:** Modify `fault-proof/src/tz/withdraw/tree_adapter.rs`, `fault-proof/src/tz/withdraw/wb_client.rs` (`BoundaryDto`), `fault-proof/src/tz/defender/verifier.rs`. Test: inline tests + empty-vector assertions.

**Interfaces:**
- Consumes: `tz_witness::merkle::{verify_proof, inner root/frontier API, empty_force_root}` and `tz_witness::checkpoint` (Task 1).
- Produces: adapter functions that only wrap `tz_witness` (outer `withdrawalRoot`/`forceRoot` = `keccak256(inner ‖ uint256(count) ‖ tag)`), consumed by proposer/guest/defender.

- [ ] **Step 1: Write failing test — proof verification delegates to `tz_witness`** — a valid `(leafHash, leafIndex, count, siblings[32])` verifies via the adapter (which now calls `tz_witness::merkle::verify_proof`); malformed inputs (`count==0`, `leafIndex==count`, `siblings.len()!=32`, wrong sibling) reject. Independently assert the three empty-tree vectors equal the frozen constants (computed, not copied).

- [ ] **Step 2: Run to verify failure** → FAIL if any local algorithm path is still used instead of `tz_witness`.

- [ ] **Step 3: Delete local algorithm** — remove `business_root`/`calculate_inner_root`/`verify_proof`/`zero_hashes`/`root_from_frontier`/`empty_*` bodies in `tree_adapter.rs`; route to `tz_witness::merkle` + `tz_witness::checkpoint`. Keep only the thin outer-wrap (`inner + count + tag`) that is op-succinct's own, not tz-witness's.

- [ ] **Step 4: Drop boundary chainId** — in `wb_client.rs` remove `BoundaryDto.chain_id` and its `!= 0` check; the boundary's correctness check is `withdrawal/forceActiveBranches.len() == count.count_ones()` + rebuild declared root via `tz_witness`.

- [ ] **Step 5: Re-point Defender verifier** — `defender/verifier.rs` calls `tz_witness::merkle::verify_proof` (tag `0x02` fixed) directly rather than the local adapter algorithm.

- [ ] **Step 6: Run tests → PASS**; fmt + clippy.

- [ ] **Step 7: Commit**
```bash
git add fault-proof/src/tz/withdraw/tree_adapter.rs fault-proof/src/tz/withdraw/wb_client.rs fault-proof/src/tz/defender/verifier.rs
git commit -m "[Oli] tz/withdraw: delegate tree/root/proof to tz-witness; drop local algo + boundary chainId"
```

**Requirement check:** R2 #4 (single source) + #2 (boundary) fixed; AC-1 single-computation-source honored.

---

## Task 5: L1 Challenger — flat v2 parse, `schemaVersion=2`, top-level chainId guard, field-by-field

Aligns the challenger to the flat wire (R2 #1/#3) and preserves the already-approved field-by-field comparison + retry semantics. Spec §5.3/§4.

**Files:** Modify `fault-proof/src/tz/game_validator.rs`, `fault-proof/src/config.rs:405` (`TzGameValidatorConfig` add `chain_id`), `fault-proof/bin/tz_challenger.rs`. Test: inline wiremock suite (extend existing).

**Interfaces:**
- Consumes: flat `SnapshotQueryResponse` (top-level `chainId`, no nested `components`); `claim.rs` `compute_claim_root`; `GameExtraData` decode.
- Produces: `TzGameValidator` that sends `schemaVersion=2`, guards `chain_id`, compares four fields + `rootClaim == claimRoot`.

- [ ] **Step 1: Write failing test — flat body + chainId guard** — a flat `ready` response (no nested `components`) with top-level `chainId != configured` ⇒ `Unavailable` (no advance); the outbound query includes `schemaVersion=2`. (Base code at `game_validator.rs:257-274` still reads a nested `components` object and omits `schemaVersion` — this test fails against it.)

- [ ] **Step 2: Run to verify failure** → FAIL.

- [ ] **Step 3: Add `chain_id: u64` to `TzGameValidatorConfig`** (`config.rs:405`, currently only `l2_rpc`), parsed from `TZ_CHAIN_ID` (reject `0`), logged; thread through `TzGameValidator::new` and `tz_challenger.rs`.

- [ ] **Step 4: Send `schemaVersion=2` + parse flat body** — `TzRootClient::query` appends `schemaVersion=2` and decodes the flat `SnapshotQueryResponse` (top-level `chainId`); replace the nested-`components` recompute path (`game_validator.rs:257-274`) with flat-field reconstruction of the four fields.

- [ ] **Step 5: Field-by-field comparison + chainId guard** — compare `blockHash/appHash/withdrawalRoot/forceRoot` (from Game `extraData`) individually plus `rootClaim == compute_claim_root(...)`; wrong `chainId` ⇒ do not advance; any field mismatch ⇒ existing challenge path.

- [ ] **Step 6: Preserve retry** — `NotReady`/`running`/`above_local_tip`/transient RPC ⇒ retryable `Unavailable`, no permanent miss (extend an existing retry test).

- [ ] **Step 7: Run challenger tests → PASS**; fmt + clippy.

- [ ] **Step 8: Commit**
```bash
git add fault-proof/src/tz/game_validator.rs fault-proof/src/config.rs fault-proof/bin/tz_challenger.rs
git commit -m "[Oli] tz challenger: flat v2 body, schemaVersion=2, top-level chainId guard, field-by-field compare"
```

**Requirement check:** R2 #1/#3 for the challenger; Spec §5.3/§4; retry/no-miss preserved.

---

## Task 6: SP1 range guest — integrate `tz-witness` (four-field pre/post claimRoot)

Fixes R2 #5 and lands the deferred guest wiring (handoff §5). Spec §5.2 guest / §6 / §10.

**Files:** Modify `programs/tz/range/src/main.rs`. Test: inline host-target tests + guest ELF build gate.

**Interfaces:**
- Consumes: `range_stdin` boundary fields appended by the proposer helper (already on the branch, handoff §5); `tz_witness::merkle` (rebuild inner root, append), `tz_witness::checkpoint::checkpoint_v2_claim_root`, `tz_block_processor::extract_withdrawals`.
- Produces: `BootInfoStruct { l2PreRoot = pre 128B claimRoot, l2PostRoot = post 128B claimRoot, .. }`.

- [ ] **Step 1: Guest compile baseline** — re-run Task 1 Step 6 to confirm the guest still builds with `tz-witness` before edits.

- [ ] **Step 2: Write failing host-target test — boundary → pre inner root / empty vectors** — for `count = 0/1/2/3/5`, rebuild `withdrawalInnerRoot` via `tz_witness::merkle` and assert the outer root matches; `count==0 ⇒ EMPTY_WITHDRAWAL_ROOT`, `forceCount==0 ⇒ empty_force_root()`.

- [ ] **Step 3: Run to verify failure** — `cargo test -p tz-range-program boundary` → FAIL (guest still uses two-field `keccak_join`).

- [ ] **Step 4: Read boundary inputs + build pre claimRoot** — after `chunk_count`, read the two `(count, activeBranches)` groups; rebuild pre inner roots via `tz_witness`; wrap to pre `withdrawalRoot`/`forceRoot`; `l2PreRoot = checkpoint_v2_claim_root(pre_block_hash, pre_app_hash, pre_withdrawal_root, pre_force_root)` (replacing the 64-byte `keccak_join`).

- [ ] **Step 5: Extract + append during replay → post claimRoot** — after each `process_block`, `tz_block_processor::extract_withdrawals` on the canonical result feeds `tz_witness` append; the guest MUST NOT trust host-supplied leaves/post root; compute `l2PostRoot = checkpoint_v2_claim_root(end_block_hash, end_app_hash, post_withdrawal_root, post_force_root)`.

- [ ] **Step 6: Write failing test — tamper ⇒ different post claimRoot** — swapping withdrawal/force roots or reusing a count changes `l2PostRoot`. Run → PASS after implementation.

- [ ] **Step 7: SP1 guest ELF build gate (hard)** — `just build-tz-range-elf` → builds.

- [ ] **Step 8: fmt + commit**
```bash
git add programs/tz/range/src/main.rs
git commit -m "[Oli] tz range guest: integrate tz-witness — four-field pre/post claimRoot from boundary + extract_withdrawals"
```

**Requirement check:** R2 #5 fixed; Spec §5.2 guest + §6 (guest self-computes post root) + §10 (boundary还原/篡改必败).

---

## Task 7: Rebuild ELFs, regenerate vkeys, update fdg-config vkey commitment

Lands the deferred vkey-affecting delivery (handoff §3, Spec §5.2 note/§12). Config only — no contract change.

**Files:** Modify `elf/` outputs (generated) + the fdg-config carrying `rangeVkeyCommitment`/`aggregationVkey` (e.g. `contracts/config/tz/opsuccinctfdgconfig.json` — confirm the exact path on-branch before editing). Test: command-based validation.

- [ ] **Step 1: Rebuild tz ELFs** — `just build-tz-elfs` (regenerates `tz-range-elf-embedded` + `tz-aggregation-elf`).
- [ ] **Step 2: Regenerate vkeys** — `just tz-vkeys`; record the new `rangeVkeyCommitment` + `aggregationVkey`.
- [ ] **Step 3: Update fdg-config** — write the new hashes into the config the proposer reads (`game_impl.rangeVkeyCommitment()` must match the loaded ELF); confirm current on-branch values before editing.
- [ ] **Step 4: Validate** — `just fp-contract-tests` + a mock proposer/challenger smoke (`just start fp-tz`) to confirm end-to-end vkey consistency.
- [ ] **Step 5: Commit**
```bash
git add elf <fdg-config-path>
git commit -m "[Oli] build: rebuild tz range/agg ELFs + update rangeVkeyCommitment for four-field guest"
```

**Requirement check:** Spec §5.2 ELF/vkey note + §12; guest change ↔ vkey kept consistent.

---

## Task 8: Regression + cross-language parity re-run

Confirms the corrections did not regress the already-green host-side suite and that cross-language parity still holds. Spec §10.

**Files:** existing tests under `fault-proof/tests/` + `programs/tz/*`. Test: this task IS test execution.

- [ ] **Step 1: Full tz unit + integration** — `cargo test -p op-succinct-fp --features tz` (expect the MR !102 baseline of 203 lib + 3 integration tests still green after the R2 corrections; update any test that asserted the OLD nested-`components`/chainId-in-boundary/`not_ready` shapes to the corrected wire).
- [ ] **Step 2: Cross-language parity** — Rust verifier (now `tz_witness::merkle::verify_proof`) vs Solidity harness on the frozen `claim-tree-v1.json` for ERC20 / ERC1155 batch / empty-tree reject / wrong tag / `leafIndex==count`: `just fp-contract-tests`.
- [ ] **Step 3: FP integration** — `just fp-integration-tests`; confirm original proposal/prove/resolve/challenge regression still passes.
- [ ] **Step 4: Commit any test corrections**
```bash
git add fault-proof/tests programs/tz
git commit -m "[Oli] tests: align tz withdraw tests to corrected WB wire; regression + cross-language re-run"
```

**Requirement check:** Spec §10 mapping; no regression of MR !102's green baseline; tests assert the corrected wire.

---

## Additional Context — task/validation mapping (all applicable; none inapplicable)

| AC | Statement (Spec §1) | Applicable? | Satisfied by |
|----|----------------------|-------------|--------------|
| **AC-1** | WB / `tz-witness` / extractor upstream on tradezone `feature/witness-builder-withdraw-v1` | Yes | **Task 1** (dep source + fixed rev), **Task 4** (delete local algo, delegate to `tz-witness`), **Task 6** (guest uses `tz-witness` + `extract_withdrawals`). |
| **AC-2** | Contracts in `xl/tz-challenger-v2` `contracts/src/fp` (final ABI authority); non-goal to modify | Yes (constraint) | **Validation-only**: Tasks 5/7 integrate the existing getters/`_verifyRootClaimPreimage`, `ITZRootManager`, `ITZClaimGame`; Global Constraints forbid contract changes; Withdraw challenge contract is external X Layer ABI. |
| **AC-3** | Use tradezone GitLab dev branch, not x2 mirror; fixed rev | Yes | **Task 1** (switch off `x2.git` rev `b3e2cf98`, pin `e56881eb2…`). |

**Inapplicable Additional Context items:** none. (Spec §1.2 confirms all three applicable and non-conflicting; Revision 2 reinforces AC-1/AC-3 as the root-cause fix.)

---

## Self-Review

**1. Spec coverage (Revision 2 focus):** R2 #1 → Tasks 2, 5. R2 #2 → Tasks 3, 4. R2 #3 → Tasks 3, 5. R2 #4 → Tasks 1, 4. R2 #5 → Task 6. Secondary route/record/status deviations → Task 2. Deferred dep switch/ELF/vkey (handoff) → Tasks 1, 7. Regression + cross-language (§10) → Task 8. Unchanged approved work (Defender, claim.rs codec, proposer helpers) intentionally not re-touched. §12 fetch precondition → Task 1 Step 1. No uncovered R2 item.

**2. Placeholder scan:** no `<REV>` placeholder (rev is resolved: `e56881eb2…`). The one deliberately un-pinned path is the exact fdg-config filename (Task 7) — flagged "confirm on-branch before editing" because it must be verified against the feature branch, not guessed. No "TBD/handle edge cases/write tests for the above".

**3. Type consistency:** `checkpoint_v2_claim_root`/`compute_claim_root`(128B) used identically in Tasks 5, 6; `CheckpointV2`(7 fields, no chain_id) + `CheckpointV2Envelope{checkpoint, chain_id}` defined in Task 3, consumed in Tasks 2, 5; `TreeBoundaryWitness`(no chain_id) in Tasks 3, 4, 6; `TzGameValidatorConfig.chain_id` added in Task 5. `tz_witness::merkle::verify_proof` is the single verify path in Tasks 4 (adapter/defender) and referenced by Task 8. No drift.

## Execution Handoff

Do NOT begin execution until stage 3.0 has reused the existing feature branch `xl/trdzn-1339/0903-0830` (MR !102). Prefer **Subagent-Driven** (superpowers:subagent-driven-development): fresh subagent per task with review between tasks. Task 1 is a hard gate — its Step 1 fetch precondition and Step 6 SP1 guest compile gate must be green before Tasks 4/6. If the tradezone dependency cannot be fetched, record the blocker and escalate (Spec §12) rather than reinstating a local tree copy.
