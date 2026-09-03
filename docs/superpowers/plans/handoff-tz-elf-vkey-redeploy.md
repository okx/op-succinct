# Hand-off: TZ four-field claim — tradezone dep switch, ELF/vkey rebuild, redeploy

> Operational hand-off produced by the Execute-and-Validate stage. **No build/deploy is performed
> here.** It records the steps that are mandatorily gated on the SP1 guest toolchain (Spec §8, §12)
> and therefore deferred to a provisioned environment, so a re-run there can complete them
> deterministically.

Jira: [TRDZN-1339](https://okcoin.atlassian.net/browse/TRDZN-1339) ·
Spec: `docs/superpowers/specs/2026-09-03-tz-withdraw-forcetx-four-field-claim-and-defender-design.md` ·
Plan: `docs/superpowers/plans/2026-09-03-tz-withdraw-forcetx-four-field-claim-and-defender-plan.md`

## 1. Why a dep switch + rebuild + redeploy is required (Spec §8, §12; Plan Tasks 1, 4, 9)

Threading the four-field `claimRoot = keccak256(blockHash ‖ appHash ‖ withdrawalRoot ‖ forceRoot)`
through the SP1 range guest changes what the guest commits and (once the boundary witness is added
to the guest's `SP1Stdin`) its input layout. Therefore **both the range vkey and the aggregation
vkey change**. Until the on-chain config is updated, `prove` will revert on a vkey mismatch — so
the MR is host-side build-/test-green but NOT deploy-complete. No dual-mode: wire mixing is
protocol-forbidden (Spec §8).

Spec §8 makes the tz-* dependency switch a **hard, mandatorily-gated** change:
> 编译门槛（硬性）：实现阶段必须在 SP1 guest target 实测 `cargo check` 通过 … 不能只停留纸面。

That gate (Plan Task 1 Step 5) **cannot run in the current execution environment** — the SP1
toolchain (`cargo-prove`, `~/.sp1/`) is absent. Committing the guest-dep switch without passing
the guest `cargo check` would violate Spec §8, so it is deferred rather than applied blindly.

## 2. AC-3 / Plan Task 1 — resolved inputs (ready to apply where SP1 is available)

Task 1 Step 1 (resolve the exact feature-branch HEAD) **is done** in this run:

- `git ls-remote https://gitlab.okg.com/xlayer-dex/tradezone.git refs/heads/feature/witness-builder-withdraw-v1`
  → **`e56881eb29879166752294c87b207a23bb2dcc26`** (reachable over HTTPS from this environment;
  supersedes the prior hand-off's `a3f3079b7`).

Apply this stanza to the workspace-root `Cargo.toml` (currently lines ~155-158) in an
SP1-provisioned environment, then run Task 1 Steps 3-6:

```toml
# tradezone (range guest deps) — TradeZone GitLab feature branch, fixed rev (WB Withdraw/Force work)
tz-block-processor = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "e56881eb29879166752294c87b207a23bb2dcc26", features = ["tee"] }
tz-dex             = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "e56881eb29879166752294c87b207a23bb2dcc26", features = ["zkvm"] }
tz-primitives      = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "e56881eb29879166752294c87b207a23bb2dcc26" }
tz-witness         = { git = "ssh://git@gitlab.okg.com/xlayer-dex/tradezone.git", rev = "e56881eb29879166752294c87b207a23bb2dcc26" }
```

> Verify the crate names/paths (`crates/witness` etc.) and feature flags against the branch's own
> `Cargo.toml` before committing (Spec §7.4). After the switch: `cargo metadata` (confirm all four
> resolve to the rev, no `x2.git` remnant in `Cargo.lock`), host build, then the **mandatory** SP1
> guest `cargo check` gate.

## 3. Required sequence (run in an environment with SP1 + private-dep access)

1. Apply the §2 dep switch; regenerate `Cargo.lock`.
2. `cargo build -p op-succinct-fp --features tz` (host gate).
3. **SP1 guest compile gate (hard, Spec §8):** `cd programs/tz/range && ~/.sp1/bin/cargo-prove prove build …`.
4. Implement the guest four-field wiring (§5 below), then `just build-tz-elfs` — rebuild
   `tz-range-elf-embedded` + `tz-aggregation-elf` (Plan Task 9).
5. `just tz-vkeys` — regenerate the vkey hashes (`cargo run --release --bin tz-config`).
6. Update `contracts/config/tz/opsuccinctfdgconfig.json` `rangeVkeyCommitment` + `aggregationVkey`
   with the new hashes (confirm the current on-branch values against the file before editing).
7. Redeploy the tz Game config (deploy-tz).

## 4. Environment access / toolchain blockers observed during this execution

Git access here reaches `github/op-succinct` **and** `gitlab.okg.com` over HTTPS, but not SSH,
and there is no SP1 toolchain:

| Dependency / tool | Host / transport | Needed for | Status here |
|---|---|---|---|
| `tz-dex`, `tz-block-processor`, `tz-primitives` (`x2.git` @ `b3e2cf98…`) | github.com/okx, **SSH** | SP1 range guest (`programs/tz/range`) | **unreachable** (SSH publickey denied; private repo, HTTPS auth also fails) |
| TradeZone `tz-witness`/core (`tradezone` @ `feature/witness-builder-withdraw-v1`) | gitlab.okg.com, **HTTPS** | guest tree rebuild + host verifier delegation (AC-1) | **reachable** over HTTPS; HEAD `e56881eb…` resolved. SSH denied. |
| `ok-kms-rust` (`v1.0.0`) | gitlab.okg.com, HTTPS | optional `kms` signer feature (OFF for tz) | reachable over HTTPS (ssh→https rewrite used for host resolution) |
| SP1 toolchain (`cargo-prove`) | — | building/checking the guest ELF (Spec §8 gate) | **absent** — the blocking item for AC-3 / Task 1 completion |

**Host-side validation harness used this run (NOT committed):** to run `cargo test -p op-succinct-fp
--features tz` while `programs/tz/range` (the only `x2.git` consumer) is unreachable, that guest
member was temporarily removed from the workspace `[workspace].members` (moved to `exclude`), and the
optional `ok-kms-rust` git dep was fetched over HTTPS via a per-command
`url."https://gitlab.okg.com/".insteadOf "ssh://git@gitlab.okg.com/"` rewrite with
`CARGO_NET_GIT_FETCH_WITH_CLI=true`. **Both are validation-harness only and reverted before commit**
— they are NOT part of the branch. In a provisioned environment, keep `programs/tz/range` in the
workspace and let the real deps resolve.

## 5. Deferred code that requires the above access (paired, vkey-affecting — land together)

The host-side building blocks are implemented and unit-tested on this branch (§6); the following
runtime wiring must be completed where the guest can compile against the real TradeZone tree core:

- **SP1 range guest (`programs/tz/range/src/main.rs`, Plan Task 4):** read the boundary-witness
  fields from `SP1Stdin` after `chunk_count`; rebuild the two pre `innerRoot`s from
  `count + activeBranches` via the tradezone `tz-witness`; wrap with `count + tag` for pre
  `withdrawalRoot`/`forceRoot`; replay canonical blocks and let `tz-block-processor::extract_withdrawals`
  + `tz-witness` compute the post roots (the guest MUST NOT trust host-supplied leaves); commit the
  four-field claim as `l2PreRoot`/`l2PostRoot`. Blocked here: `programs/tz/range` depends on the
  unreachable `x2.git` deps and no SP1 toolchain is present; the exact `tz-witness` API must be
  linked, not guessed.
- **Proposer stdin splice (`fault-proof/src/tz/proposer.rs`, Plan Task 5):** after
  `range_stdin.write(&chunk_count)`, append the boundary fields produced by the unit-tested
  `boundary_stdin_fields` helper (already on this branch). Host half of the same vkey-affecting
  change as the guest read above — land together.
- **Single-computation-source (AC-1, Spec §5.4):** re-point the host Defender local verifier
  (`fault-proof/src/tz/defender/verifier.rs` → `tz/withdraw/tree_adapter.rs`) to delegate to
  `tz_witness::verify_proof` once `tz-witness` is a resolvable dependency of `fault-proof`, so the
  proof/tree math has a single byte-source. The current native implementation is spec-faithful and
  unit-tested against the published empty vectors, and is retained as the cross-check oracle.

## 6. What IS complete and verified on this branch (host-side)

`cargo test -p op-succinct-fp --features tz --lib --test tz_defender_integration` is green
(**203 lib + 3 integration tests, 0 failed** in this run). Verified: the four-field shared library
(`tz/withdraw/` — claimRoot/sub-root codec, 164-byte extraData decode, `CheckpointV2`/boundary/proof
types, `WbError` taxonomy, tree-adapter outer wrapper + proof-path verify + empty-vector assertions),
the WB v2 read client (4 endpoints + popcount/declared-root/chainId validation), the L1 challenger
chainId guard + four-field claim comparison, the WB-backed `compute_output_root_at_block`, the
boundary fetch/cross-check/stdin-ordering + 164-byte `extraData` self-consistency helpers, and the
full independent Defender (challenge seam, config, RootManager source, LRU cache, local verifier,
watcher, handler state machine, `tz-defender` binary). Empty-tree vectors are computed independently
and asserted against the Spec's published values (no frozen fixture required).
