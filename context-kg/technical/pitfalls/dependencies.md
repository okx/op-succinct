---
name: "dependencies"
description: "Dependency and build pitfalls — sp1 patches, kona-rpc avoidance, DA feature flags, ELF build pipeline"
---
# Dependency and Build Pitfalls

## sp1 Patch Chain

[Rule] Root `Cargo.toml [patch.crates-io]` must keep all `sp1-*` and `slop-*` crates pinned to `github.com/okx/sp1#feat/gateway-proxy-v6.1.0`. Removing any patch breaks production cluster gateway auth. Affected: every workspace member transitively pulls sp1. Recovery: re-add the patches and `cargo update`.

## kona-rpc Conflict

[Rule] `utils/host/Cargo.toml`: never add `kona-rpc`. Trigger: convenience refactor to use kona's RPC types directly. Why prohibited: `kona-rpc` → `rollup-boost` → `reth-optimism-primitives` → alloy version conflict with hokulea v1.1.4. Correct approach: maintain local RPC types in `utils/host/src/rpc_types.rs`.

## Cross-Crate Boundary

[Rule] `utils/client/*` must not depend on `utils/host`, `utils/signer`, `utils/proof`, or any `*-host-utils`. Trigger: convenience reuse of host types in guest code. Why prohibited: zkVM-guest isolation — only the preimage oracle is permitted. Correct approach: hoist shared types to `op-succinct-client-utils`.

## DA Feature Exclusivity

[Rule] `utils/proof` selects exactly one DA via Cargo feature flag (`ethereum` / `celestia` / `eigenda`) at compile time. Multi-DA in one build is not supported. Trigger: trying to build a generic node. Correct approach: produce three separate binaries, one per DA.

## Patched RustCrypto Hashes

[Pitfall] `Cargo.toml [patch.crates-io]` pins `sha2`, `sha3`, `tiny-keccak`, `k256`, `p256`, `substrate-bn` to `sp1-patches` forks. These contain precompile-friendly variants for the zkVM. Removing them silently degrades guest performance and may break precompile invocation. Trigger: dependency cleanup. Correct approach: keep patches; bump tags only when the official sp1 release notes call out a change.

## Local Build Hits Endpoint Security

[Pitfall] sp1's build scripts spawn helper binaries under `~/.cargo/git/checkouts/sp1-*/target/sp1-native-bins/debug/build/`. On macOS with Santa (or similar endpoint security), these are blocked and SIGKILLed. Trigger: first sp1 build after a version bump. Correct approach: apply to the Santa allowlist; or build inside Docker; or rely on CI for verification.

## ELF Build Pipeline

[Rule] ELF compilation must run inside Docker (`tag v6.1.0`) via `sp1_build::build_program_with_args` — the in-repo `utils/build/src/lib.rs` build calls are intentionally commented out. Trigger: re-enabling the in-tree builder. Correct approach: build externally; don't run cargo prove build inside the workspace build script.

## Cargo.lock Conflicts

[Pitfall] Merging `dev` into a feature branch often produces a `Cargo.lock` conflict due to sp1/kona version bumps in dev. Trigger: routine PR maintenance. Correct approach: `git checkout --theirs Cargo.lock` and run `cargo check` to let cargo re-solve from the merged `Cargo.toml`; commit the result.

## Workspace Member Drift

[Pitfall] Root `Cargo.toml` lists 19 explicit + 2 glob workspace members (`programs/range/*`, `scripts/*`). Adding a new member requires updating the workspace list AND adding it to `workspace.dependencies` if any other crate references it. Trigger: new crate scaffolding. Correct approach: follow the existing pattern; run `cargo metadata --format-version=1` to verify.

## Whole-Workspace Resolution Blocked by Private github Dep (okx/x2)

[Pitfall] `programs/tz/range` (the zkVM guest) depends on the **private github** crates `tz-block-processor` / `tz-dex` / `tz-primitives` from `okx/x2` (pinned rev). In environments without a github SSH deploy key (e.g. this Oli pipeline env, where the git token rewrite only covers `gitlab.okg.com`) and without the pinned commit in the cargo cache, the source cannot be resolved. Because **Cargo resolves the entire workspace dependency graph before building anything**, even a scoped `cargo check -p op-succinct-fp` fails with `failed to load source for dependency tz-block-processor` — it never reaches the host crate, which does not need x2 at all.

[Rule] The host crate `op-succinct-fp` (fault-proof) does **NOT** need `okx/x2`: the range ELF is embedded via `include_bytes!` (see `decisions/ADR-008-elf-embedding-strategy.md`); only the guest crate compiles against x2, in a separate zkVM toolchain step. So gates for a fault-proof-only change can be validated by scoping to the changed crate (`rtk cargo check -p op-succinct-fp --all-targets --features tz`; `cargo test -p op-succinct-fp --features tz --lib`). Trigger: running `cargo check --all-targets --all-features` for a fault-proof change in a network/key-restricted env. Correct approach: scope to `-p op-succinct-fp`; if a temporary `programs/tz/range` workspace-member exclusion is used to force resolution, **revert it** (verify `git diff` on `Cargo.toml`/`Cargo.lock` is empty) — workspace membership must not change in the deliverable.

[Pitfall] `validity` pulls `postgresql_embedded`, whose build script **downloads PostgreSQL binaries from github** at build time — also impossible in a no-network env. `fault-proof ↮ validity` (no cross-dependency; see `arch/dependency.md`), so a fault-proof change is unaffected — this is a second reason a full-workspace gate fails in a restricted env without implicating the change under review.

Source: review-finding F-01/F-02 (TDD Summary A-06 §6 environment limitations)

## Contract Pragma Relax + `via_ir` for `forge bind`

[Pitfall] `op-succinct-bindings` runs `forge bind` and is a **test-build prerequisite of fault-proof** (fault-proof tests won't build until bindings compile). If a change relaxes Solidity pragmas (`pragma solidity 0.8.15;`/`0.8.20;` → `^...`) to route all contracts through a single solc (e.g. 0.8.24), the tz deploy scripts then fail to compile under that single compiler with Solidity **"Stack too deep"**, which breaks `forge bind` and therefore the whole fault-proof test build. Trigger: a Rust change that transitively triggers a `forge bind` after touching contract pragmas. Correct approach: add `optimizer = true` + `via_ir = true` to `contracts/foundry.toml` — the **same flags `contracts/deploy-tz.sh` already uses** for these scripts, so deployed/verifier bytecode already matches; this changes no ABI, vkey, or ELF. Note this is an out-of-feature-scope build-enablement change → get the contract-pipeline owner to confirm.

[Pitfall] Relaxing pragmas inside **vendored submodules** (`contracts/lib/{optimism,lib-keccak,sp1-contracts}`) to make a local `forge build`/`forge bind` pass leaves the submodules `-dirty` (working-tree edits, submodule SHA unchanged). Because submodules are committed as pointers, these edits do **not** travel into the parent-repo MR — correct, but it leaves a tree that cannot be cleanly committed and a fresh CI checkout will hit the original pragma mismatch again. Trigger: editing vendored `.sol` pragmas as a quick local fix. Correct approach: treat them as env-local scaffolding — **revert before the Push+MR stage**, or bump the upstream lib properly if genuinely needed.

Source: review-finding F-03/F-04 (TDD Summary A-06 §6; Code Review A-08 R6-3/R6-4)
