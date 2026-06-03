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

## SP1 Patch Availability for New Guest Dependencies

[Pitfall] When adding a new RustCrypto crate (or any crypto crate) to a zkVM guest program, check whether an SP1-optimized patch exists in the workspace `[patch.crates-io]` section. Missing patches mean unoptimized native Rust crypto runs inside the zkVM at significantly higher cycle cost. Example: `k256 v0.13` has an SP1 patch (`patch-k256-13.4-sp1-6.0.0`) with precompile acceleration; `p384 v0.13` does NOT have an SP1 patch, resulting in higher per-verification cycle cost for P-384 operations. This is accepted for `p384` because certificate chain verification runs only once per aggregation (not per-range), but the cycle budget impact should be measured for any high-frequency guest operation.
**Trigger**: adding a new `*-crypto` or `elliptic-curve` crate to a `programs/*` guest crate.
**Correct**: search `[patch.crates-io]` for an existing SP1 patch; if none exists, document the cycle cost impact and verify it's acceptable for the call frequency.
**Module**: `Cargo.toml` (workspace patches), `programs/aggregation/Cargo.toml`
**Source**: review-finding F-08 (Code Review R6, TD §4.9.1 Risk R-2)
**Date**: 2026-06-02
**Hit count**: 1

## Dual CBOR Library Coexistence

[Pitfall] The workspace has two CBOR libraries: `serde_cbor` (used for L1 header encoding in `programs/aggregation/src/main.rs`) and `ciborium` (used for COSE_Sign1 and AttestationDoc parsing in `programs/aggregation/src/tee/`). Both are compiled into the guest ELF, adding ~20-30KB. `serde_cbor` is unmaintained; `ciborium` is its maintained successor and is RFC 7049/8949 compatible. Migration of existing `serde_cbor` usage to `ciborium` is deferred per PRD minimal change principle. Future CBOR work in guest code should use `ciborium`, not `serde_cbor`.
**Trigger**: adding new CBOR parsing to the aggregation guest.
**Correct**: use `ciborium`; do not add new `serde_cbor` usage. Plan eventual migration of existing `serde_cbor` header parsing to `ciborium`.
**Module**: `programs/aggregation/src/main.rs` (serde_cbor), `programs/aggregation/src/tee/` (ciborium)
**Source**: review-finding F-04 (Adversarial Review #1)
**Date**: 2026-06-02
**Hit count**: 1

## Local Build Hits Endpoint Security

[Pitfall] sp1's build scripts spawn helper binaries under `~/.cargo/git/checkouts/sp1-*/target/sp1-native-bins/debug/build/`. On macOS with Santa (or similar endpoint security), these are blocked and SIGKILLed. Trigger: first sp1 build after a version bump. Correct approach: apply to the Santa allowlist; or build inside Docker; or rely on CI for verification.

## ELF Build Pipeline

[Rule] ELF compilation must run inside Docker (`tag v6.1.0`) via `sp1_build::build_program_with_args` — the in-repo `utils/build/src/lib.rs` build calls are intentionally commented out. Trigger: re-enabling the in-tree builder. Correct approach: build externally; don't run cargo prove build inside the workspace build script.

## Cargo.lock Conflicts

[Pitfall] Merging `dev` into a feature branch often produces a `Cargo.lock` conflict due to sp1/kona version bumps in dev. Trigger: routine PR maintenance. Correct approach: `git checkout --theirs Cargo.lock` and run `cargo check` to let cargo re-solve from the merged `Cargo.toml`; commit the result.

## Upstream Error String Coupling

[Pitfall] Detecting upstream error conditions by matching `e.to_string().contains("…")` silently breaks when the upstream crate changes wording. Trigger: dependency version bump modifies an error message used as a discrimination sentinel. Correct approach: define a `const SENTINEL: &str = "…"` in the consumer crate, reference it in both the match logic and a dedicated integration test that asserts the sentinel still appears in the upstream output. Pin the dep version and re-validate on every bump. Example: `fault-proof/tee/enclave/src/error.rs::CLAIM_MISMATCH_SENTINEL` detects kona executor's "Failed to validate L2 block" message; a golden-test asserts the format.

**Module**: `fault-proof/tee/enclave/src/error.rs`, `fault-proof/tee/enclave/src/runner.rs`
**Source**: Adversarial Review Finding #1 (2026-06-02)
**Date**: 2026-06-02
**Hit count**: 1

## Workspace Member Drift

[Pitfall] Root `Cargo.toml` lists 19 explicit + 2 glob workspace members (`programs/range/*`, `scripts/*`). Adding a new member requires updating the workspace list. Whether to also add it to `workspace.dependencies` depends on consumption pattern: crates consumed by multiple workspace members via `{name}.workspace = true` should be added; leaf crates consumed via `path = "…"` by a small number of specific consumers may be omitted (e.g. `xlayer-tee-types` is referenced by path only, and `xlayer-tee-host` uses direct version specs for deps like `axum 0.8`, `tower-http 0.6` that differ from workspace versions). Trigger: new crate scaffolding. Correct approach: follow the existing pattern; run `cargo metadata --format-version=1` to verify.

## tower-http Version Mismatch with axum 0.8

[Pitfall] The workspace declares `tower-http 0.5.2`, but `axum 0.8` requires `tower-http 0.6`. New crates using axum 0.8 cannot use `tower-http = { workspace = true }` — they must declare a direct dependency on `tower-http 0.6`. This version mismatch is not caught by `cargo check` until the specific axum feature (e.g. `DefaultBodyLimit` from `tower-http::limit`) is actually used, producing a confusing "trait not implemented" error rather than a version conflict. Trigger: adding a new inbound HTTP service crate using axum 0.8 while the workspace pins tower-http 0.5.x. Correct approach: use direct version dependency `tower-http = { version = "0.6", features = ["limit"] }` in the new crate's Cargo.toml instead of `workspace = true`. Do not bump the workspace version unless all existing consumers are migrated.

**Module**: `fault-proof/tee/host/Cargo.toml`
**Source**: TDD Summary A-06 (design decision #5)
**Date**: 2026-06-02
**Hit count**: 1
