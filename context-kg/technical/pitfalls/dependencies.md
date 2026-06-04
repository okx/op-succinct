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

## p384 Not in SP1 Patch Set

[Pitfall] `p384` is NOT included in the `[patch.crates-io]` SP1 fork set, unlike `k256` and `p256`. All P-384 ECDSA operations (used by TEE attestation cert chain verification — 4 cert signature verifications + 1 COSE ES384 signature) run as pure Rust on RISC-V without hardware acceleration. This makes TEE batch proving significantly more cycle-expensive than SP1 batches.

**Trigger**: Adding or modifying code that uses P-384 curves inside a zkVM guest (e.g. TEE attestation verification).

**Correct**: Profile P-384 cycle count with `sp1_zkvm::precompiles::cycle_tracker` before assuming acceptable performance. Monitor SP1 releases for a potential `p384` precompile patch.

[Rule] When adding new elliptic curve operations to a zkVM guest, always check whether the curve has an SP1 precompile patch in `[patch.crates-io]`. Unpatched curves run orders of magnitude slower.

**Module**: `programs/aggregation` (TEE attestation verification)
**Source**: Adversarial review finding #1 (XLOP-1065)
**Date**: 2026-06-04
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

[Pitfall] Root `Cargo.toml` lists 19 explicit + 2 glob workspace members (`programs/range/*`, `scripts/*`). Adding a new member requires updating the workspace list. Whether to also add it to `workspace.dependencies` depends on consumption pattern: crates consumed by multiple workspace members via `{name}.workspace = true` should be added; leaf crates consumed via `path = "…"` by a small number of specific consumers may be omitted (e.g. `xlayer-tee-types` is referenced by path only). Trigger: new crate scaffolding. Correct approach: follow the existing pattern; run `cargo metadata --format-version=1` to verify.
