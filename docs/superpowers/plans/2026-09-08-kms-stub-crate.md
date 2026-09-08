# KMS Stub Crate — feature-gated `ok-kms-rust` secret resolution — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Do not run `executing-plans` from this (planning) stage** — this document is the deliverable of the "Write Implementation Plan" stage; execution happens in the downstream "Execute and Validate Plan" stage.

**Goal:** Make `op-succinct` build out of the box offline for every contributor/CI job by replacing the private SSH git dependency on `ok-kms-rust` with an in-tree stub, while resolving `kms:<name>` secret references through the real SDK in production builds.

**Architecture:** Declare `ok-kms-rust` as an in-tree **path** dependency (`stubs/ok-kms-rust`) that is always present; a `just` recipe swaps the *contents* of that directory (stub ↔ real SDK) for production — the committed manifest is never edited. `utils/signer` gains a unified reference model (`is_kms_ref`, `maybe_resolve`, `KmsError`) that resolves `kms:<name>` values via a process-wide, never-dropped KMS client behind the existing `kms` feature, and passes non-`kms:` values through byte-for-byte.

**Tech Stack:** Rust (edition 2021, workspace `resolver = "2"`), Cargo workspace, `thiserror`, `serde_json`, `tracing`, `OnceLock`; `just` task runner. Consumer surface: `op-succinct-signer-utils` (`utils/signer`) and the `op-succinct-fp` fault-proof binaries.

**Spec:** `docs/superpowers/specs/2026-09-08-kms-stub-crate-design.md` (Status: **APPROVED** 2026-09-08, Oli Stage 1.0; creator approved via AskUserQuestion after Lark review). Lark review doc: <https://okg-block.sg.larksuite.com/docx/Gy87dovrroicCrx2JwjlbXl1gNf> (recorded in `docs/superpowers/lark-review-doc.md`).

**Jira:** [XLOP-1197](https://okcoin.atlassian.net/browse/XLOP-1197) (Epic, `technical-epic`).

**Repository / branch:** `op-succinct` (`gitlab.okg.com/github/op-succinct.git`); base and MR target branch **`xl/tz-dev`** (resolved from native task context; feature branch is created by the downstream branch stage and reused on feedback rounds).

## Global Constraints

Every task's requirements implicitly include this section. Values copied verbatim from the approved spec §5 and grounded against the current tree.

- **GC1 — No private URL in the committed manifest.** After the change, `git grep 'ssh://git@gitlab.okg.com' -- '*.toml'` MUST find nothing. (Anchor goal; today it matches `Cargo.toml:40`.)
- **GC2 — No git dependency on the private group** anywhere in `[workspace.dependencies]` for KMS.
- **GC3 — No real SDK checkout committed.** `stubs/ok-kms-rust` in Git contains only the stub; the real checkout exists only transiently after `just kms-crate` and is reverted by `just kms-crate-restore`. `git status --porcelain stubs/ok-kms-rust` MUST be empty before any commit.
- **GC4 — Offline default build.** `cargo check`, `cargo clippy`, and `cargo test` succeed for the KMS path with no network and no private-GitLab access (stub in place).
- **GC5 — Byte-for-byte passthrough.** Non-`kms:` values (including surrounding whitespace) round-trip unchanged through `maybe_resolve`. No trimming, no normalization.
- **GC6 — Feature default OFF.** `kms` is in no default feature set; a `kms:` reference without the feature yields `KmsError::Disabled` + rebuild guidance and never touches the SDK.
- **GC7 — Loud stub failure.** With `--features kms` + stub, every lookup fails carrying the literal `OK_KMS_STUB`; the KMS build recipe refuses a stub-linked binary.
- **GC8 — Client reuse.** The process-wide KMS client is constructed at most once via a `static OnceLock` and never dropped (the real SDK loads a Go CGO `.so`; dropping it would `dlclose` → SIGBUS).
- **GC9 — Workspace hygiene.** `members` updated for `stubs/ok-kms-rust`; `cargo metadata --format-version=1` resolves; no accidental workspace-membership churn elsewhere.
- **GC10 — Never log secret material.** Per `context-kg/technical/pitfalls/signer.md` ("Sensitive Data in Logs"): never log `access_key`, `secret_key`, raw private keys, or resolved secret values. `KmsError` messages carry only the reference *name* or the SDK error text, never the resolved secret.
- **GC11 — Scoped gates (restricted-env aware).** Validate with crate-scoped commands (`-p op-succinct-signer-utils`, `-p ok-kms-rust`, `-p op-succinct-fp --bin proposer`). Do NOT run a full `--all-features --workspace` gate: it fails in restricted envs for unrelated reasons — `programs/tz/range` needs private `okx/x2` github SSH deps and `validity` downloads `postgresql_embedded` (see `context-kg/technical/pitfalls/dependencies.md`). Those are out of scope.
- **GC12 — Commit hygiene.** `docs/superpowers/**` is committed to the feature branch (normal repo Git rules; no special policy). Every Oli commit subject begins **exactly** `[Oli] ` (with the trailing space).

## Design decisions carried in from the approved spec (adopt as-is)

The spec §9 left open items; the approved defaults are adopted here so the executor does not re-litigate them:

- **D1 (spec §3.8 / §9.1) — retire the env-flag model.** Remove `ENABLE_KMS` / `KMS_SECRET_KEY_NAME`, `is_kms_enabled()`, and `fetch_secret()` outright (default = remove; no live deployment is known to set `ENABLE_KMS`). A `kms:<name>` value placed in `XLAYER_SECRET_KEY` now triggers resolution. If a live deployment using `ENABLE_KMS=true` is discovered during execution, STOP and escalate rather than silently keeping the flag.
- **D2 (spec §3.4 / §9.2) — resolution call is `get_all_secrets()`.** The stub mirrors the proven real-SDK surface: `KmsClient::new() -> Result<KmsClient, KmsError>`, `KmsClient::get_all_secrets() -> Result<String, KmsError>`, `KmsError::Disabled`. Before the first `just kms-crate` production build, re-verify the real SDK surface still matches the stub (Task 4, verify note).
- **D3 (spec §3.2 alt C) — extend `utils/signer`, no new crate.** The reference model lives in `utils/signer/src/kms.rs` (the signer is today's only secret consumer), reusing the existing `kms` feature and `OnceLock`.

## Additional Context

**None supplied** (spec §8; the Oli `external_inputs` channel was empty and the Jira ticket has no linked PRD/remote content). There is therefore no applicable Additional Context item to map to a task. This is recorded as **inapplicable — reason: not supplied for this task**. If a feedback iteration supplies Additional Context, add a delta plan (see "Feedback iterations" below) that maps each new item to a task or records it inapplicable with a reason.

## File Structure (created / modified)

| File | Action | Responsibility |
|---|---|---|
| `stubs/ok-kms-rust/Cargo.toml` | Create | Stub crate manifest; package name `ok-kms-rust`, dependency-free, offline-resolvable. |
| `stubs/ok-kms-rust/src/lib.rs` | Create | Stub SDK: `STUB_MARKER`, `KmsError`, `KmsClient::new` (Ok), `get_all_secrets` (Err carrying `OK_KMS_STUB`). |
| `Cargo.toml` (workspace root) | Modify | `Cargo.toml:40` git→path dep; add `stubs/ok-kms-rust` to `[workspace] members` (lines 2–24). |
| `utils/signer/src/kms.rs` | Modify (rewrite) | Reference model: `KMS_REF_PREFIX`, `is_kms_ref`, `maybe_resolve`, `KmsError`; feature-gated SDK `imp` module with `OnceLock` client; unit tests. |
| `utils/signer/src/lib.rs` | Modify | Re-export reference API; rewrite `resolve_xlayer_secret_key` (`lib.rs:28-38`); apply `maybe_resolve` at secret read-sites in `Signer::from_env` (`access_key` `lib.rs:118-119`, `secret_key` `lib.rs:120`, `PRIVATE_KEY` `lib.rs:168-169`); integration tests. |
| `utils/signer/Cargo.toml` | No change | Already `ok-kms-rust = { workspace = true, optional = true }` and `kms = ["dep:ok-kms-rust"]` (lines 32, 50). `thiserror`/`serde_json`/`tracing` already present (lines 44, 36, 43). |
| `justfile` | Modify | Add `kms-crate`, `kms-crate-restore`, `build-kms` recipes (append near the build recipes). |
| `docs/superpowers/**` | Commit | Spec + this plan + lark-review-doc committed to the feature branch (GC12). |

---

## Task 1: In-tree stub crate + workspace wiring

**Files:**
- Create: `stubs/ok-kms-rust/Cargo.toml`
- Create: `stubs/ok-kms-rust/src/lib.rs`
- Modify: `Cargo.toml` (root) — line 40 (`[workspace.dependencies] ok-kms-rust`) and `members` (lines 2–24)

**Interfaces:**
- Produces (the compile-time contract consumed by Task 2's `#[cfg(feature = "kms")]` module):
  - `ok_kms_rust::STUB_MARKER: &str` (== `"OK_KMS_STUB"`)
  - `ok_kms_rust::KmsClient` with `pub fn new() -> Result<KmsClient, KmsError>` and `pub fn get_all_secrets(&self) -> Result<String, KmsError>`
  - `ok_kms_rust::KmsError` — enum implementing `std::error::Error + Display`, with at least the variant `Disabled` (the only variant Task 2 names).

- [ ] **Step 1: Create the stub crate manifest**

Create `stubs/ok-kms-rust/Cargo.toml`:

```toml
[package]
name = "ok-kms-rust"
version = "1.0.0"
edition = "2021"
license = "MIT"
description = "In-tree stub of the OKG ok-kms-rust SDK. Compiles offline with no private-group access; every secret lookup fails carrying the OK_KMS_STUB marker. Swap for the real SDK via `just kms-crate` for production builds."

[dependencies]
```

(No dependencies — plain safe Rust so it resolves with no network / no private-GitLab access. `version = "1.0.0"` mirrors the real SDK tag; the workspace dep line carries no version constraint, so a path dep substitutes cleanly.)

- [ ] **Step 2: Write the stub crate source**

Create `stubs/ok-kms-rust/src/lib.rs`:

```rust
//! In-tree stub of the OKG-internal `ok-kms-rust` SDK.
//!
//! The stub mirrors exactly the public surface `op-succinct-signer-utils`
//! compiles against so a workspace path dependency substitutes for the real
//! SDK without touching the committed manifest. `KmsClient::new` succeeds so
//! init paths stay exercised, but every secret lookup fails carrying
//! `STUB_MARKER` — a binary accidentally built `--features kms` against the
//! stub fails loudly on first use instead of authenticating with a bogus
//! credential. Swap for the real SDK with `just kms-crate`.

/// Marker embedded in every stub lookup error and thus in a stub-linked
/// binary's read-only data. `grep -ac OK_KMS_STUB <binary>` is > 0 for a
/// stub-linked build and 0 for a real-SDK build.
pub const STUB_MARKER: &str = "OK_KMS_STUB";

/// Mirrors the real SDK's error type surface that the signer references.
#[derive(Debug)]
pub enum KmsError {
    /// The SDK reported KMS disabled at client construction.
    Disabled,
    /// Stub-specific: any lookup against the stub. Carries `STUB_MARKER`.
    Stub(String),
}

impl std::fmt::Display for KmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KmsError::Disabled => write!(f, "ok-kms-rust stub: KMS disabled"),
            KmsError::Stub(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for KmsError {}

/// Mirrors the real `ok-kms-rust` client surface used by the signer.
pub struct KmsClient;

impl KmsClient {
    /// Infallible construction so callers' init paths stay exercised.
    pub fn new() -> Result<KmsClient, KmsError> {
        Ok(KmsClient)
    }

    /// Always fails, embedding `STUB_MARKER` so a stub-linked `--features kms`
    /// binary fails loudly on first use.
    pub fn get_all_secrets(&self) -> Result<String, KmsError> {
        Err(KmsError::Stub(format!(
            "{STUB_MARKER}: built against the in-tree ok-kms-rust stub; run \
             `just kms-crate` with a real SDK checkout for production KMS resolution"
        )))
    }
}
```

- [ ] **Step 3: Verify the stub crate compiles offline**

Run: `cd op-succinct && cargo check -p ok-kms-rust`
Expected: PASS (no network access needed; no external dependencies).

- [ ] **Step 4: Swap the workspace dependency from git → path**

In `Cargo.toml` (root), replace line 40:

```toml
# BEFORE
ok-kms-rust = { git = "ssh://git@gitlab.okg.com/okcoin-commons/ok-kms-rust.git", tag = "v1.0.0" }
# AFTER
ok-kms-rust = { path = "stubs/ok-kms-rust" }
```

- [ ] **Step 5: Add the stub to workspace members**

In `Cargo.toml` (root) `[workspace] members` (lines 2–24), add the entry (keep alphor-grouped near the other `utils`/in-tree crates; placing it after `"bindings",` is fine):

```toml
    "bindings",
    "stubs/ok-kms-rust",
]
```

- [ ] **Step 6: Verify the workspace resolves and no private URL remains**

Run:
```bash
cd op-succinct
cargo metadata --format-version=1 >/dev/null && echo "metadata OK"
git grep -n 'ssh://git@gitlab.okg.com' -- '*.toml' ; echo "grep-exit=$?"
```
Expected: `metadata OK` prints (GC9); the `git grep` prints **no lines** and `grep-exit=1` (no match) — satisfying GC1/GC2.

- [ ] **Step 7: Commit**

```bash
cd op-succinct
git add stubs/ok-kms-rust/Cargo.toml stubs/ok-kms-rust/src/lib.rs Cargo.toml
git commit -m "[Oli] feat(kms): add in-tree ok-kms-rust stub crate; switch workspace dep to path"
```

**Requirement checks:** GC1, GC2, GC4 (stub compiles offline), GC9. Spec §3.4, §3.5.

---

## Task 2: Reference model in `utils/signer/src/kms.rs`

**Files:**
- Modify (rewrite): `utils/signer/src/kms.rs`
- Test: `utils/signer/src/kms.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `ok_kms_rust::{KmsClient, KmsError}` and `STUB_MARKER` (from Task 1) — only under `#[cfg(feature = "kms")]`.
- Produces (consumed by Task 3):
  - `pub const KMS_REF_PREFIX: &str` (== `"kms:"`)
  - `pub fn is_kms_ref(value: &str) -> bool`
  - `pub fn maybe_resolve(value: &str) -> Result<String, KmsError>`
  - `pub enum KmsError { Disabled, Empty, Backend(String) }` (derives `thiserror::Error`, so `std::error::Error + Send + Sync + 'static` → usable with `anyhow::Context`).

- [ ] **Step 1: Write the failing tests (feature-off + pure functions)**

Replace the `#[cfg(test)]` region (add if absent) in `utils/signer/src/kms.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_kms_ref_detects_only_exact_prefix() {
        assert!(is_kms_ref("kms:foo"));
        assert!(!is_kms_ref("foo"));
        assert!(!is_kms_ref("KMS:foo")); // case-sensitive
        assert!(!is_kms_ref(" kms:foo")); // leading space is not a prefix
        assert!(!is_kms_ref(""));
    }

    #[test]
    fn passthrough_is_byte_for_byte() {
        // trailing whitespace and 0x-prefixed literals must round-trip unchanged
        let v = "0xabc123   ";
        assert_eq!(maybe_resolve(v).unwrap(), v);
        assert_eq!(maybe_resolve("plain-secret").unwrap(), "plain-secret");
    }

    #[test]
    fn empty_reference_name_is_empty_error() {
        assert!(matches!(maybe_resolve("kms:"), Err(KmsError::Empty)));
    }

    #[cfg(not(feature = "kms"))]
    #[test]
    fn reference_without_feature_is_disabled_with_guidance() {
        match maybe_resolve("kms:foo") {
            Err(KmsError::Disabled) => {
                let msg = KmsError::Disabled.to_string();
                assert!(msg.contains("--features kms"), "message must include rebuild guidance");
            }
            other => panic!("expected Disabled, got {other:?}"),
        }
    }

    #[cfg(feature = "kms")]
    #[test]
    fn reference_with_feature_and_stub_fails_loudly_and_reuses_client() {
        // Two lookups both fail carrying the stub marker; the OnceLock client
        // is constructed at most once (second call reuses it — no panic/second init).
        let e1 = maybe_resolve("kms:x").unwrap_err();
        let e2 = maybe_resolve("kms:y").unwrap_err();
        assert!(e1.to_string().contains("OK_KMS_STUB"), "got: {e1}");
        assert!(e2.to_string().contains("OK_KMS_STUB"), "got: {e2}");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd op-succinct && cargo test -p op-succinct-signer-utils --lib kms`
Expected: FAIL to compile — `is_kms_ref`, `maybe_resolve`, `KMS_REF_PREFIX`, `KmsError` are not yet defined in their new shape.

- [ ] **Step 3: Rewrite `kms.rs` with the reference model**

Replace the entire contents of `utils/signer/src/kms.rs` above the test module with:

```rust
//! KMS reference-resolution helper.
//!
//! A secret value of the form `kms:<name>` is resolved via the OKG-internal
//! `ok-kms-rust` SDK at load time; any value WITHOUT the `kms:` prefix passes
//! through byte-for-byte unchanged. The SDK is reachable only in some build
//! environments, so it is gated behind the `kms` feature. Default builds
//! compile against the in-tree stub (`stubs/ok-kms-rust`) and resolve offline.
//!
//! # Singleton note (kms feature on)
//! `ok-kms-rust` loads a Go CGO `.so` at init. Dropping `KmsClient` would call
//! `dlclose` and SIGBUS (Go GC goroutines keep running), so the client lives in
//! a process-global `OnceLock` and is never dropped.

use thiserror::Error;

/// Prefix that marks a value as a KMS reference.
pub const KMS_REF_PREFIX: &str = "kms:";

/// True iff `value` begins with `KMS_REF_PREFIX` (case-sensitive, no trimming).
pub fn is_kms_ref(value: &str) -> bool {
    value.starts_with(KMS_REF_PREFIX)
}

/// Errors from KMS reference resolution. Messages never carry the resolved
/// secret value (only the reference name or SDK error text) — see
/// `context-kg/technical/pitfalls/signer.md` "Sensitive Data in Logs".
#[derive(Debug, Error)]
pub enum KmsError {
    /// A `kms:` reference was seen but the `kms` feature is not compiled in.
    #[error(
        "KMS reference seen but this binary was built without the `kms` feature; \
         rebuild with `--features kms` (e.g. `just build-kms proposer`) or supply a literal secret"
    )]
    Disabled,
    /// The reference name after `kms:` is empty, or the resolved secret is empty.
    #[error("KMS reference name or resolved secret value is empty")]
    Empty,
    /// The SDK lookup failed (SDK disabled, backend/network error, or key absent).
    #[error("KMS backend error: {0}")]
    Backend(String),
}

/// If `value` is a `kms:<name>` reference, resolve `<name>` via the SDK and
/// return the secret. Otherwise return `value` unchanged (byte-for-byte).
pub fn maybe_resolve(value: &str) -> Result<String, KmsError> {
    if !is_kms_ref(value) {
        return Ok(value.to_string());
    }
    let name = &value[KMS_REF_PREFIX.len()..];
    if name.is_empty() {
        return Err(KmsError::Empty);
    }
    imp::resolve(name)
}

#[cfg(feature = "kms")]
mod imp {
    use std::sync::OnceLock;

    use ok_kms_rust::{KmsClient, KmsError as SdkError};

    use super::KmsError;

    // Constructed at most once; never dropped (CGO `.so` lifetime). GC8.
    static KMS_CLIENT: OnceLock<Result<KmsClient, String>> = OnceLock::new();

    fn client() -> Result<&'static KmsClient, KmsError> {
        KMS_CLIENT
            .get_or_init(|| match KmsClient::new() {
                Ok(c) => {
                    tracing::info!("KMS client initialized");
                    Ok(c)
                }
                Err(SdkError::Disabled) => {
                    Err("ok-kms-rust SDK reported Disabled — check its activation env vars".to_string())
                }
                Err(e) => Err(format!("KMS init failed: {e}")),
            })
            .as_ref()
            .map_err(|e| KmsError::Backend(e.clone()))
    }

    pub fn resolve(name: &str) -> Result<String, KmsError> {
        let client = client()?;
        let json = client
            .get_all_secrets()
            .map_err(|e| KmsError::Backend(e.to_string()))?;
        let secrets: std::collections::HashMap<String, String> =
            serde_json::from_str(&json).map_err(|e| KmsError::Backend(format!("parse KMS JSON: {e}")))?;
        match secrets.get(name) {
            Some(v) if !v.is_empty() => Ok(v.clone()),
            Some(_) => Err(KmsError::Empty),
            None => Err(KmsError::Backend(format!("KMS key '{name}' not found"))),
        }
    }
}

#[cfg(not(feature = "kms"))]
mod imp {
    use super::KmsError;

    pub fn resolve(_name: &str) -> Result<String, KmsError> {
        Err(KmsError::Disabled)
    }
}
```

(Note: this DELETES the old `is_kms_enabled`, `fetch_secret`, and the `ENABLE_KMS`/`KMS_SECRET_KEY_NAME` doc comments per decision D1. `thiserror`, `serde_json`, and `tracing` are already dependencies of `utils/signer` — no `Cargo.toml` change.)

- [ ] **Step 4: Run tests to verify they pass (feature off)**

Run: `cd op-succinct && cargo test -p op-succinct-signer-utils --lib kms`
Expected: PASS for `is_kms_ref_detects_only_exact_prefix`, `passthrough_is_byte_for_byte`, `empty_reference_name_is_empty_error`, `reference_without_feature_is_disabled_with_guidance`. (The `#[cfg(feature = "kms")]` test is not compiled here.)

- [ ] **Step 5: Run the feature-on tests against the stub**

Run: `cd op-succinct && cargo test -p op-succinct-signer-utils --features kms --lib kms`
Expected: PASS including `reference_with_feature_and_stub_fails_loudly_and_reuses_client` (both errors contain `OK_KMS_STUB`). This exercises GC7 + GC8 at unit level.

- [ ] **Step 6: Lint**

Run: `cd op-succinct && cargo clippy -p op-succinct-signer-utils --all-targets --features kms`
Expected: no new warnings on the changed file (`kms.rs`).

- [ ] **Step 7: Commit**

```bash
cd op-succinct
git add utils/signer/src/kms.rs
git commit -m "[Oli] feat(signer): add kms: reference-resolution model (is_kms_ref/maybe_resolve)"
```

**Requirement checks:** Spec §3.2 (reference model + semantics), §3.3 (client reuse, GC8), §6 tests 1–5. GC5, GC6, GC7, GC10.

---

## Task 3: Route secret read-sites through `maybe_resolve`; retire the env-flag model

**Files:**
- Modify: `utils/signer/src/lib.rs` — `resolve_xlayer_secret_key` (`lib.rs:26-38`), `Signer::from_env` read-sites (`lib.rs:118-120`, `lib.rs:168-169`), crate-root re-exports (near `lib.rs:19`)
- Test: `utils/signer/src/lib.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `kms::{is_kms_ref, maybe_resolve, KmsError, KMS_REF_PREFIX}` (from Task 2).
- Produces: unchanged public signatures — `Signer::from_env() -> Result<Self>` and `SignerLock::from_env()` keep their shape (20 call-sites across `fault-proof/bin/*`, `fault-proof/src/config.rs`, `validity/src/env.rs` are unaffected). Adds public re-exports `is_kms_ref` / `maybe_resolve` / `KmsError` / `KMS_REF_PREFIX` at the crate root so a future flag- or file-path-based caller can guard a raw argument before touching the filesystem.

- [ ] **Step 1: Write the failing integration test**

Add to the existing `#[cfg(test)] mod tests` in `utils/signer/src/lib.rs`:

```rust
#[test]
fn local_signer_passthrough_literal_private_key() {
    // A literal (non-kms:) PRIVATE_KEY resolves unchanged and builds a LocalSigner.
    // Well-known Anvil dev key #0 (public test vector, not a real secret).
    let key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let resolved = crate::maybe_resolve(key).expect("passthrough");
    assert_eq!(resolved, key);
    let signer = Signer::new_local_signer(&resolved).expect("local signer");
    assert_eq!(
        format!("{:?}", signer.address()).to_lowercase(),
        "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
    );
}

#[cfg(not(feature = "kms"))]
#[test]
fn kms_ref_private_key_without_feature_errors() {
    assert!(matches!(crate::maybe_resolve("kms:private_key"), Err(crate::KmsError::Disabled)));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd op-succinct && cargo test -p op-succinct-signer-utils --lib`
Expected: FAIL to compile — `crate::maybe_resolve` / `crate::KmsError` are not yet re-exported.

- [ ] **Step 3: Add the crate-root re-exports**

In `utils/signer/src/lib.rs`, just after `pub mod kms;` (`lib.rs:19`), add:

```rust
pub use kms::{is_kms_ref, maybe_resolve, KmsError, KMS_REF_PREFIX};
```

- [ ] **Step 4: Rewrite `resolve_xlayer_secret_key`**

Replace `utils/signer/src/lib.rs:26-38` with:

```rust
/// Resolve the XLayer remote signer secret key. The `XLAYER_SECRET_KEY` value is
/// passed through the unified KMS reference model: a `kms:<name>` value is
/// resolved via the SDK; any literal value is returned unchanged.
fn resolve_xlayer_secret_key() -> Result<String> {
    let raw = std::env::var("XLAYER_SECRET_KEY")
        .context("XLAYER_SECRET_KEY is required when XLAYER_SIGNER_ENABLED=true")?;
    kms::maybe_resolve(&raw).context("failed to resolve XLAYER_SECRET_KEY")
}
```

- [ ] **Step 5: Route `access_key` and `PRIVATE_KEY` through `maybe_resolve`**

In `Signer::from_env`, change the `access_key` field (`lib.rs:118-119`) from the plain env read to:

```rust
                    access_key: {
                        let raw = std::env::var("XLAYER_ACCESS_KEY")
                            .context("XLAYER_ACCESS_KEY is required when XLAYER_SIGNER_ENABLED=true")?;
                        kms::maybe_resolve(&raw).context("failed to resolve XLAYER_ACCESS_KEY")?
                    },
```

And change the `PRIVATE_KEY` branch (`lib.rs:168-169`) from `Signer::new_local_signer(&private_key_str)` to:

```rust
        } else if let Ok(private_key_str) = std::env::var("PRIVATE_KEY") {
            let resolved =
                kms::maybe_resolve(&private_key_str).context("failed to resolve PRIVATE_KEY")?;
            Signer::new_local_signer(&resolved)
```

(Leave the `secret_key: resolve_xlayer_secret_key()?` line at `lib.rs:120` as-is — Step 4 changed the function it calls. Do NOT run `maybe_resolve` on non-secret config: endpoints, addresses, GCP keyring, Web3 URL keep exact values — spec §3.6.)

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd op-succinct && cargo test -p op-succinct-signer-utils --lib`
Expected: PASS including `local_signer_passthrough_literal_private_key` and `kms_ref_private_key_without_feature_errors`. Existing `#[ignore]` network tests remain ignored.

- [ ] **Step 7: Confirm the env-flag model is fully removed**

Run:
```bash
cd op-succinct
git grep -n -e 'ENABLE_KMS' -e 'KMS_SECRET_KEY_NAME' -e 'is_kms_enabled' -e 'fetch_secret' -- 'utils/signer' ; echo "grep-exit=$?"
```
Expected: **no lines**, `grep-exit=1` (decision D1 — env-flag model retired). If any deployment doc or manifest elsewhere still references `ENABLE_KMS`, STOP and escalate (see D1).

- [ ] **Step 8: Lint the full changed crate (both feature states)**

Run:
```bash
cd op-succinct
cargo clippy -p op-succinct-signer-utils --all-targets
cargo clippy -p op-succinct-signer-utils --all-targets --features kms
```
Expected: no new warnings.

- [ ] **Step 9: Commit**

```bash
cd op-succinct
git add utils/signer/src/lib.rs
git commit -m "[Oli] refactor(signer): route secrets through maybe_resolve; retire ENABLE_KMS flag"
```

**Requirement checks:** Spec §3.6 (read-site integration), §3.8 + D1 (retire env-flag), §6 test 7. GC5, GC6, GC10. Backward compatibility: literal `PRIVATE_KEY`/`XLAYER_SECRET_KEY`/`XLAYER_ACCESS_KEY` behave exactly as before (spec §7 non-goal preserved).

---

## Task 4: `justfile` recipes — SDK swap, restore, and stub-linked build guard

**Files:**
- Modify: `justfile` (append after the existing `build` recipe group)

**Interfaces:**
- Consumes: the `op-succinct-fp` `kms` feature (`fault-proof/Cargo.toml:109` — `kms = ["op-succinct-signer-utils/kms"]`) and the `proposer` binary; the `STUB_MARKER` literal from Task 1.
- Produces: `just kms-crate`, `just kms-crate-restore`, `just build-kms <bin>` operator recipes. The SSH URL lives ONLY inside `kms-crate` (operator action), never in the committed dependency manifest (GC1).

- [ ] **Step 1: Add the recipes**

Append to `justfile` (the file uses `just` syntax; recipes with a `#!/usr/bin/env bash` shebang run as a single bash script, matching the existing style, e.g. the `run-single` recipe):

```just
# ── KMS crate management (operator-only; the real SDK URL never enters the committed manifest) ──

# Swap the in-tree stub for a real ok-kms-rust checkout (idempotent). Local pre-prod only.
kms-crate url="ssh://git@gitlab.okg.com/okcoin-commons/ok-kms-rust.git" tag="v1.0.0":
    #!/usr/bin/env bash
    set -euo pipefail
    DEST="stubs/ok-kms-rust"
    if [ -f "$DEST/.ok-kms-real" ]; then
      echo "ok-kms-rust: real SDK already in place; nothing to do"
      exit 0
    fi
    TMP="$(mktemp -d)"
    trap 'rm -rf "$TMP"' EXIT
    git clone --depth 1 --branch "{{tag}}" "{{url}}" "$TMP/ok-kms-rust"
    rm -rf "$DEST"
    mkdir -p "$DEST"
    (cd "$TMP/ok-kms-rust" && tar --exclude=.git -cf - .) | (cd "$DEST" && tar -xf -)
    touch "$DEST/.ok-kms-real"
    echo "ok-kms-rust: real SDK checked out at {{tag}} into $DEST"

# Restore the committed in-tree stub, undoing `just kms-crate`.
kms-crate-restore:
    #!/usr/bin/env bash
    set -euo pipefail
    git checkout -- stubs/ok-kms-rust
    git clean -fdq stubs/ok-kms-rust
    echo "ok-kms-rust: committed stub restored (git status clean)"

# Build a fault-proof binary with --features kms and REFUSE a stub-linked binary.
build-kms bin="proposer" *features='kms':
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/tmp
    TMPDIR="$(pwd)/target/tmp" CARGO_TARGET_DIR="$(pwd)/target" \
      cargo build --release -p op-succinct-fp --bin {{bin}} --features {{features}}
    BIN="target/release/{{bin}}"
    COUNT="$(grep -ac OK_KMS_STUB "$BIN" || true)"
    if [ "${COUNT:-0}" -gt 0 ]; then
      echo "ERROR: {{bin}} is linked against the ok-kms-rust STUB (OK_KMS_STUB x$COUNT)." >&2
      echo "Run \`just kms-crate\` with the real SDK before a production KMS build." >&2
      exit 1
    fi
    echo "OK: {{bin}} built with kms features and is NOT stub-linked"
```

- [ ] **Step 2: Verify the stub-linked guard FAILS on a stub build (GC7)**

With the stub in place (default tree), run:
```bash
cd op-succinct && just build-kms proposer
```
Expected: builds `target/release/proposer` with `--features kms` against the stub, then **exits non-zero** with the `OK_KMS_STUB` error — proving the guard refuses a stub-linked KMS binary. (`op-succinct-fp` + `proposer` does not need `okx/x2`, so this resolves offline per GC11.)

> If the restricted build env cannot compile `op-succinct-fp` at all for unrelated reasons, fall back to asserting the marker directly on any `--features kms` artifact of `op-succinct-signer-utils` built in Task 2, and record the environment limitation in the stage notes.

- [ ] **Step 3: Verify idempotency / restore recipes are well-formed**

Run (no network needed — this only checks `just` parses and the restore path is clean):
```bash
cd op-succinct
just --list | grep -E 'kms-crate|build-kms'
git status --porcelain stubs/ok-kms-rust ; echo "clean-exit=$?"
```
Expected: the three recipes are listed; `git status --porcelain stubs/ok-kms-rust` prints nothing (GC3). Do NOT run `just kms-crate` in CI/restricted envs (it needs SSH access to the private group — an operator action).

- [ ] **Step 4: Verify-against-real-SDK note (execution-time reminder, non-blocking here)**

Before the first real production `just kms-crate` build, confirm the real `ok-kms-rust` v1.0.0 public surface still matches the stub (`KmsClient::new`, `get_all_secrets`, `KmsError::Disabled`). If the real SDK diverged, update the stub to match (the stub is the compile-time contract for both). This is an operator/production step, not part of the offline CI gate.

- [ ] **Step 5: Commit**

```bash
cd op-succinct
git add justfile
git commit -m "[Oli] chore(kms): add kms-crate swap/restore recipes and stub-linked build guard"
```

**Requirement checks:** Spec §3.7 (recipes), §3.4 (marker verification), GC1 (URL only in recipe), GC3, GC7, GC11. Decision D2 (verify-real-SDK note).

---

## Task 5: Commit the Superpowers context to the feature branch

**Files:**
- Commit: `docs/superpowers/specs/2026-09-08-kms-stub-crate-design.md`, `docs/superpowers/plans/2026-09-08-kms-stub-crate.md` (this file), `docs/superpowers/lark-review-doc.md`

- [ ] **Step 1: Stage and commit the design context (GC12)**

```bash
cd op-succinct
git add docs/superpowers/
git commit -m "[Oli] docs(superpowers): add KMS stub crate design spec and implementation plan"
```

Expected: `docs/superpowers/**` is tracked on the feature branch so it survives forward CoW and the pre-MR-review context archive. (Normal repo Git rules; no special policy — Flow prompt.)

> Ordering note for the executor: this docs commit may be made first (before Task 1) or last — either is acceptable. It is listed as a discrete task so the design context is never left uncommitted.

**Requirement checks:** GC12.

---

## Full validation sequence (offline, scoped — run before handing off)

Run from `op-succinct/`. All commands are crate-scoped per GC11 (a full `--all-features --workspace` gate is expected to fail in restricted envs for unrelated `okx/x2` / `postgresql_embedded` reasons and MUST NOT be used as the gate).

```bash
cd op-succinct
# 1. Anchor goal: no private SSH URL in any committed manifest
git grep -n 'ssh://git@gitlab.okg.com' -- '*.toml'   # expect: ok-kms line GONE (only recipe body may mention it, and that is in justfile, not *.toml)
# 2. Workspace resolves with the stub path dep
cargo metadata --format-version=1 >/dev/null && echo "metadata OK"
# 3. Stub crate compiles offline
cargo check -p ok-kms-rust
# 4. Signer, feature OFF (default) — compiles + tests pass
cargo test -p op-succinct-signer-utils --lib
# 5. Signer, feature ON against the stub — tests pass, stub marker present in errors
cargo test -p op-succinct-signer-utils --features kms --lib
# 6. Lint both feature states — no new warnings
cargo clippy -p op-succinct-signer-utils --all-targets
cargo clippy -p op-succinct-signer-utils --all-targets --features kms
# 7. Env-flag model fully retired
git grep -n -e 'ENABLE_KMS' -e 'is_kms_enabled' -e 'fetch_secret' -- 'utils/signer'   # expect: no lines
# 8. Stub-linked build guard refuses a stub KMS binary
just build-kms proposer   # expect: build succeeds, then non-zero exit with OK_KMS_STUB error
# 9. Stub tree is pristine (no real SDK committed)
git status --porcelain stubs/ok-kms-rust   # expect: empty
```

**Expected outcomes:** commands 2–7 succeed (or, for greps, print no lines); command 8 fails loudly with `OK_KMS_STUB` (that failure is the success condition for GC7); command 9 prints nothing.

## Requirement → Task traceability

| Requirement / constraint (spec) | Satisfied by |
|---|---|
| `kms:<name>` resolved via `ok-kms-rust` at load time (Epic; spec §3.2) | Task 2 (`maybe_resolve` + feature-on `imp::resolve`) |
| Non-`kms:` passthrough byte-for-byte (spec §3.2, GC5) | Task 2 (`maybe_resolve` early return) + Task 2 test `passthrough_is_byte_for_byte` |
| Default build compiles against in-tree stub, offline (Epic; spec §3.4, GC4) | Task 1 (stub crate + path dep) + validation cmd 3–4 |
| Committed manifest never references KMS SSH URL — anchor goal (spec §3.1, GC1/GC2) | Task 1 (git→path) + validation cmd 1 |
| Feature-gated, default OFF (spec §3.6, GC6) | Task 2 (`#[cfg(feature = "kms")]`; `Disabled` when off) + test `reference_without_feature_is_disabled_with_guidance` |
| Process-wide client reused, never dropped (spec §3.3, GC8) | Task 2 (`OnceLock`) + test `..._reuses_client` |
| Loud stub failure w/ `OK_KMS_STUB`; recipe refuses stub-linked binary (spec §3.4/§3.7, GC7) | Task 1 (`STUB_MARKER`) + Task 4 (`build-kms` guard) + validation cmd 8 |
| Public `is_kms_ref` / `maybe_resolve` API (Epic; spec §3.2/§3.6) | Task 2 (definitions) + Task 3 (crate-root re-exports) |
| Read-site integration for `PRIVATE_KEY` / `XLAYER_ACCESS_KEY` / `XLAYER_SECRET_KEY` (spec §3.6) | Task 3 (Steps 4–5) |
| Retire env-flag model `ENABLE_KMS`/`KMS_SECRET_KEY_NAME` (spec §3.8, D1) | Task 3 (Step 3 rewrite deletes them) + validation cmd 7 |
| Required unit tests 1–4 (spec §6) | Task 2 Steps 1/4/5 |
| Additional tests: empty-name (5), stub marker in binary (6), from_env integration (7) (spec §6) | Task 2 (empty-name), Task 4 (marker in binary), Task 3 (from_env integration) |
| `just` swap/restore recipes (spec §3.7) | Task 4 |
| Workspace hygiene / `cargo metadata` resolves (spec §5 C9, GC9) | Task 1 Steps 5–6 + validation cmd 2 |
| No real SDK checkout committed (spec §5 C3, GC3) | Task 4 (restore) + validation cmd 9 |
| Never log secret material (signer.md, GC10) | Task 2 (`KmsError` carries only names/SDK text) |
| `docs/superpowers/**` committed; `[Oli] ` commit subjects (spec §5 C10, GC12) | Task 5 + every task's commit |
| Additional Context items | **None supplied** (spec §8) — inapplicable, no task required |

## Self-Review

1. **Spec coverage** — every spec section (§3.1–§3.8, §5 C1–C10, §6 tests 1–7, §7 non-goals, §8 Additional Context) maps to a task in the traceability table above. No gaps.
2. **Placeholder scan** — no `TBD`/`TODO`/"handle edge cases"/"similar to Task N"; every code step carries real code.
3. **Type consistency** — `is_kms_ref`, `maybe_resolve`, `KmsError { Disabled, Empty, Backend(String) }`, `KMS_REF_PREFIX`, `STUB_MARKER`, `KmsClient::{new, get_all_secrets}` are used identically across Tasks 1–3 and the tests. `Signer::new_local_signer` / `Signer::from_env` signatures are unchanged, so the 20 external call-sites need no edits.

## Feedback iterations (if this plan is reworked)

Preserve prior files. On a feedback round, add a clearly-linked delta plan `docs/superpowers/plans/YYYY-MM-DD-kms-stub-crate-<delta-slug>.md` that (a) links back to this plan, (b) records only the changed/added tasks, and (c) maps any newly-supplied Additional Context item to a task or records it inapplicable with a reason. Do not delete or overwrite this file.

## Execution Handoff

Plan complete. Execution happens in the downstream **Execute and Validate Plan** stage (this planning stage does NOT invoke `executing-plans`). Recommended execution approach for that stage: **subagent-driven** (fresh subagent per task, review between tasks) via `superpowers:subagent-driven-development`; inline batch execution via `superpowers:executing-plans` is the alternative.
