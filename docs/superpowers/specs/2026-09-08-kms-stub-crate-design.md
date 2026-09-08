# Design Spec — KMS stub crate: feature-gated `ok-kms-rust` secret resolution

- **Jira:** [XLOP-1197](https://okcoin.atlassian.net/browse/XLOP-1197) (Epic, `technical-epic`)
- **Repository:** `op-succinct` (`gitlab.okg.com/github/op-succinct.git`)
- **Target / base branch:** `xl/tz-dev`
- **Lark Review Document:** https://okg-block.sg.larksuite.com/docx/Gy87dovrroicCrx2JwjlbXl1gNf (record: `docs/superpowers/lark-review-doc.md`)
- **Status:** APPROVED — 2026-09-08 (Oli Stage 1.0; creator approved via AskUserQuestion after Lark review)
- **Revision:** initial round, 2026-09-08

> **Delivery gate (Oli):** This stage produces the design Spec only. No implementation,
> branch, or MR is created before this Spec is approved.

---

## 1. Objective

Make `op-succinct` build **out of the box for every contributor and CI job** while still
allowing production builds to resolve secrets through the OKG-internal `ok-kms-rust` KMS SDK.

Concretely: a secret input whose value is a **`kms:<name>` reference** is resolved at load
time via `ok-kms-rust`; any value **without** the `kms:` prefix passes through
**byte-for-byte unchanged**. Default builds compile against an **in-tree stub** of the SDK, so
nobody needs `gitlab.okg.com` private-group access to run `cargo check / clippy / test`.

### The anchor goal (decided with reviewer)

> **The committed workspace `Cargo.toml` must never reference the KMS SSH URL directly.**

Everything below serves that anchor. It is satisfied by declaring `ok-kms-rust` as an in-tree
**path** dependency (`stubs/ok-kms-rust`) that is always present in the tree; a `just` recipe
swaps the *contents* of that directory (stub ↔ real SDK checkout) for a production build — the
committed manifest is never edited.

---

## 2. Background — current state in the repository (grounded)

The repo already contains a **narrower, different** KMS integration that this Epic supersedes.
Findings below are grounded via the codegraph index (81,319 nodes / 246,260 edges) and the
repo's own `context-kg/technical` docs.

### 2.1 The problem, in the manifest

`Cargo.toml` (workspace root), `[workspace.dependencies]`:

```toml
ok-kms-rust = { git = "ssh://git@gitlab.okg.com/okcoin-commons/ok-kms-rust.git", tag = "v1.0.0" }
```

This is a **git dependency on a private GitLab group over SSH**. Even though downstream
consumers mark it `optional = true` and gate it behind a `kms` feature, **Cargo resolves the
entire workspace dependency graph before building anything** (confirmed by
`context-kg/technical/pitfalls/dependencies.md` — "Whole-Workspace Resolution Blocked by
Private … Dep"). So any environment lacking an SSH deploy key for that private repo —
CI, external contributors, and this Oli pipeline env (whose git-token rewrite covers HTTPS
`gitlab.okg.com`, not SSH) — fails `cargo check/clippy/test`, **feature flags
notwithstanding**. This is exactly the breakage the Epic removes.

### 2.2 The existing KMS module (env-flag model)

`utils/signer/src/kms.rs` (85 lines) implements an **env-flag** model:

- `is_kms_enabled()` → `true` when `ENABLE_KMS == "true"` (case-insensitive).
- `fetch_secret(key_name)` — behind `#[cfg(feature = "kms")] mod imp`, uses
  `ok_kms_rust::{KmsClient, KmsError}`, stores a process-global
  `OnceLock<Result<KmsClient, String>>` that is **constructed at most once and never dropped**
  (the SDK loads a Go CGO `.so`; dropping the client would `dlclose` and SIGBUS), then calls
  `client.get_all_secrets()` → parses JSON `HashMap<String,String>` → looks up `key_name`.
- `#[cfg(not(feature = "kms"))] mod imp` returns an `anyhow::bail!` with rebuild guidance.
- Env vars: `ENABLE_KMS`, `KMS_SECRET_KEY_NAME`.

`utils/signer/Cargo.toml`:

```toml
ok-kms-rust = { workspace = true, optional = true }
[features]
kms = ["dep:ok-kms-rust"]
```

**Proven real-SDK surface** (what the repo already compiles against, so it *must* exist in
`ok-kms-rust` v1.0.0): `KmsClient::new() -> Result<KmsClient, KmsError>`,
`KmsClient::get_all_secrets() -> Result<String, _>`, and `KmsError::Disabled`.

### 2.3 The only consumer, and where secrets are read

- `resolve_xlayer_secret_key()` (`utils/signer/src/lib.rs`) is the single caller: if
  `kms::is_kms_enabled()` it fetches `KMS_SECRET_KEY_NAME` via `kms::fetch_secret`, else reads
  `XLAYER_SECRET_KEY` from env. Used **only** for the XLayer `secret_key`.
- All signer secrets are read from **environment variables** inside
  `Signer::from_env()` (`utils/signer/src/lib.rs:82-179`), priority order:
  1. `XLAYER_SIGNER_ENABLED=true` → XLayer (`XLAYER_SIGNER_ENDPOINT`, `XLAYER_SIGNER_ADDRESS`,
     `XLAYER_ACCESS_KEY`, `XLAYER_SECRET_KEY`);
  2. `GOOGLE_PROJECT_ID`+`GOOGLE_LOCATION`+`GOOGLE_KEYRING` → GCP Cloud HSM (non-secret config);
  3. `SIGNER_URL`+`SIGNER_ADDRESS` → Web3Signer (non-secret config);
  4. `PRIVATE_KEY` → LocalSigner;
  5. else error.
  `SignerLock::from_env()` wraps it; **6 callers** across
  `fault-proof/bin/{proposer,challenger,tz_proposer,tz_challenger}.rs`.
- **No fault-proof binary takes a `--private-key` CLI flag** and **no binary reads a secret
  from a file path**. The only `--private-key` args in the tree are test/deploy helpers that
  invoke `forge`/`cast` (`fault-proof/tests/common/*.rs`, `justfile`). The **secret inputs are
  env-based**: `PRIVATE_KEY`, `XLAYER_SECRET_KEY`, `XLAYER_ACCESS_KEY`.

### 2.4 Workspace facts that constrain the change

- Root `members` = 19 explicit + globs `programs/range/*`, `scripts/*`; `exclude =
  ["scripts/ci-env"]`; `resolver = "2"`. Adding a member requires updating `members` **and**
  `[workspace.dependencies]` (`context-kg/.../pitfalls/dependencies.md` — "Workspace Member Drift").
- No `stubs/` directory exists yet.
- Feature conventions (`context-kg/.../conventions/feature-types.md`): optional deps activated
  via `dep:` form; features kept orthogonal; the default build must incur no penalty.
- A full `--all-features` workspace gate can fail in a restricted env for **unrelated** reasons
  (private `okx/x2` github SSH deps under `programs/tz/range`; `postgresql_embedded` download in
  `validity`). Scope gates to the changed crates. The KMS change must make the **KMS** path
  itself resolvable offline; it does not fix those unrelated deps.

---

## 3. Proposed design

### 3.1 Component overview

Three coordinated pieces:

1. **`stubs/ok-kms-rust`** — a new in-tree crate that mirrors the *proven* public surface of the
   real SDK, constructs successfully, and **fails every lookup** with an embedded marker.
2. **`utils/signer`** — evolved to expose the reference model (`is_kms_ref`, `maybe_resolve`,
   `KmsError`) and to route all secret reads through it. (Chosen over a brand-new crate because
   the signer is today's only secret consumer; keeps workspace wiring minimal and reuses the
   existing `kms` feature + `OnceLock`.)
3. **`justfile`** — recipes to swap the stub for a real SDK checkout for production builds and to
   verify a KMS build is not stub-linked.

```
                       committed manifest (never edited)
root Cargo.toml:  ok-kms-rust = { path = "stubs/ok-kms-rust" }   ── optional, activated by `kms`
                                     │
              ┌──────────────────────┴───────────────────────┐
       default (stub in place)                     `just kms-crate` (local, pre-prod)
   stubs/ok-kms-rust = STUB code            stubs/ok-kms-rust dir contents = REAL SDK checkout
   (KmsClient::new OK, lookups fail          (real ok-kms-rust source; produces a working client)
    w/ OK_KMS_STUB marker)                   `just kms-crate-restore` puts the stub back
```

### 3.2 The reference model (in `utils/signer`)

Public API (module, e.g. `utils/signer/src/kms.rs`, re-exported from the crate root):

```rust
/// Prefix that marks a value as a KMS reference.
pub const KMS_REF_PREFIX: &str = "kms:";

/// True iff `value` begins with `KMS_REF_PREFIX`.
pub fn is_kms_ref(value: &str) -> bool;

/// If `value` is a `kms:<name>` reference, resolve `<name>` via the SDK and return the secret.
/// Otherwise return `value` unchanged (byte-for-byte, including surrounding whitespace).
pub fn maybe_resolve(value: &str) -> Result<String, KmsError>;

#[derive(Debug, thiserror::Error)]
pub enum KmsError {
    /// `kms:` reference seen but the `kms` feature is not compiled in. Message includes
    /// rebuild guidance (e.g. `rebuild with --features kms`).
    #[error(...)] Disabled,
    /// The reference name after `kms:` is empty, or the resolved secret value is empty.
    #[error(...)] Empty,
    /// The SDK lookup failed (SDK reported disabled, network/backend error, or key absent).
    #[error(...)] Backend(String),
}
```

Semantics:

- **Passthrough:** `is_kms_ref(v) == false` ⇒ `maybe_resolve(v)` returns `v` cloned, unchanged.
  No trimming, no normalization. This preserves current behavior for literal secrets and
  plaintext secret files exactly.
- **Reference, feature OFF:** `is_kms_ref(v) == true` and `kms` feature not enabled ⇒
  `Err(KmsError::Disabled)` with rebuild guidance. The SDK is never referenced.
- **Reference, feature ON:** parse `<name>` from `kms:<name>`; empty `<name>` ⇒
  `Err(KmsError::Empty)`. Otherwise fetch via the process-wide client (see §3.3), select
  `<name>` from `get_all_secrets()`; missing key / SDK error ⇒ `Err(KmsError::Backend(..))`;
  empty resolved value ⇒ `Err(KmsError::Empty)`.

The single function that touches `ok_kms_rust` is `#[cfg(feature = "kms")]`-gated; the
non-`kms` build never names the SDK type, so it compiles regardless of stub-vs-real.

### 3.3 Process-wide client

Keep the existing pattern: a `static OnceLock<Result<KmsClient, String>>` constructed at most
once via `KmsClient::new()` and **never dropped** (CGO `.so` lifetime). `maybe_resolve` reuses
this client across all lookups. This directly satisfies the acceptance criterion "the
process-wide client is reused across lookups."

### 3.4 The stub crate `stubs/ok-kms-rust`

A minimal crate whose **public API mirrors exactly what `utils/signer` compiles against**:

```rust
pub const STUB_MARKER: &str = "OK_KMS_STUB";

#[derive(Debug)] // + std::error::Error / Display
pub enum KmsError { Disabled, /* … same variants the real SDK exposes that we reference … */ }

pub struct KmsClient { /* trivial */ }

impl KmsClient {
    /// Infallible: constructs successfully so callers' init paths stay exercised.
    pub fn new() -> Result<KmsClient, KmsError> { Ok(KmsClient { .. }) }

    /// Always fails, embedding STUB_MARKER in the error text so a binary accidentally built
    /// `--features kms` against the stub fails loudly on first use instead of silently
    /// authenticating with a bogus credential.
    pub fn get_all_secrets(&self) -> Result<String, KmsError> {
        Err(KmsError::Backend(format!("{STUB_MARKER}: built against the ok-kms-rust stub; \
             run `just kms-crate` with a real SDK checkout for production")))
    }
}
```

- The literal `OK_KMS_STUB` lands in the compiled binary's read-only data, so
  `grep -ac OK_KMS_STUB <binary>` returns > 0 for stub-linked builds and 0 for real-SDK builds.
- The stub has **no dependency** on any private group; it is plain safe Rust and resolves
  offline.
- Crate name/version match `ok-kms-rust` so the path dependency substitutes cleanly.

> **Verify-against-real-SDK checklist (for the implementation stage):** before the first
> `just kms-crate` production build, confirm the real `ok-kms-rust` v1.0.0 public surface still
> matches the stub (`KmsClient::new`, `get_all_secrets`, `KmsError` variants referenced). If the
> real SDK diverges, update the stub to match; the stub is the compile-time contract for both.

### 3.5 Manifest changes

- Root `Cargo.toml`:
  - `[workspace.dependencies] ok-kms-rust = { path = "stubs/ok-kms-rust" }` (replaces the git line).
  - Add `stubs/ok-kms-rust` to `[workspace] members`.
- `utils/signer/Cargo.toml`: unchanged in shape — still
  `ok-kms-rust = { workspace = true, optional = true }` and `kms = ["dep:ok-kms-rust"]`.
- No `[patch.crates-io]` entry is needed (it was never patched; it's a direct dep).

### 3.6 Binary / read-site integration

Apply `maybe_resolve()` **at each secret read site** inside `Signer::from_env()` (decided):

- `PRIVATE_KEY` → `Signer::new_local_signer(&maybe_resolve(&private_key_str)?)`.
- XLayer: `access_key: maybe_resolve(&env("XLAYER_ACCESS_KEY")?)?`, and
  `resolve_xlayer_secret_key()` becomes `maybe_resolve(&env("XLAYER_SECRET_KEY")?)` — routing the
  XLayer secret through the unified model.
- Non-secret config (endpoints, addresses, GCP keyring, Web3 URL) is **not** run through
  `maybe_resolve` (they are not secrets and must keep exact values).

Because non-`kms:` values pass through unchanged, every existing deployment that supplies a
literal `PRIVATE_KEY` / `XLAYER_SECRET_KEY` / `XLAYER_ACCESS_KEY` behaves **exactly as before**.

`is_kms_ref` / `maybe_resolve` are exported publicly so a future flag- or file-path-based caller
can guard a raw argument with `is_kms_ref` *before* touching the filesystem (per the Epic), even
though no such caller exists in op-succinct today.

### 3.7 `justfile` recipes

- `kms-crate` — **idempotent** swap: replace `stubs/ok-kms-rust` contents with a real
  `ok-kms-rust` checkout (e.g. clone the SSH repo at the pinned tag into the path, or copy a
  provided checkout). Idempotent = re-running detects an already-real checkout and no-ops.
- `kms-crate-restore` — restore the committed in-tree stub (e.g. `git checkout -- stubs/ok-kms-rust`
  / `git clean`), undoing `kms-crate`.
- A `--features kms` production build recipe that, after building, **verifies the stub marker is
  absent** from the produced binary (`grep -ac OK_KMS_STUB <binary>` must be 0) and **fails**
  otherwise — so a KMS build can never ship still linked against the stub.

The SSH URL for the real SDK lives **only** inside the `kms-crate` recipe body (an operator
action), never in the committed dependency manifest — satisfying the anchor goal.

### 3.8 Retiring the env-flag model

`resolve_xlayer_secret_key()` is rewritten to use `maybe_resolve(env("XLAYER_SECRET_KEY"))`, so
`ENABLE_KMS` / `KMS_SECRET_KEY_NAME` and `is_kms_enabled()` / `fetch_secret()` are **retired**
in favor of the reference model (a `kms:<name>` value in `XLAYER_SECRET_KEY` now triggers
resolution). This is an intentional behavior change to an internal, unreleased mechanism.
_Open confirmation for reviewers:_ if any deployed environment already sets
`ENABLE_KMS=true`, we will instead keep a thin deprecated shim that maps it onto the reference
model for one release. Absent such a deployment, the flags are removed outright.

---

## 4. Alternatives considered (and why rejected)

| # | Alternative | Why rejected |
|---|-------------|--------------|
| A | **Coexist:** add the reference crate + stub but leave `kms.rs` env-flag model untouched. | Two parallel KMS mechanisms (`ENABLE_KMS` flag *and* `kms:` reference) is confusing and doubles the test/maintenance surface. Reviewer's anchor goal is the dependency fix; unifying is cleaner. |
| B | **Minimal:** only swap the git dep → stub path dep; keep env-flag API, skip the reference model. | Diverges from the Epic scope (`is_kms_ref`/`maybe_resolve`, broad secret coverage). Leaves the narrow XLAYER-only integration. |
| C | **New dedicated crate** `utils/kms` for the reference model (signer depends on it). | Matches "dedicated crate" wording most literally but adds two new workspace members and wiring for a consumer set that is, today, just the signer. Chosen to **extend `utils/signer`** instead. |
| D | **`[patch]` the git dep to a path** instead of changing the dependency line. | The base declaration would still be the SSH git URL in the committed manifest — violates the anchor goal. |
| E | **`get_value_by_key(name)`** stub method per the Epic text. | The repo provably uses `get_all_secrets()`; `get_value_by_key` is **not** proven to exist in the real SDK. Referencing an unverified signature risks a stub that won't compile against the real crate. Chose the proven `get_all_secrets()` surface (reviewer-approved). |
| F | **Process-wide env pre-pass** in each `main()` (mutate global env for an allowlist). | Broader but mutates global process state and is less explicit than resolving exactly the secret values at their read sites. Read-site resolution chosen. |

---

## 5. Constraints and invariants

- **C1 — No private URL in the committed manifest.** `git grep 'ssh://git@gitlab.okg.com'
  Cargo.toml` finds nothing after the change. (Anchor goal.)
- **C2 — No git dependency on the private group anywhere** in `[workspace.dependencies]` for KMS.
- **C3 — No real SDK checkout committed.** `stubs/ok-kms-rust` in Git contains only the stub;
  the real checkout exists only transiently after `just kms-crate` and is git-ignored / restored.
- **C4 — Offline default build.** `cargo check`, `cargo clippy --workspace --all-features`, and
  `cargo test` succeed with **no network and no private-GitLab access** for the *KMS* path (stub
  in place). Pre-existing unrelated private deps (`okx/x2`, `postgresql_embedded`) are out of
  scope; gates are scoped to changed crates per repo convention.
- **C5 — Byte-for-byte passthrough.** Non-`kms:` values (including surrounding whitespace)
  round-trip unchanged through `maybe_resolve`.
- **C6 — Feature default OFF.** `kms` is not in any default feature set; a `kms:` reference
  without the feature yields `Disabled` + rebuild guidance and never touches the SDK.
- **C7 — Loud stub failure.** With `--features kms` + stub, every lookup fails carrying
  `OK_KMS_STUB`; the KMS build recipe refuses a stub-linked binary.
- **C8 — Client reuse.** The process-wide client is constructed at most once and never dropped.
- **C9 — Workspace hygiene.** `members` updated for `stubs/ok-kms-rust`; `cargo metadata
  --format-version=1` resolves; no accidental workspace-membership churn elsewhere.
- **C10 — Commit hygiene.** `docs/superpowers/**` committed to the feature branch; every Oli
  commit subject and MR title begins exactly `[Oli] `.

---

## 6. Testing strategy

Unit tests (the Epic's required four, in `utils/signer`):

1. **Prefix detection** — `is_kms_ref("kms:foo") == true`; `is_kms_ref("foo")`,
   `is_kms_ref("KMS:foo")`, `is_kms_ref(" kms:foo")`, `is_kms_ref("")` all `false`.
2. **Literal passthrough** — `maybe_resolve("0xabc… ")` returns the input unchanged including
   trailing whitespace; a plaintext value with no prefix is identical in and out.
3. **Disabled without feature** — `#[cfg(not(feature = "kms"))]`: `maybe_resolve("kms:foo")` is
   `Err(KmsError::Disabled)` and the message contains rebuild guidance.
4. **Client reuse with feature + stub** — `#[cfg(feature = "kms")]`: two `maybe_resolve("kms:x")`
   calls both fail with an error containing `OK_KMS_STUB`, and the `OnceLock` client is
   initialized exactly once (observable via the single init path / no second construction).

Additional coverage:

5. **Empty-name / empty-value** — `maybe_resolve("kms:")` ⇒ `KmsError::Empty`.
6. **Stub marker present in binary** — build a `--features kms` binary against the stub and assert
   `grep -ac OK_KMS_STUB` > 0 (build-recipe / integration check); assert the production recipe
   *rejects* it.
7. **`Signer::from_env` integration** — a literal `PRIVATE_KEY` still yields a `LocalSigner`
   with the same address (behavior unchanged); a `kms:` `PRIVATE_KEY` without the feature errors
   with `Disabled`.

Gate scoping (restricted-env aware): validate with crate-scoped commands
(`cargo test -p op-succinct-signer-utils`, with and without `--features kms`) rather than a full
`--all-features` workspace build that would trip on unrelated private deps.

---

## 7. Non-goals

- No change to non-KMS deployments — literal secrets and plaintext secret files behave exactly
  as before.
- No git dependency on the private GitLab group anywhere in the workspace manifest.
- No real SDK checkout committed to the repository.
- No new secret *sources* beyond the existing signer inputs; no change to GCP/Web3 signer config.
- Not fixing unrelated private-dependency build breakage (`okx/x2`, `postgresql_embedded`).
- No implementation in this stage (design Spec only, per the Oli delivery gate).

---

## 8. Additional Context

**None supplied.** This task carried no Additional Context (the Oli `external_inputs` channel was
empty and the Jira ticket has no linked PRD or remote content). All requirements above derive
from the Jira Epic XLOP-1197 and grounded repository facts. If Additional Context is supplied in
a later revision, it will be recorded verbatim here together with its resolved design
implications.

---

## 9. Open items for reviewer confirmation

1. **§3.8 env-flag retirement** — remove `ENABLE_KMS`/`KMS_SECRET_KEY_NAME` outright, or keep a
   one-release deprecated shim? (Default: remove, unless a live deployment uses the flag.)
2. **§3.4 SDK surface** — confirmed `get_all_secrets()` is the resolution call; the implementer
   will re-verify the real SDK surface before the first `kms-crate` swap.
3. **§3.7 `kms-crate` source** — the recipe clones the real SDK from its SSH URL at the pinned
   tag into `stubs/ok-kms-rust`; confirm operators have SSH access at production build time.
