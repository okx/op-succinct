# Design Spec — KMS stub crate: remove the private `ok-kms-rust` SSH dependency (minimal-diff)

- **Jira:** [XLOP-1197](https://okcoin.atlassian.net/browse/XLOP-1197) (Epic, `technical-epic`)
- **Repository:** `op-succinct` (`gitlab.okg.com/github/op-succinct.git`)
- **Feature branch (reuse):** `xl/xlop-1197/0908-0931` → **target/base branch:** `xl/tz-dev`
- **MR (reuse):** [#104](https://gitlab.okg.com/github/op-succinct/-/merge_requests/104) — base SHA `972c86d0f8bb70ddb758a61860911db6f6334b7e`, current SHA `462bb0b3626e215736b32bf243a10b70866e08ea`
- **Lark Review Document:** https://okg-block.sg.larksuite.com/docx/Gy87dovrroicCrx2JwjlbXl1gNf (record: `docs/superpowers/lark-review-doc.md`)
- **Status:** APPROVED — 2026-09-09 (Oli Stage 1.0, attempt 2; creator approved via AskUserQuestion after Lark review)
- **Revision:** round 2 (rework), 2026-09-09 — supersedes the round-1 APPROVED design after creator CHANGES_REQUESTED

> **Delivery gate (Oli):** This stage produces the design Spec only. No implementation is
> performed here. On this rework round the existing branch and MR are **reused** — no new branch
> and no new MR are created.

---

## 0. What changed in this revision (round 2) — and why

Round 1 was approved, implemented on `xl/xlop-1197/0908-0931`, and reached human MR review, where
the creator requested changes. **Verbatim creator feedback (highest-priority input this round):**

> I realized in utils/signer/src/kms.rs, a lot of existing functions has been refactored but their
> core logic is the same. You should not refactor if there is no significant changes to their
> logic. The most important thing is to stub the kms dependency of referencing the ssh url in
> Cargo.toml

The round-1 design authorized a scope expansion — a new *reference model* (`is_kms_ref`,
`maybe_resolve`, `KmsError{Disabled,Empty,Backend}`), rerouting three read sites in
`Signer::from_env()`, and **retiring** the env-flag model (`ENABLE_KMS` / `KMS_SECRET_KEY_NAME`,
`is_kms_enabled` / `fetch_secret`). That rewrite is exactly what refactored functions in
`utils/signer/src/kms.rs` whose **core logic was unchanged**. This revision **removes that
expansion** and narrows the design to the smallest change set that satisfies the anchor goal.

**Kept from round 1** (creator-approved direction): the in-tree **path dependency** to a new
`stubs/ok-kms-rust` workspace member, the `just kms-crate` swap approach (swap directory
*contents*, never the manifest), and the Git treatment (`docs/superpowers/**` committed; every Oli
commit subject / MR title begins exactly `[Oli] `).

**Removed / reverted from round 1:**
- ❌ the reference-model API in `utils/signer` (`is_kms_ref`, `maybe_resolve`, `KMS_REF_PREFIX`, and the new `utils/signer` `KmsError{Disabled,Empty,Backend}` type);
- ❌ retirement of `ENABLE_KMS` / `KMS_SECRET_KEY_NAME` / `is_kms_enabled` / `fetch_secret`;
- ❌ rerouting `PRIVATE_KEY` / `XLAYER_SECRET_KEY` / `XLAYER_ACCESS_KEY` read sites through a new resolver;
- ❌ the `OK_KMS_STUB` marker and the `--features kms` build-verify recipe (creator chose the bare-minimum stub this round — see §7).

**New creator decisions this round** (via AskUserQuestion, 2026-09-09):
- **Bare-minimum stub** — the stub compiles and fails at runtime with a plain error; no `OK_KMS_STUB` marker and no build-verify recipe.
- **Clone-from-SSH swap** — `just kms-crate` clones the real SDK from its SSH URL at the pinned tag; the SSH URL is confined to the justfile recipe body and never appears in any `*.toml`.

---

## 1. Objective and anchor goal

Make `op-succinct` build **out of the box for every contributor and CI job** — `cargo
check / clippy / test` must succeed with **no `gitlab.okg.com` private-group SSH access** — while
still allowing a production build to link the real OKG-internal `ok-kms-rust` KMS SDK.

### The anchor goal (creator, unchanged from round 1)

> **The committed workspace `Cargo.toml` must never reference the KMS SSH URL.**

Everything below serves that anchor. It is satisfied by declaring `ok-kms-rust` as an in-tree
**path** dependency (`stubs/ok-kms-rust`) that is always present in the tree; a `just` recipe swaps
the *contents* of that directory (stub ↔ real SDK checkout) for a production build — the committed
manifest is never edited.

**This round adds a second, equally hard goal derived from the feedback:** the change must be a
**minimal diff**. In particular `utils/signer/src/kms.rs` must be preserved unchanged wherever its
core logic is unchanged (target: **zero** changes to that file). See §5 — Minimal-Diff Constraint.

---

## 2. Background — current state in the repository (grounded)

Findings grounded via the codegraph index (81,319 nodes / 246,260 edges · op-succinct) at base SHA
`972c86d` (the on-disk checkout), plus the repo's `context-kg/technical` KG docs.

### 2.1 The problem, in the manifest

`Cargo.toml` (workspace root), `[workspace.dependencies]`:

```toml
ok-kms-rust = { git = "ssh://git@gitlab.okg.com/okcoin-commons/ok-kms-rust.git", tag = "v1.0.0" }
```

A **git dependency on a private GitLab group over SSH**. Even though `utils/signer` marks it
`optional = true` behind a `kms` feature, **Cargo resolves the entire workspace dependency graph
before building anything** (repo pitfall `context-kg/technical/pitfalls/dependencies.md`). So any
environment lacking an SSH deploy key for that private repo — CI, external contributors, and this
Oli pipeline env (whose git-token rewrite covers HTTPS `gitlab.okg.com`, not SSH) — fails
`cargo check/clippy/test`, **feature flags notwithstanding**. This is exactly the breakage the Epic
removes, and the sole anchor-goal target.

### 2.2 The existing KMS module — its core logic must be PRESERVED

`utils/signer/src/kms.rs` (85 lines, 5 symbols; sole consumer `utils/signer/src/lib.rs`) implements
an **env-flag** model. Read verbatim at base SHA:

- `pub fn is_kms_enabled() -> bool` — `true` when `ENABLE_KMS == "true"` (case-insensitive). References no SDK symbol.
- `pub use imp::fetch_secret;`
- `#[cfg(feature = "kms")] mod imp` — `use ok_kms_rust::{KmsClient, KmsError};`, a process-global
  `static KMS_CLIENT: OnceLock<Result<KmsClient, String>>` constructed at most once via
  `KmsClient::new()` and **never dropped** (the SDK loads a Go CGO `.so`; dropping would `dlclose`
  and SIGBUS), `init_kms_client()` matching `Err(KmsError::Disabled)` specially, and `fetch_secret`
  calling `client.get_all_secrets()` → `serde_json` into `HashMap<String,String>` → `key_name` lookup.
- `#[cfg(not(feature = "kms"))] mod imp` — `fetch_secret` returns `anyhow::bail!` with rebuild guidance.
- Env vars: `ENABLE_KMS`, `KMS_SECRET_KEY_NAME`.

**The exact `ok-kms-rust` surface this file references** — and therefore the *only* surface the
stub must provide so the file compiles unchanged:

| Symbol referenced by unchanged `kms.rs` | Required stub shape |
|---|---|
| `ok_kms_rust::KmsClient` | `pub struct KmsClient` |
| `ok_kms_rust::KmsError` | `pub enum KmsError` implementing `Debug + Display + std::error::Error` (Display used via `format!("{e}")`; `Error` required because `get_all_secrets()`'s result is passed to `anyhow::Context::context`) |
| `KmsError::Disabled` | a `Disabled` variant (named in an `init_kms_client` match arm) |
| `KmsClient::new() -> Result<KmsClient, KmsError>` | associated fn with this exact signature |
| `KmsClient::get_all_secrets(&self) -> Result<String, KmsError>` | method returning `Result<String, _>` where `_: std::error::Error + Send + Sync + 'static` |

### 2.3 The only consumer — also needs NO change

- `resolve_xlayer_secret_key()` (`utils/signer/src/lib.rs:28-38`) is the single caller of both
  `is_kms_enabled` and `fetch_secret`. Core logic: if `is_kms_enabled()` → read
  `KMS_SECRET_KEY_NAME` and `kms::fetch_secret(&key_name)`; else read `XLAYER_SECRET_KEY` from env.
  It references **no** `ok-kms-rust` symbol directly.
- All signer secrets are read from **environment variables** inside `Signer::from_env()`
  (`PRIVATE_KEY`, `XLAYER_SECRET_KEY`, `XLAYER_ACCESS_KEY`, plus non-secret config). `from_env` has
  6 callers across `fault-proof/bin/{proposer,challenger,tz_proposer,tz_challenger}.rs`. No binary
  takes a `--private-key` CLI flag; no binary reads a secret from a file path.

Because neither `resolve_xlayer_secret_key()` nor `Signer::from_env()` names an `ok-kms-rust`
symbol, **swapping the git dependency for a path dependency does not require changing either of
them.**

### 2.4 Workspace facts that constrain the change

- Root `members` = 19 explicit + globs `programs/range/*`, `scripts/*`; `exclude = ["scripts/ci-env"]`;
  `resolver = "2"`. Adding a member requires updating `members` **and** the `[workspace.dependencies]`
  line (KG pitfall "Workspace Member Drift").
- No `stubs/` directory exists yet.
- Root `[patch.crates-io]` pins all `sp1-*` / `slop-*` crates to the okx gateway-proxy fork
  (KG "sp1 Patch Chain") — **must not be touched**. `ok-kms-rust` is a direct dep, never patched, so
  no `[patch]` entry is involved.
- A full `--all-features` workspace gate can fail in a restricted env for **unrelated** reasons
  (private `okx/x2` github SSH deps under `programs/tz/range`; `postgresql_embedded` download in
  `validity`). Scope gates to the changed crates; the KMS change fixes the **KMS** path only.

---

## 3. Proposed design (minimal-diff)

Three coordinated pieces, all additive or single-line except the one manifest edit that IS the
anchor goal:

1. **root `Cargo.toml`** — repoint the `ok-kms-rust` workspace dependency from the SSH git URL to
   the in-tree path, and register the new member.
2. **`stubs/ok-kms-rust`** — a NEW crate mirroring exactly the SDK surface in §2.2, that constructs
   and **fails every lookup at runtime with a plain error** (bare-minimum; no marker).
3. **`justfile`** — `kms-crate` (clone the real SDK from SSH into the path) and `kms-crate-restore`
   (restore the committed stub). No build-verify recipe (creator: bare-minimum).

```
                       committed manifest (never edited after this one line)
root Cargo.toml:  ok-kms-rust = { path = "stubs/ok-kms-rust" }   ── optional, activated by `kms`
                                     │
              ┌──────────────────────┴───────────────────────┐
       default (stub in place)                     `just kms-crate` (operator, pre-prod)
   stubs/ok-kms-rust = STUB code            stubs/ok-kms-rust dir contents = REAL SDK checkout
   (KmsClient::new OK; get_all_secrets       (cloned from ssh://…/ok-kms-rust.git @ v1.0.0)
    fails at runtime, plain error)           `just kms-crate-restore` puts the committed stub back
```

### 3.1 Root `Cargo.toml` (the ONLY existing-file edit that IS the anchor goal)

- `[workspace.dependencies]`: replace the git line with
  `ok-kms-rust = { path = "stubs/ok-kms-rust" }`.
- `[workspace] members`: add `"stubs/ok-kms-rust"`.
- No other change; `[patch.crates-io]` untouched.

### 3.2 `utils/signer` — UNCHANGED

- `utils/signer/Cargo.toml` stays exactly `ok-kms-rust = { workspace = true, optional = true }` and
  `kms = ["dep:ok-kms-rust"]`. Because it inherits via `workspace = true`, repointing the root
  dependency from git to path requires **no edit** to the signer manifest.
- `utils/signer/src/kms.rs` — **byte-for-byte unchanged** (its core logic is unchanged; the stub is
  shaped to match the surface it already uses).
- `utils/signer/src/lib.rs` — `resolve_xlayer_secret_key()` and `Signer::from_env()` **unchanged**.
- The env-flag model (`ENABLE_KMS`, `KMS_SECRET_KEY_NAME`, `is_kms_enabled`, `fetch_secret`) is
  **preserved with its existing semantics** — NOT retired.

### 3.3 The stub crate `stubs/ok-kms-rust` (new files only)

A minimal crate whose public API is exactly §2.2 and nothing more:

```rust
use std::fmt;

#[derive(Debug)]
pub enum KmsError {
    /// Named by an `init_kms_client` match arm in utils/signer/src/kms.rs; kept for source compat.
    Disabled,
    /// Carries the plain stub failure message returned by get_all_secrets().
    Backend(String),
}

impl fmt::Display for KmsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KmsError::Disabled => write!(f, "ok-kms-rust stub: KMS disabled"),
            KmsError::Backend(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for KmsError {}

pub struct KmsClient {}

impl KmsClient {
    /// Constructs successfully so the existing OnceLock init path stays exercised.
    pub fn new() -> Result<KmsClient, KmsError> { Ok(KmsClient {}) }

    /// Bare-minimum stub: always fails at runtime with a plain error directing the operator to
    /// run `just kms-crate` for a real build. (No grep-able marker; creator chose bare-minimum.)
    pub fn get_all_secrets(&self) -> Result<String, KmsError> {
        Err(KmsError::Backend(
            "ok-kms-rust stub in use — run `just kms-crate` to link the real SDK for a KMS build"
                .to_string(),
        ))
    }
}
```

- The stub has **no dependency** on any private group; it is plain safe Rust and resolves offline.
- Crate `name`/`version` match `ok-kms-rust` v1.0.0 so the path dependency substitutes cleanly.
- The exact variant set of `KmsError` is an implementation detail bounded by §2.2: it must expose
  `Disabled` and whatever variant `get_all_secrets()` returns; nothing beyond what unchanged
  `kms.rs` needs to compile.

> **Verify-against-real-SDK checklist (for the implementation stage):** before the first
> `just kms-crate` production build, confirm the real `ok-kms-rust` v1.0.0 surface still matches the
> stub (`KmsClient::new`, `get_all_secrets`, `KmsError::Disabled`). If the real SDK diverges, update
> the stub to match — the stub is the compile-time contract for both.

### 3.4 `justfile` recipes (new recipes only)

- `kms-crate` — swap in the real SDK: clone
  `ssh://git@gitlab.okg.com/okcoin-commons/ok-kms-rust.git` at tag `v1.0.0` into
  `stubs/ok-kms-rust` (idempotent: re-running detects an already-real checkout and no-ops). The SSH
  URL lives **only** here, in a recipe body an operator runs — never in a committed `*.toml`.
- `kms-crate-restore` — restore the committed in-tree stub (`git checkout -- stubs/ok-kms-rust` and
  `git clean` the untracked real checkout), undoing `kms-crate`.
- **No** build-verify recipe (bare-minimum stub; creator decision).

---

## 4. Alternatives considered (and why the minimal path wins this round)

| # | Alternative | Verdict |
|---|-------------|---------|
| A (**chosen**) | **Minimal:** swap git dep → path dep, add the stub sized to the *existing* `kms.rs` surface, add `just` swap recipes; leave `kms.rs` / `lib.rs` / signer manifest and the env-flag model untouched. | **Chosen.** Satisfies the anchor goal with the smallest diff and honors the creator's minimal-diff feedback. |
| B | **Reference-model rewrite** (round-1 design): add `is_kms_ref`/`maybe_resolve`/`KmsError{Empty,Backend}`, reroute three read sites, retire the env-flag model. | **Rejected this round.** Refactors functions whose core logic is unchanged — the exact thing the creator asked us not to do. |
| C | **New dedicated `utils/kms` crate** for a resolver. | Rejected: adds workspace members and consumers for a resolver that this round does not introduce at all. |
| D | **`[patch]` the git dep to a path** instead of editing the dependency line. | Rejected: the base declaration would still be the SSH git URL in the committed manifest — violates the anchor goal. |
| E | **Stub method `get_value_by_key(name)`** per the Epic text. | Rejected: unchanged `kms.rs` uses `get_all_secrets()`; the stub must mirror what the real code compiles against, not an unverified signature. |
| F | **Keep the git dep, document an SSH key requirement.** | Rejected: does not fix the offline-build breakage; contradicts the anchor goal. |

---

## 5. Minimal-Diff Constraint (normative — governs the implementation stage)

**Judgment rule.** For any existing function or item in `utils/signer/src/kms.rs` (and more broadly
in `utils/signer`), if its **core logic is unchanged** by swapping the git dependency for the path
dependency, then it **must not** be modified: do not change its signature, do not rename it, do not
split it, do not reorder it, do not reformat it. A change to such a function is permitted **only**
if the revised Spec can state, hunk-by-hunk, why that exact change is *required* to get the
committed `Cargo.toml` off the SSH URL. Any change that cannot be so justified is out of scope and
must be reverted to the base-SHA original.

**File / symbol whitelist for this round** (the *only* things allowed to change):

| Path | Allowed change | Justification (why required for the anchor goal) |
|---|---|---|
| `Cargo.toml` (workspace root) | Repoint `ok-kms-rust` dep git→`{ path = "stubs/ok-kms-rust" }`; add `"stubs/ok-kms-rust"` to `members`. | This single edit **is** the anchor goal; the member entry is required for Cargo to resolve the path dep. |
| `stubs/ok-kms-rust/**` | New crate: `Cargo.toml` + `src/lib.rs` per §3.3. | The path dep needs a real target that resolves offline and provides the surface unchanged `kms.rs` references. |
| `justfile` | Add `kms-crate` and `kms-crate-restore` recipes per §3.4. | Operational swap to the real SDK; keeps the SSH URL out of every committed `*.toml`. |
| `docs/superpowers/**` | This Spec + downstream plan; committed to the branch. | Cumulative design record; Oli flow requirement. |

**Explicitly UNCHANGED (must equal base SHA `972c86d` byte-for-byte):**
`utils/signer/src/kms.rs` · `utils/signer/src/lib.rs` (incl. `resolve_xlayer_secret_key`,
`Signer::from_env`) · `utils/signer/Cargo.toml` · the env-flag model
(`ENABLE_KMS` / `KMS_SECRET_KEY_NAME` / `is_kms_enabled` / `fetch_secret`) · root `[patch.crates-io]`.
No new reference-model API (`is_kms_ref` / `maybe_resolve` / `KMS_REF_PREFIX`, or a new `KmsError`
type inside `utils/signer`) is introduced. The stub crate's own `KmsError` (§3.3) is a separate type
that mirrors the real `ok-kms-rust` SDK error and is unrelated to the removed reference model.

**Machine-executable gate for stage 3.0 (implementation):** produce
`git diff 972c86d0f8bb70ddb758a61860911db6f6334b7e -- utils/signer/src/kms.rs`. The expected result
is **empty**. If it is non-empty, review it hunk-by-hunk against the judgment rule above; revert any
hunk that is not required by the anchor goal to the base-SHA original.

---

## 6. Constraints and invariants

- **C1 — No private URL in any committed `*.toml`.** `git grep 'ssh://git@gitlab.okg.com' -- '*.toml'`
  finds nothing after the change. (Anchor goal.)
- **C2 — No git dependency on the private group** anywhere in `[workspace.dependencies]` for KMS.
- **C3 — No real SDK checkout committed.** `stubs/ok-kms-rust` in Git contains only the stub; the
  real checkout exists only transiently after `just kms-crate` and is git-ignored / restored.
- **C4 — Offline default build.** `cargo check`, `cargo clippy`, and `cargo test` for the signer
  crate succeed with **no network and no private-GitLab access** (stub in place). Pre-existing
  unrelated private deps (`okx/x2`, `postgresql_embedded`) are out of scope; gates are scoped to the
  changed crates per repo convention.
- **C5 — `kms.rs` unchanged.** `git diff <base> -- utils/signer/src/kms.rs` is empty (target), or
  contains only hunks individually justified as required by the anchor goal. (Minimal-Diff Constraint.)
- **C6 — Env-flag behavior preserved.** `ENABLE_KMS` / `KMS_SECRET_KEY_NAME` and `is_kms_enabled` /
  `fetch_secret` keep their existing semantics and signatures.
- **C7 — Feature default OFF.** `kms` is in no default feature set; the default build never compiles
  the SDK path and never names an `ok_kms_rust` type.
- **C8 — Feature ON compiles against the stub.** `cargo check -p op-succinct-signer-utils --features kms`
  succeeds against the in-tree stub with no private access.
- **C9 — Client reuse preserved.** The existing process-wide `OnceLock` client is constructed at
  most once and never dropped (unchanged behavior).
- **C10 — Workspace hygiene.** `members` updated for `stubs/ok-kms-rust`; `cargo metadata
  --format-version=1` resolves; no accidental workspace-membership churn elsewhere.
- **C11 — Commit hygiene.** `docs/superpowers/**` committed to `xl/xlop-1197/0908-0931`; every Oli
  commit subject and MR title begins exactly `[Oli] `. Tool artifacts (`op-succinct/.codegraph/`,
  `op-succinct/.oli-codegraph/`, `tmp/`) are **not** committed.

---

## 7. Testing strategy (scoped to the minimal change)

Because `utils/signer/src/kms.rs` is unchanged, **no new unit tests for a reference model are
introduced**, and all existing signer tests must keep passing unchanged. The verification this round
targets is the build/resolution behavior:

1. **Offline resolution (anchor goal).** With the stub in place, `cargo metadata` and
   `cargo check -p op-succinct-signer-utils` succeed with no SSH access to `gitlab.okg.com`.
2. **Feature ON against the stub.** `cargo check -p op-succinct-signer-utils --features kms`
   compiles against `stubs/ok-kms-rust` (proves the stub surface matches unchanged `kms.rs`).
3. **Feature OFF unchanged.** `cargo test -p op-succinct-signer-utils` (no `--features kms`) passes
   exactly as at base SHA.
4. **Anchor-goal grep.** `git grep 'ssh://git@gitlab.okg.com' -- '*.toml'` returns nothing.
5. **kms.rs diff gate.** `git diff <base> -- utils/signer/src/kms.rs` is empty (or every hunk is
   individually justified per §5).

Gate scoping (restricted-env aware): use crate-scoped commands (`-p op-succinct-signer-utils`, with
and without `--features kms`) rather than a full `--all-features` workspace build that would trip on
unrelated private deps.

---

## 8. Non-goals

- **No refactor of unchanged functions.** No signature, name, split, or reorder change to any
  `utils/signer/src/kms.rs` item whose core logic is unchanged. (Primary creator directive.)
- **No reference model.** No `is_kms_ref` / `maybe_resolve` / `KMS_REF_PREFIX` and no rerouting of
  `PRIVATE_KEY` / `XLAYER_SECRET_KEY` / `XLAYER_ACCESS_KEY` read sites.
- **No retirement** of `ENABLE_KMS` / `KMS_SECRET_KEY_NAME` / `is_kms_enabled` / `fetch_secret`.
- No new secret *sources*; no change to GCP / Web3 signer config.
- No stub marker / build-verify recipe (bare-minimum stub).
- No real SDK checkout committed; no `[patch.crates-io]` change.
- Not fixing unrelated private-dependency build breakage (`okx/x2`, `postgresql_embedded`).
- No new branch and no new MR — reuse `xl/xlop-1197/0908-0931` and MR #104.

---

## 9. Additional Context

**None supplied.** This task carried no Additional Context (the Oli `external_inputs` channel is
empty and the Jira Epic has no linked PRD or remote content); this rework round does **not**
introduce or relax any Additional Context. The only new input this round is the creator's MR-review
feedback quoted verbatim in §0, which this Spec has fully materialized (minimal-diff scope,
`kms.rs` preserved, env-flag model retained, reference model removed). Should Additional Context be
supplied in a later revision, it will be recorded verbatim here with its resolved design implications.

---

## 10. Downstream notes

- **Stage 2.0 (plan):** regenerate `docs/superpowers/plans/2026-09-08-kms-stub-crate.md` from THIS
  revised Spec. The restored plan reflects the round-1 (rejected) reference-model scope and must be
  rewritten to the minimal-diff scope above before implementation.
- **Stage 3.0 (implementation):** continue on `xl/xlop-1197/0908-0931`; apply the §5 whitelist and
  run the §5 machine-executable gate so the eventual MR shows "anchor goal met + `kms.rs` diff
  empty".
- **Stage 5.0 (MR):** update the description of the existing MR #104; do not open a new MR.
