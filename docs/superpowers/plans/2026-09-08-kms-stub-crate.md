# KMS Stub Crate — remove the private `ok-kms-rust` SSH dependency (minimal-diff) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Do not run `executing-plans` from this (planning) stage** — this document is the deliverable of the "Write Implementation Plan" stage; execution happens in the downstream "Execute and Validate Plan" stage.

> **⚠ Round 2 (rework) — this plan REPLACES the round-1 reference-model plan.** The round-1 design was approved, implemented, and rejected at MR review: the creator asked us **not to refactor `utils/signer` functions whose core logic is unchanged**. This plan is regenerated from the round-2 **minimal-diff** Spec (same file path, per Spec §10). The round-1 scope (reference model `is_kms_ref`/`maybe_resolve`, retiring the env-flag model, `OK_KMS_STUB` marker, build-verify recipe) is **removed**. Verbatim creator feedback that governs this round:
> > I realized in utils/signer/src/kms.rs, a lot of existing functions has been refactored but their core logic is the same. You should not refactor if there is no significant changes to their logic. The most important thing is to stub the kms dependency of referencing the ssh url in Cargo.toml

**Goal:** Make `op-succinct` build offline for every contributor/CI job by repointing the `ok-kms-rust` workspace dependency from a private SSH git URL to an in-tree `stubs/ok-kms-rust` path crate — with the **smallest possible diff** and **zero changes** to `utils/signer/src/kms.rs`, `utils/signer/src/lib.rs`, and the env-flag model.

**Architecture:** One manifest edit (git→path + add member) IS the anchor goal. A new dependency-free stub crate mirrors *exactly* the `ok-kms-rust` surface that the unchanged `kms.rs` already compiles against (`KmsClient::new`, `get_all_secrets`, `KmsError::Disabled`) and fails every lookup at runtime with a plain error. A `just` recipe swaps the directory *contents* (stub ↔ real SDK cloned from SSH) for production; the SSH URL lives only in the recipe body, never in a committed `*.toml`.

**Tech Stack:** Rust (edition 2021, workspace `resolver = "2"`), Cargo workspace path dependency, plain safe Rust stub (no external deps), `just` task runner.

**Spec:** `docs/superpowers/specs/2026-09-08-kms-stub-crate-design.md` (Status: **APPROVED** 2026-09-09, Oli Stage 1.0 attempt 2; creator approved via AskUserQuestion after Lark review — round 2, minimal-diff, supersedes round-1). Lark review doc: <https://okg-block.sg.larksuite.com/docx/Gy87dovrroicCrx2JwjlbXl1gNf> (recorded in `docs/superpowers/lark-review-doc.md`).

**Jira:** [XLOP-1197](https://okcoin.atlassian.net/browse/XLOP-1197) (Epic, `technical-epic`).

**Repository / branch:** `op-succinct` (`gitlab.okg.com/github/op-succinct.git`). This is a **rework round**: reuse feature branch **`xl/xlop-1197/0908-0931`** and existing **MR #104**; target/base branch **`xl/tz-dev`**. No new branch, no new MR. Diff-gate base SHA: `972c86d0f8bb70ddb758a61860911db6f6334b7e` (the on-disk checkout; verified `git rev-parse HEAD` == this).

## Global Constraints

Every task's requirements implicitly include this section. Values copied verbatim from Spec §5/§6 and grounded against the current tree at base SHA `972c86d`.

- **GC1 — No private URL in any committed `*.toml`.** After the change, `git grep 'ssh://git@gitlab.okg.com' -- '*.toml'` MUST find nothing. (Anchor goal; today it matches `Cargo.toml:40`.)
- **GC2 — No git dependency on the private group** anywhere in `[workspace.dependencies]` for KMS.
- **GC3 — No real SDK checkout committed.** `stubs/ok-kms-rust` in Git contains only the stub; the real checkout exists only transiently after `just kms-crate` and is reverted by `just kms-crate-restore`. `git status --porcelain stubs/ok-kms-rust` MUST be empty before any commit.
- **GC4 — Offline default build.** `cargo check`/`cargo clippy`/`cargo test` for the signer crate succeed with no network and no private-GitLab access (stub in place).
- **GC5 — `utils/signer/src/kms.rs` UNCHANGED.** `git diff 972c86d0f8bb70ddb758a61860911db6f6334b7e -- utils/signer/src/kms.rs` MUST be **empty**. (Primary creator directive; Spec §5 machine-executable gate.)
- **GC6 — Env-flag behavior preserved.** `ENABLE_KMS` / `KMS_SECRET_KEY_NAME` and `is_kms_enabled` / `fetch_secret` keep their existing semantics and signatures. **No reference model** (`is_kms_ref` / `maybe_resolve` / `KMS_REF_PREFIX`) is introduced; no read-site rerouting.
- **GC7 — Feature default OFF.** `kms` is in no default feature set; the default build never compiles the SDK path and never names an `ok_kms_rust` type.
- **GC8 — Feature ON compiles against the stub.** `cargo check -p op-succinct-signer-utils --features kms` succeeds against the in-tree stub with no private access.
- **GC9 — Client reuse preserved.** The existing process-wide `OnceLock` client (in `kms.rs`) is constructed at most once and never dropped — unchanged behavior (a consequence of GC5).
- **GC10 — Workspace hygiene.** `members` updated for `stubs/ok-kms-rust`; `cargo metadata --format-version=1` resolves; no accidental workspace-membership churn elsewhere; root `[patch.crates-io]` untouched.
- **GC11 — Scoped gates (restricted-env aware).** Validate with crate-scoped commands (`-p op-succinct-signer-utils`, with/without `--features kms`; `-p ok-kms-rust`). Do NOT run a full `--all-features --workspace` gate: it fails in restricted envs for unrelated reasons — `programs/tz/range` needs private `okx/x2` github SSH deps and `validity` downloads `postgresql_embedded` (Spec §2.4 / `context-kg/technical/pitfalls/dependencies.md`). Those are out of scope.
- **GC12 — Commit hygiene.** `docs/superpowers/**` is committed to `xl/xlop-1197/0908-0931`; every Oli commit subject / MR title begins **exactly** `[Oli] ` (trailing space). Tool artifacts (`op-succinct/.codegraph/`, `op-succinct/.oli-codegraph/`, `tmp/`) are NOT committed.

## Minimal-Diff Constraint (normative — Spec §5)

**Judgment rule.** For any existing item in `utils/signer` (especially `kms.rs`), if its core logic is unchanged by swapping the git dependency for the path dependency, it **must not** be modified — no signature/rename/split/reorder/reformat. A change is permitted only if it is *required* to get the committed `Cargo.toml` off the SSH URL, justified hunk-by-hunk.

**Whitelist — the ONLY paths allowed to change this round:**

| Path | Allowed change |
|---|---|
| `Cargo.toml` (workspace root) | Repoint `ok-kms-rust` dep git→`{ path = "stubs/ok-kms-rust" }`; add `"stubs/ok-kms-rust"` to `members`. |
| `stubs/ok-kms-rust/**` | New crate: `Cargo.toml` + `src/lib.rs` (+ a stub-local `.gitignore` hardening C3). |
| `justfile` | Add `kms-crate` and `kms-crate-restore` recipes. |
| `docs/superpowers/**` | This plan + the Spec; committed to the branch. |

**Explicitly UNCHANGED (must equal base SHA `972c86d` byte-for-byte):** `utils/signer/src/kms.rs` · `utils/signer/src/lib.rs` (incl. `resolve_xlayer_secret_key`, `Signer::from_env`) · `utils/signer/Cargo.toml` · the env-flag model · root `[patch.crates-io]` · root `.gitignore`.

## Additional Context

**None supplied** (Spec §9; the Oli `external_inputs` channel is empty and the Jira Epic has no linked PRD/remote content). This rework round introduces/relaxes no Additional Context. Recorded as **inapplicable — reason: not supplied for this task**. The only new input this round is the creator's MR-review feedback (quoted in the Round-2 banner above), which the Spec materialized as the minimal-diff scope and which this plan implements. If a future feedback round supplies Additional Context, add a clearly-linked delta plan mapping each item to a task or recording it inapplicable with a reason.

## File Structure (created / modified)

| File | Action | Responsibility |
|---|---|---|
| `stubs/ok-kms-rust/Cargo.toml` | Create | Stub crate manifest; package name `ok-kms-rust`, version `1.0.0`, dependency-free, offline-resolvable. |
| `stubs/ok-kms-rust/src/lib.rs` | Create | Stub SDK mirroring exactly Spec §2.2: `KmsError { Disabled, Backend(String) }` (`Debug`+`Display`+`Error`), `KmsClient::new() -> Result<KmsClient, KmsError>` (Ok), `get_all_secrets(&self) -> Result<String, KmsError>` (plain-error failure — no marker). |
| `stubs/ok-kms-rust/.gitignore` | Create | Ignore the transient real-SDK swap marker so it is never committed (C3 hardening; within the §5 whitelist). |
| `Cargo.toml` (workspace root) | Modify | `Cargo.toml:40` git→path; add `stubs/ok-kms-rust` to `[workspace] members` (lines 2–24). ONLY existing-file edit. |
| `justfile` | Modify | Append `kms-crate` (clone real SDK from SSH into the path, idempotent) and `kms-crate-restore` (restore committed stub). No build-verify recipe. |
| `utils/signer/**` | **NO CHANGE** | `kms.rs`, `lib.rs`, `Cargo.toml` remain byte-for-byte at base SHA (GC5/GC6). The stub is shaped to the surface `kms.rs` already uses, so the signer inherits the path dep via `workspace = true` with no edit. |
| `docs/superpowers/**` | Commit | Spec + this plan committed to `xl/xlop-1197/0908-0931` (GC12). |

---

## Task 1: Create the in-tree stub crate `stubs/ok-kms-rust`

**Files:**
- Create: `stubs/ok-kms-rust/Cargo.toml`
- Create: `stubs/ok-kms-rust/src/lib.rs`
- Create: `stubs/ok-kms-rust/.gitignore`

**Interfaces:**
- Consumes: nothing (dependency-free).
- Produces (the compile-time contract the UNCHANGED `utils/signer/src/kms.rs` already references — Spec §2.2):
  - `ok_kms_rust::KmsClient` with `pub fn new() -> Result<KmsClient, KmsError>` and `pub fn get_all_secrets(&self) -> Result<String, KmsError>`
  - `ok_kms_rust::KmsError` — enum implementing `Debug + Display + std::error::Error`, with at least the variant `Disabled` (named in a `kms.rs` match arm) and one variant carrying the runtime failure string.

- [ ] **Step 1: Create the stub crate manifest**

Create `stubs/ok-kms-rust/Cargo.toml`:

```toml
[package]
name = "ok-kms-rust"
version = "1.0.0"
edition = "2021"
license = "MIT"
description = "In-tree stub of the OKG-internal ok-kms-rust SDK. Compiles offline with no private-group access; every secret lookup fails at runtime with a plain error. Swap for the real SDK via `just kms-crate` for production builds."

[dependencies]
```

(No dependencies — plain safe Rust so it resolves with no network / no private-GitLab access. `version = "1.0.0"` mirrors the real SDK tag; the workspace dep line carries no version constraint, so a path dep substitutes cleanly.)

- [ ] **Step 2: Write the stub crate source (mirrors Spec §2.2/§3.3 exactly — no marker)**

Create `stubs/ok-kms-rust/src/lib.rs`:

```rust
//! In-tree stub of the OKG-internal `ok-kms-rust` SDK.
//!
//! Mirrors exactly the public surface that `op-succinct-signer-utils`
//! (`utils/signer/src/kms.rs`) compiles against, so a workspace path
//! dependency substitutes for the real SDK without touching the committed
//! manifest. `KmsClient::new` succeeds so the existing `OnceLock` init path
//! stays exercised; every secret lookup fails at runtime with a plain error
//! directing the operator to `just kms-crate`. Bare-minimum: no grep marker.

use std::fmt;

#[derive(Debug)]
pub enum KmsError {
    /// Named by an `init_kms_client` match arm in utils/signer/src/kms.rs; kept for source compat.
    Disabled,
    /// Carries the plain stub failure message returned by `get_all_secrets`.
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
    pub fn new() -> Result<KmsClient, KmsError> {
        Ok(KmsClient {})
    }

    /// Bare-minimum stub: always fails at runtime with a plain error directing the
    /// operator to run `just kms-crate` for a real build. (No grep-able marker.)
    pub fn get_all_secrets(&self) -> Result<String, KmsError> {
        Err(KmsError::Backend(
            "ok-kms-rust stub in use — run `just kms-crate` to link the real SDK for a KMS build"
                .to_string(),
        ))
    }
}
```

(This surface is exactly what the UNCHANGED `kms.rs` references: `KmsClient::{new, get_all_secrets}`, `KmsError::Disabled`, and `KmsError: Display + Error`. Do NOT add any other public item — Spec §3.3 "nothing more".)

- [ ] **Step 3: Add the stub-local gitignore (C3 hardening)**

Create `stubs/ok-kms-rust/.gitignore`:

```gitignore
# Transient marker written by `just kms-crate` when the real SDK is swapped in.
# Never commit it (nor any real-SDK checkout); `just kms-crate-restore` reverts the swap.
/.ok-kms-real
```

- [ ] **Step 4: Verify the stub crate compiles offline**

Run: `cd op-succinct && cargo check -p ok-kms-rust`
Expected: PASS (no network access needed; no external dependencies). If `-p ok-kms-rust` is not yet resolvable because the workspace member is not registered, this passes only after Task 2; in that case run this verification as part of Task 2 Step 3.

- [ ] **Step 5: Commit**

```bash
cd op-succinct
git add stubs/ok-kms-rust/Cargo.toml stubs/ok-kms-rust/src/lib.rs stubs/ok-kms-rust/.gitignore
git commit -m "[Oli] feat(kms): add in-tree ok-kms-rust stub crate (offline, bare-minimum)"
```

**Requirement checks:** Spec §3.3 (stub shape), §2.2 (surface parity), GC3 (marker ignored), GC4 (offline). No marker / no build-verify (Spec §0, §8 — bare-minimum).

---

## Task 2: Repoint the workspace dependency git → path and register the member

**Files:**
- Modify: `Cargo.toml` (root) — `[workspace.dependencies] ok-kms-rust` (line 40) and `[workspace] members` (lines 2–24)

**Interfaces:**
- Consumes: the stub crate from Task 1 (`stubs/ok-kms-rust`, package `ok-kms-rust`).
- Produces: the workspace now resolves `ok-kms-rust` from the in-tree path; `utils/signer` (which uses `ok-kms-rust = { workspace = true, optional = true }`) inherits the path dep with NO manifest edit.

- [ ] **Step 1: Swap the workspace dependency from git → path**

In `Cargo.toml` (root), replace line 40:

```toml
# BEFORE (Cargo.toml:40)
ok-kms-rust = { git = "ssh://git@gitlab.okg.com/okcoin-commons/ok-kms-rust.git", tag = "v1.0.0" }
# AFTER
ok-kms-rust = { path = "stubs/ok-kms-rust" }
```

- [ ] **Step 2: Register the stub as a workspace member**

In `Cargo.toml` (root) `[workspace] members` (the list at lines 2–24), add the entry after `"bindings",`:

```toml
    "bindings",
    "stubs/ok-kms-rust",
]
```

(Do NOT touch `exclude`, `resolver`, or `[patch.crates-io]` — GC10.)

- [ ] **Step 3: Verify the workspace resolves and the stub builds offline**

Run:
```bash
cd op-succinct
cargo metadata --format-version=1 >/dev/null && echo "metadata OK"
cargo check -p ok-kms-rust && echo "stub check OK"
```
Expected: `metadata OK` and `stub check OK` (GC10, GC4). No SSH/network access needed.

- [ ] **Step 4: Verify no private SSH URL remains in any committed manifest**

Run:
```bash
cd op-succinct
git grep -n 'ssh://git@gitlab.okg.com' -- '*.toml' ; echo "grep-exit=$?"
```
Expected: **no lines**, `grep-exit=1` (no match) — GC1/GC2 satisfied. (The URL now exists only in the `justfile` recipe added in Task 3, which is not a `*.toml`.)

- [ ] **Step 5: Confirm `utils/signer` is untouched (GC5 gate)**

Run:
```bash
cd op-succinct
git diff 972c86d0f8bb70ddb758a61860911db6f6334b7e -- utils/signer/src/kms.rs ; echo "kms-diff-exit=$?"
git diff 972c86d0f8bb70ddb758a61860911db6f6334b7e -- utils/signer/src/lib.rs utils/signer/Cargo.toml
```
Expected: **no output** for all three (the change is entirely in root `Cargo.toml` + `stubs/` + `justfile`). This is the Spec §5 machine-executable gate — an empty `kms.rs` diff.

- [ ] **Step 6: Commit**

```bash
cd op-succinct
git add Cargo.toml
git commit -m "[Oli] feat(kms): repoint ok-kms-rust workspace dep to in-tree stub path"
```

**Requirement checks:** Spec §3.1, §3.2 (signer unchanged), §5 whitelist + gate. GC1, GC2, GC5, GC6, GC10.

---

## Task 3: `justfile` — real-SDK swap and restore recipes (no build-verify)

**Files:**
- Modify: `justfile` (append after the existing build recipes)

**Interfaces:**
- Consumes: the committed stub at `stubs/ok-kms-rust`.
- Produces: `just kms-crate` (swap in the real SDK) and `just kms-crate-restore` (restore the stub). The SSH URL lives ONLY inside the `kms-crate` recipe body (an operator action), never in a committed `*.toml` (GC1). No `OK_KMS_STUB` marker / no build-verify recipe (Spec §3.4, §8 — bare-minimum).

- [ ] **Step 1: Add the recipes**

Append to `justfile` (the file uses `just` syntax; recipes with a `#!/usr/bin/env bash` shebang run as a single bash script, matching the existing `run-single`/`run-multi` style):

```just
# ── KMS crate management (operator-only; the real SDK SSH URL never enters a committed *.toml) ──

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
```

- [ ] **Step 2: Verify `just` parses the recipes and the stub tree stays pristine**

Run (no network needed — this only checks parsing and the clean state):
```bash
cd op-succinct
just --list | grep -E 'kms-crate'
git status --porcelain stubs/ok-kms-rust ; echo "clean-exit=$?"
```
Expected: both `kms-crate` and `kms-crate-restore` are listed; `git status --porcelain stubs/ok-kms-rust` prints nothing (GC3). Do NOT run `just kms-crate` in CI/restricted envs — it needs SSH access to the private group (an operator action).

- [ ] **Step 3: Verify-against-real-SDK note (execution/production reminder, non-blocking here)**

Before the first real production `just kms-crate` build, confirm the real `ok-kms-rust` v1.0.0 surface still matches the stub (`KmsClient::new`, `get_all_secrets`, `KmsError::Disabled`). If the real SDK diverged, update the stub to match (the stub is the compile-time contract for both). This is an operator/production step, not part of the offline CI gate.

- [ ] **Step 4: Commit**

```bash
cd op-succinct
git add justfile
git commit -m "[Oli] chore(kms): add kms-crate swap and kms-crate-restore recipes"
```

**Requirement checks:** Spec §3.4 (recipes), GC1 (URL only in recipe body), GC3. No marker / no build-verify (Spec §0, §8).

---

## Task 4: Feature-gate validation against the stub (no source changes)

**Files:** none modified — this task only runs the compile/test gates that prove the stub surface matches the unchanged `kms.rs`.

- [ ] **Step 1: Feature OFF — default build + tests unchanged**

Run:
```bash
cd op-succinct
cargo check -p op-succinct-signer-utils
cargo test  -p op-succinct-signer-utils --lib
```
Expected: PASS exactly as at base SHA — the default build never names an `ok_kms_rust` type (GC7). No new tests were added (GC5/GC6: `kms.rs` unchanged, so the existing signer tests are the coverage).

- [ ] **Step 2: Feature ON — compiles against the in-tree stub**

Run:
```bash
cd op-succinct
cargo check -p op-succinct-signer-utils --features kms
```
Expected: PASS — proves `stubs/ok-kms-rust` exposes exactly the surface `kms.rs` uses under `#[cfg(feature = "kms")]` (`KmsClient::new`, `get_all_secrets`, `KmsError::Disabled`), with no private access (GC8).

- [ ] **Step 3: Lint both feature states (no new warnings)**

Run:
```bash
cd op-succinct
cargo clippy -p op-succinct-signer-utils --all-targets
cargo clippy -p op-succinct-signer-utils --all-targets --features kms
```
Expected: no new warnings attributable to the stub (the signer sources are unchanged; only the dependency target changed).

- [ ] **Step 4: Re-assert the minimal-diff gate**

Run:
```bash
cd op-succinct
git diff 972c86d0f8bb70ddb758a61860911db6f6334b7e -- utils/signer/src/kms.rs ; echo "kms-diff-exit=$?"
```
Expected: **no output** (empty diff) — Spec §5 gate. If non-empty, revert `kms.rs` to base SHA; a `kms.rs` change is out of scope this round.

**Requirement checks:** Spec §6 tests 1–3, §7 (offline resolution + feature-on stub compile + feature-off unchanged). GC4, GC5, GC7, GC8, GC11.

---

## Task 5: Commit the Superpowers context to the feature branch

**Files:**
- Commit: `docs/superpowers/specs/2026-09-08-kms-stub-crate-design.md`, `docs/superpowers/plans/2026-09-08-kms-stub-crate.md` (this file, round-2), `docs/superpowers/lark-review-doc.md`

- [ ] **Step 1: Stage and commit the design context (GC12)**

```bash
cd op-succinct
git add docs/superpowers/
git commit -m "[Oli] docs(superpowers): round-2 minimal-diff KMS stub design spec and plan"
```

Expected: `docs/superpowers/**` is tracked on `xl/xlop-1197/0908-0931` so it survives forward CoW and the pre-MR-review context archive. Normal repo Git rules; no special policy (Flow prompt).

> Ordering note: this docs commit may be made first or last — either is acceptable. Listed as a discrete task so the design context is never left uncommitted. Do NOT `git add` `.codegraph/`, `.oli-codegraph/`, `tmp/`, or any `.oli-security-report.json`.

**Requirement checks:** GC12, Spec §11 (C11).

---

## Full validation sequence (offline, scoped — run before handing off)

Run from `op-succinct/`. All commands are crate-scoped per GC11 (a full `--all-features --workspace` gate is expected to fail in restricted envs for unrelated `okx/x2` / `postgresql_embedded` reasons and MUST NOT be used as the gate).

```bash
cd op-succinct
# 1. Anchor goal: no private SSH URL in any committed manifest
git grep -n 'ssh://git@gitlab.okg.com' -- '*.toml'   # expect: NO lines (only justfile recipe body may mention it)
# 2. Workspace resolves with the stub path dep
cargo metadata --format-version=1 >/dev/null && echo "metadata OK"
# 3. Stub crate compiles offline
cargo check -p ok-kms-rust
# 4. Signer, feature OFF (default) — compiles + tests pass unchanged
cargo test -p op-succinct-signer-utils --lib
# 5. Signer, feature ON against the stub — compiles (surface parity)
cargo check -p op-succinct-signer-utils --features kms
# 6. Lint both feature states — no new warnings
cargo clippy -p op-succinct-signer-utils --all-targets
cargo clippy -p op-succinct-signer-utils --all-targets --features kms
# 7. MINIMAL-DIFF GATE: kms.rs is byte-for-byte unchanged
git diff 972c86d0f8bb70ddb758a61860911db6f6334b7e -- utils/signer/src/kms.rs   # expect: EMPTY
# 8. Signer lib.rs / Cargo.toml also unchanged
git diff 972c86d0f8bb70ddb758a61860911db6f6334b7e -- utils/signer/src/lib.rs utils/signer/Cargo.toml   # expect: EMPTY
# 9. Env-flag model still present (NOT retired)
git grep -n -e 'ENABLE_KMS' -e 'is_kms_enabled' -e 'fetch_secret' -- utils/signer/src/kms.rs   # expect: matches present
# 10. Stub tree is pristine (no real SDK committed)
git status --porcelain stubs/ok-kms-rust   # expect: empty
```

**Expected outcomes:** commands 2–6 succeed; commands 1, 7, 8 print nothing (empty diff / no match); command 9 DOES print matches (env-flag preserved — the inverse of round 1); command 10 prints nothing.

## Requirement → Task traceability

| Requirement / constraint (Spec) | Satisfied by |
|---|---|
| Anchor goal: committed manifest never references KMS SSH URL (§1, §3.1, C1/C2) | Task 2 (git→path) + validation cmd 1 |
| In-tree path dependency + register member (§3.1, C10) | Task 2 Steps 1–2 + validation cmd 2 |
| Stub mirrors exact `kms.rs` surface, fails at runtime, no marker (§2.2, §3.3) | Task 1 + Task 4 Step 2 |
| `utils/signer/src/kms.rs` unchanged — minimal-diff gate (§5, C5) | Task 2 Step 5 + Task 4 Step 4 + validation cmd 7 |
| `lib.rs` / signer `Cargo.toml` unchanged (§3.2, §5) | validation cmd 8 |
| Env-flag model preserved; NO reference model (§3.2, §8, C6) | (no task changes it) + validation cmd 9 |
| Offline default build (§7.1, C4) | Task 4 Step 1 + validation cmd 2–4 |
| Feature ON compiles against stub (§7.2, C8) | Task 4 Step 2 + validation cmd 5 |
| Feature OFF tests unchanged (§7.3) | Task 4 Step 1 + validation cmd 4 |
| Client reuse preserved (§3.2, C9) | consequence of GC5 (kms.rs unchanged) |
| No real SDK checkout committed (§3.3, C3) | Task 1 Step 3 (.gitignore) + Task 3 (restore) + validation cmd 10 |
| `just` swap/restore recipes; SSH URL only in recipe (§3.4, C1) | Task 3 + validation cmd 1 |
| No stub marker / no build-verify recipe (§0, §8) | Task 1 Step 2 + Task 3 (recipes only) |
| Workspace hygiene / `[patch]` untouched (§2.4, C10) | Task 2 Step 2 note + validation cmd 2 |
| `docs/superpowers/**` committed; `[Oli] ` subjects (§11, C11) | Task 5 + every task's commit |
| Reuse branch `xl/xlop-1197/0908-0931` + MR #104; no new branch/MR (§0, §10) | Plan header + downstream stages 3.0/5.0 |
| Additional Context items | **None supplied** (Spec §9) — inapplicable, no task required |

## Self-Review

1. **Spec coverage** — every Spec section (§1 anchor goal, §3.1–§3.4 design, §5 minimal-diff whitelist + gate, §6 constraints C1–C11, §7 tests 1–5, §8 non-goals, §9 Additional Context, §10 downstream) maps to a task/validation in the traceability table. No gaps.
2. **Placeholder scan** — no `TBD`/`TODO`/"handle edge cases"/"similar to Task N"; every code step carries real code (stub source, manifest edit, recipes).
3. **Type consistency** — the stub's `KmsError { Disabled, Backend(String) }`, `KmsClient::{new, get_all_secrets}` match exactly the symbols the unchanged `kms.rs` references (`ok_kms_rust::{KmsClient, KmsError}`, `KmsError::Disabled`, `get_all_secrets`). No reference-model symbols are introduced anywhere (round-1 scope fully removed).
4. **Anti-regression vs round 1** — this plan does NOT add `is_kms_ref`/`maybe_resolve`/`KMS_REF_PREFIX`, does NOT reroute read sites, does NOT retire the env-flag model, and does NOT add an `OK_KMS_STUB` marker or build-verify recipe. Validation cmds 7–9 fail the round-1 shape and pass the round-2 shape.

## Feedback iterations (if this plan is reworked again)

This file is the single canonical plan and was regenerated in place for round 2 (Spec §10). On any further feedback round, prefer revising THIS file with a new dated round banner; if a parallel scope must be preserved, add a clearly-linked delta plan `docs/superpowers/plans/YYYY-MM-DD-kms-stub-crate-<delta-slug>.md` that links back here, records only changed/added tasks, and maps any newly-supplied Additional Context to a task or records it inapplicable with a reason.

## Execution Handoff

Plan complete. Execution happens in the downstream **Execute and Validate Plan** stage on branch `xl/xlop-1197/0908-0931` (this planning stage does NOT invoke `executing-plans`). Recommended execution approach: **subagent-driven** (fresh subagent per task, review between tasks) via `superpowers:subagent-driven-development`; inline batch execution via `superpowers:executing-plans` is the alternative. Stage 3.0 must run the Spec §5 machine-executable gate (`git diff 972c86d … -- utils/signer/src/kms.rs` empty); stage 5.0 updates the description of the existing MR #104 (no new MR).
