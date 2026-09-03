# Hand-off: TZ four-field claim — ELF/vkey rebuild, redeploy, and access-gated remainder

> Operational hand-off produced by the Execute-and-Validate stage. **No build/deploy is performed
> here.** This records the deferred steps (spec §8, §12) plus the items blocked by the execution
> environment's dependency-access limits, so the plan-execution operator (or a re-run in a
> provisioned environment) can complete them.

Jira: [TRDZN-1339](https://okcoin.atlassian.net/browse/TRDZN-1339) ·
Spec: `docs/superpowers/specs/2026-09-03-tz-withdraw-forcetx-root-and-defender-design.md` ·
Plan: `docs/superpowers/plans/2026-09-03-tz-withdraw-forcetx-root-and-defender-plan.md`

## 1. Why a rebuild + redeploy is required (spec §8)

Threading the four-field `claimRoot = keccak256(blockHash ‖ appHash ‖ withdrawalRoot ‖ forceRoot)`
through the SP1 range guest changes what the guest commits and (once the boundary witness is added
to the guest's `SP1Stdin`) its input layout. Therefore **both the range vkey and the aggregation
vkey change**. Until the on-chain config is updated, `prove` will revert on a vkey mismatch — so
the MR is build-/test-green but NOT deploy-complete (spec §14 criterion 7; §5 "compile- & test-green
MR"). No dual-mode: wire mixing is protocol-forbidden (spec §8).

## 2. Required sequence (run in an environment with SP1 + private-dep access)

1. `just build-tz-elfs` — rebuild `tz-range-elf-embedded` + `tz-aggregation-elf`.
2. `just tz-vkeys` — regenerate the vkey hashes (`cargo run --release --bin tz-config`).
3. Update `contracts/config/tz/opsuccinctfdgconfig.json` `rangeVkeyCommitment` + `aggregationVkey`
   with the new hashes (current values on this branch: `rangeVkeyCommitment=0x584fd7b9…`,
   `aggregationVkey=0x00be73c0…` — confirm against the file before editing).
4. Redeploy the tz Game config (deploy-tz).
5. Cross-process version note (spec §12): the tradezone (`x2.git`) rev used to build the ELF and the
   Claim Tree Core version MUST match the WB side; a bump requires rebuild + redeploy.

## 3. Environment access blockers observed during execution (MUST provision to finish)

This execution environment's git credentials are scoped to `github/op-succinct` only. The following
private dependencies could **not** be fetched, so the corresponding steps were deferred:

| Dependency | Host | Needed for | Status here |
|---|---|---|---|
| `tz-dex`, `tz-block-processor`, `tz-primitives` (`x2.git` @ `b3e2cf98…`) | github.com/okx | SP1 range guest (`programs/tz/range`) | **unreachable** (SSH publickey denied) |
| TradeZone Claim Tree Core (`tradezone` @ `feature/witness-builder-withdraw-v1`, HEAD `a3f3079b7`, `crates/chain/src/witness/`) | gitlab.okg.com `xlayer-dex/tradezone` | guest tree rebuild + host tree cross-check | **unreachable** (deploy key not authorized for that project) |
| `ok-kms-rust` (`v1.0.0`) | gitlab.okg.com `okcoin-commons` | optional `kms` signer feature (OFF for tz) | **unreachable** (not authorized) |
| SP1 toolchain (`cargo-prove`) | — | building the guest ELF | **absent** |

To build/test the host-side `fault-proof --features tz` crate here, the optional/guest-only private
deps were replaced with **local empty stubs via a cargo `[patch]` in the workspace-root `Cargo.toml`
plus a parent-directory `.cargo/config.toml` `paths` override — both OUTSIDE the committed tree and
reverted before finishing** (they are NOT part of the branch). In a provisioned environment, remove
any such shim and let the real deps resolve.

## 4. Deferred code that requires the above access (paired, vkey-affecting — land together)

The host-side building blocks are implemented and unit-tested on this branch; the following runtime
wiring must be completed where the guest can compile against the real Claim Tree Core:

- **SP1 range guest (`programs/tz/range/src/main.rs`, plan T8):** read the boundary-witness fields
  from `SP1Stdin` after `chunk_count`; rebuild the two pre `innerRoot`s from `count + activeBranches`
  via the tradezone Claim Tree Core; wrap with `count + tag` for pre `withdrawalRoot`/`forceRoot`;
  replay canonical blocks and let the Claim Tree Core extract records/leaves and compute the post
  roots (the guest MUST NOT trust host-supplied leaves); commit the full four-field claim as
  `l2PreRoot`/`l2PostRoot` (ABI shape unchanged, 160 B). Replace `keccak_join(block_hash, state_hash)`.
  Blocked here because `programs/tz/range` depends on `x2.git` + the tradezone core (unreachable) and
  no SP1 toolchain is present; the exact tradezone `crates/chain/src/witness/` API must be linked
  rather than guessed.
- **Proposer stdin splice (`fault-proof/src/tz/proposer.rs::prove_range`, plan T7):** after
  `range_stdin.write(&chunk_count)`, append the boundary fields produced by the unit-tested
  `boundary_stdin_fields` helper (already on this branch). This is the host half of the same
  vkey-affecting change as the guest read above — land them together.
- **Four-preimage Game creation (`handle_game_creation`, plan T9):** write the 164-byte four-preimage
  `extraData` (`l2BlockNumber ‖ parentIndex ‖ blockHash ‖ appHash ‖ withdrawalRoot ‖ forceRoot`) and
  set `rootClaim` to the four-field claim, gated by `assert_extra_data_self_consistent` (already on
  this branch). Requires the four-preimage Game impl (`HAS_ROOT_CLAIM_PREIMAGE`) to be the deployed
  game type. The `compute_output_root_at_block` four-field path (WB-backed) is already implemented.

## 5. What IS complete and verified on this branch (host-side, crates.io-only)

`cargo test -p op-succinct-fp --features tz` (lib + `tz_defender_integration`) is green:
the four-field shared library (`tz/withdraw/`), the L1 challenger chainId guard, the WB-backed
`compute_output_root_at_block`, the boundary fetch + cross-check + stdin-ordering helpers, and the
full independent Defender (mock challenge seam, config, RootManager source, LRU cache, local
verifier, watcher, handler state machine, `tz-defender` binary). Empty-tree vectors are computed
independently and asserted against the spec's published values (no frozen fixture required).
