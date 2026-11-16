# Range program ELF — okx/optimism a492b62b alignment

This record describes how `elf/range-elf-embedded` was produced. All paths are relative to the
repository root.

## Source

| Item | Value |
|---|---|
| Base commit | `0f8a69a8f94b6b6a225e46f54837eedd81db572a` (`main`) |
| Source commit the ELF was built from | `9f91d7d0b9ec05b60f185e55700df8a5bcc33652` (clean tracked tree at build time) |
| okx/optimism revision (Kona, OP Alloy, alloy-op-evm, op-revm) | `a492b62bbecbdcf3be90719e042c9abca47c8cc6` |
| Execution crates | `revm` 40.0.3, `revm-precompile` 36.0.3, `alloy-evm` 0.36.0, `op-revm` 20.0.0, `alloy-op-evm` 0.32.0, `reth-codecs` 0.4.2 |
| SP1 | `sp1-sdk`/`sp1-lib`/`sp1-zkvm` 6.1.0; `okx/sp1` `dab85639bb828aafa2971ae38fda8eeb56c4b1f5` |
| `Cargo.lock` SHA256 at build commit `9f91d7d0` | `c62dc69d136bd278b99d8e03f431df95a4959d28c75bb850fce9af2ddc47886a` |

The lock hash above is the value at the commit the ELF was built from, not the current tree. The
current tree differs from it only by the later one-line removal of the `sha2` entry in the
`op-succinct-scripts` package dependencies; that package is outside the range program's dependency
graph, so the ELF build input is unaffected and the ELF was not rebuilt after that edit.

## Lock check

Scripted comparison of the new `Cargo.lock` with the base lock — all checks PASS:

- all 28 okx/optimism packages at `a492b62b…`; package list identical to the base (28 packages);
- zero occurrences of `bc7bb771`, `ethereum-optimism/optimism`, `op-rs/kona`, `okx/reth`;
- exactly one version each of `revm` (40.0.3), `op-revm` (20.0.0), `alloy-evm` (0.36.0),
  `alloy-op-evm` (0.32.0), `kona-mpt` (0.3.0), `kona-executor` (0.4.0);
- proof stack unchanged: 48 `okx/sp1` lock entries at `dab85639…` (47 packages plus the unused
  `sp1-cuda` patch entry, same as the base), 3 `okx/sp1-cluster` packages at
  `f3995e8aba652f3c27547eaed63fd276ea169ec2`, all 9 `sp1-patches` packages identical to the base
  (`e48b656e…`, `0a16ae7a…`, `13747d25…`, `476243d3…`, `92379418…`, `1880299a…`, `957430a4…`),
  registry `sp1-lib`/`sp1-zkvm` 6.1.0.

## Compile

| Command | Exit |
|---|---|
| `cargo update -p kona-mpt … -p revm-precompile` (targeted; no bare `cargo update`) | 0 |
| `cargo check --workspace --all-targets --exclude op-succinct-bindings --exclude op-succinct-fp` | 0 |
| `cargo check -p op-succinct-fp --lib --bins` | 0 |
| `cargo test -p op-succinct-client-utils --lib` (information only) | 0 — 22 passed |

`op-succinct-bindings` (and therefore the `op-succinct-fp` test targets, its only dependent) was
not compiled: its build script runs `forge bind`, which fails on the unchanged `contracts/` tree
because `ISP1Verifier.sol` (`^0.8.20`) and the optimism contracts (`=0.8.15`) end up in one
compilation unit. `contracts/` and `bindings/` are identical to the base commit, so this is
independent of the dependency change.

## ELF build

| Item | Value |
|---|---|
| Method | A — local SP1 CLI (no Docker daemon available) |
| `cargo prove --version` | `cargo-prove sp1 (dab8563 …)`, installed with `cargo install --locked --git https://github.com/okx/sp1 --rev dab85639bb828aafa2971ae38fda8eeb56c4b1f5 sp1-cli` |
| SP1 toolchain | `succinct-1.93.0-64bit` release asset `rust-toolchain-x86_64-unknown-linux-gnu.tar.gz` (SHA256 `99e68dd864dd7ee9688333346b428452c705d82a11098e51146389417e0c82c6`); `rustc +succinct --version` = `rustc 1.93.0-dev`; cargo `1.99.0` (rustup fallback) |
| Target | `riscv64im-succinct-zkvm-elf` |
| Command (from `programs/range/ethereum`) | `cargo prove build --elf-name range-elf-embedded --output-directory ../../../elf --rustflags="--remap-path-prefix=<repo>=/root/program,--remap-path-prefix=<cargo home>=/root/.cargo"` |
| Build time (UTC) | 2026-11-06T09:21:59Z – 09:23:38Z |
| `elf/range-elf-embedded` size | 7,300,496 bytes |
| `elf/range-elf-embedded` SHA256 | `f8cbd267af6e25994e3c37c3268fca57942516ffd6ef8b3bd12b595dc0d87916` |
| Reproducibility | a second build of the same commit with the same command produced the same SHA256 |
| Previous ELF (base commit, reference only) | SHA256 `d438b6ce49beb569a5c32d1108db31a706421225f61903725b3d762d90d6e590` |

The path remapping keeps local build-host paths out of the binary. The `justfile` recipe uses the
Docker builder (`--docker --tag v6.1.0`) instead, so a Docker build of the same commit is not
expected to give the same bytes.

No key files are committed in this tree: the range verifying key is derived at runtime by a
dynamic `setup` of the embedded ELF. Because the ELF bytes changed, the range vkey commitment
differs from the base; any deployed configuration that references it is updated separately by its
owner.

## Not covered here

- `elf/aggregation-elf`, `elf/celestia-range-elf-embedded` and `elf/eigenda-range-elf-embedded`
  were not rebuilt; they are still the files from the base commit. The aggregation vkey and the
  rollup config hash were not recomputed.
- Proof generation, state-root/output-root comparison, game and e2e flows, RPC, chain checks and
  rollback were not run; they are left to the owner of the release test plan.
- Raw build and check logs are kept outside the repository with SHA256 indexes.