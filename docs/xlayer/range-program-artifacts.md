# Range and aggregation program ELF artifacts — okx/optimism a492b62b alignment

This record documents how the two embedded SP1 ELFs — `elf/range-elf-embedded` and
`elf/aggregation-elf` — are produced, the exact bytes currently committed, and the
verification-key consequences of those bytes. All paths are relative to the repository root.

## 1. Current artifacts

| File | Size (bytes) | SHA256 |
|---|---|---|
| `elf/range-elf-embedded` | 7,297,720 | `1ce623dc52e1d948a01371ce4d4f084eb51ec551910d2b58cb55630415be7d89` |
| `elf/aggregation-elf` | 768,808 | `489a5f3762a81d885e53673312d8d168880019c6996ff5c7ffd23e8107ebc466` |

Both files are ELF64 little-endian RISC-V objects (`e_machine = 0xF3`), i.e. SP1 guest
programs and not host objects or scripts.

`elf/celestia-range-elf-embedded` and `elf/eigenda-range-elf-embedded` are not part of this
record and were not changed.

## 2. Provenance — CI Docker builder

Both committed files are the artifact output of a single `build-elfs` job.

| Item | Value |
|---|---|
| Job | `build-elfs`, stage `Build`, id `42208979` |
| Pipeline | `16099476` (source `merge_request_event`, ref `refs/merge-requests/123/head`) |
| Source commit | `f80bf96319ae0394a344aa20aa0164c86c4b6cc0` |
| Base commit (target branch) | `0f8a69a8f94b6b6a225e46f54837eedd81db572a` |
| SP1 toolchain in the job | `v6.1.0` (`sp1up: installing SP1 (version v6.1.0, tag v6.1.0)`) |
| Builder image | `ghcr.io/succinctlabs/sp1:v6.1.0` |
| Range build command | `cd programs/range/ethereum && cargo-prove prove build --elf-name range-elf-embedded --docker --tag "v${SP1_VERSION}" --output-directory "$CI_PROJECT_DIR/elf"` |
| Aggregation build command | `cd programs/aggregation && cargo-prove prove build --elf-name aggregation-elf --docker --tag "v${SP1_VERSION}" --output-directory "$CI_PROJECT_DIR/elf"` |
| Artifact archive | `op-succinct-elfs-f80bf963.zip`, 2,977,539 bytes |
| Archive SHA256 | `31963d8a8f0bd21c3d225a6ddd1435f6973bcf5ce33acce3b28d1e7ed36fc9a2` |
| Archive expiry | 2026-11-23T08:57:35.253Z |

The job's own log records the guest crates compiling against the repository's patched SP1
(`sp1-primitives v6.1.0 (https://github.com/okx/sp1?branch=feat%2Fgateway-proxy-v6.1.0#dab85639)`):
the Docker image supplies the guest toolchain, while the dependency graph still resolves to the
okx/sp1 fork recorded in `Cargo.lock`.

The job ended with `script_failure` only because its drift check found the rebuilt binaries
different from the files then committed; the two rebuilt binaries are exactly the files recorded
in section 1. A CI build is environment-sensitive: a `web`-triggered pipeline of the same commit
used a different `CARGO_HOME` and produced different bytes, because the registry source path is
embedded in the binary. The artifact adopted here is the `merge_request_event` build of this
source tree, which is also the pipeline type whose drift check consumes it.

## 3. Byte-level artifact integrity

The archive was read without executing anything. It contains exactly two entries, with no
duplicate names, no absolute paths, no `..` components and no directory entries.

| Entry | Size (bytes) | CRC32 | SHA256 |
|---|---|---|---|
| `elf/range-elf-embedded` | 7,297,720 | `0xdc93f2ce` | `1ce623dc52e1d948a01371ce4d4f084eb51ec551910d2b58cb55630415be7d89` |
| `elf/aggregation-elf` | 768,808 | `0x331a7aa1` | `489a5f3762a81d885e53673312d8d168880019c6996ff5c7ffd23e8107ebc466` |

The committed files were compared byte-for-byte against these entries (`cmp`) and are identical.

## 4. Previous committed files

| File | Previous size (bytes) | Previous SHA256 | Origin |
|---|---|---|---|
| `elf/range-elf-embedded` | 7,300,496 | `f8cbd267af6e25994e3c37c3268fca57942516ffd6ef8b3bd12b595dc0d87916` | Local SP1 CLI (`cargo prove`) build of commit `9f91d7d0b9ec05b60f185e55700df8a5bcc33652` with path remapping |
| `elf/aggregation-elf` | 771,408 | `3cdcd394c013384c3666e08d9bedb33952b273a4d6971a2a5a5aa375e51a8297` | Unchanged file from the target branch |

The previous range ELF was produced outside the CI Docker builder. Because the CI drift check
compares rebuilt bytes against the committed file, that difference was reported as drift on every
run. Both files are now the Docker builder's own output, so a rebuild of the same source tree in
the same pipeline type reproduces the committed bytes and the drift check reports nothing.

## 5. Dependency and branch context

The branch aligns the OP Stack crates to okx/optimism `a492b62bbecbdcf3be90719e042c9abca47c8cc6`;
that alignment is part of the branch history and is not modified by this artifact update.

| Item | Value |
|---|---|
| okx/optimism revision (Kona, OP Alloy, alloy-op-evm, op-revm) | `a492b62bbecbdcf3be90719e042c9abca47c8cc6` |
| Execution crates | `revm` 40.0.3, `revm-precompile` 36.0.3, `alloy-evm` 0.36.0, `op-revm` 20.0.0, `alloy-op-evm` 0.32.0, `reth-codecs` 0.4.2 |
| SP1 crates | `sp1-sdk`/`sp1-lib`/`sp1-zkvm` 6.1.0; `sp1-sdk` from `okx/sp1` `dab85639bb828aafa2971ae38fda8eeb56c4b1f5` |
| `Cargo.lock` SHA256 at the earlier build commit `9f91d7d0` | `c62dc69d136bd278b99d8e03f431df95a4959d28c75bb850fce9af2ddc47886a` |

The lock hash above describes the earlier local-build commit, not the current tree. The proof
stack itself is unchanged: 48 `okx/sp1` lock entries at `dab85639…` (47 packages plus the unused
`sp1-cuda` patch entry), 3 `okx/sp1-cluster` packages, and the 9 `sp1-patches` git packages.

## 6. Verification keys

Embedding is by `include_bytes!` in `utils/elfs/src/lib.rs`; the range ELF is selected by feature
flag in `get_range_elf_embedded()` (`utils/proof/src/lib.rs`). No key file is committed: both keys
are derived at run time by an SP1 `setup` of the embedded ELF.

The two keys are derived differently and are not interchangeable:

- **Range vkey commitment** — `B256::from(u32_to_u8(vk.hash_u32()))`: the `[u32; 8]` BabyBear
  representation of the range verifying key, each limb written big-endian into 32 bytes.
- **Aggregation vkey** — `SP1VerifyingKey::bytes32()`, the raw 32-byte representation.

Canonical measurement entry point (no chain access needed — both values are printed before the
optional environment/RPC branch):

```
cargo build --release -p op-succinct-scripts --bin config --locked
./target/release/config
```

Measured with rustc 1.97.0-nightly (7c3c88f42 2026-05-14) and the workspace lock
(`sp1-sdk` 6.1.0 from `okx/sp1` `dab85639…`):

| ELF set | Range vkey commitment | Aggregation vkey |
|---|---|---|
| Previous committed files (§4) | `0x16640cd44c9875e631526e583469c6e74f0bb40155bd9da003665896179d8348` | `0x00896a880203339a7a04fba4dbe8140239279b4610475890740f026be67eb4ed` |
| Current committed files (§1) | `0x45bd1547534cb6093b6606765fd91a7f15def34f7b21932e0e3aeef348cb0455` | `0x00756250376ecfc39574a2bd675181d8984b3f74db78aaee1494e9ecb4ab1fe9` |

The range commitment changes with the range ELF and the aggregation vkey changes with the
aggregation ELF; in this update both files changed, so both values rotate. Deployment-side
configuration — on-chain immutables and environment values — is owned by the deployment process
and is not changed by this record.

## 7. Rollup config hash

`hash_rollup_config` (`utils/client/src/boot.rs`) is
`SHA256(serde_json::to_string_pretty(RollupConfig))`.

`RollupConfig` is not a build input: it is fetched at run time from the L2 node RPC
(`optimism_rollupConfig`) and cached to a gitignored path (`L2_CONFIG_DIR`, default
`configs/L2`, file `{chain_id}.json`; see `utils/host/src/fetcher.rs`). For the same
`RollupConfig` object serialized by the same algorithm, replacing an ELF does not change this
hash, because no ELF byte is an input to it.

No measured before/after value is claimed here: the chain's `RollupConfig` is not an input to
this work. A static value in tracked configuration is a different artifact from a runtime RPC
computation and is not presented as one.

## 8. Tracked static configuration

`contracts/testnet/opsuccinctfdgconfig.json` carries static `rollupConfigHash`,
`rangeVkeyCommitment` and `aggregationVkey` values that the testnet deployment script
(`contracts/script/fp/DeployOPSuccinctLiteTestnet.s.sol`) reads into `SP1Config`. The upgrade path
reads the same values from the environment, and the dispute game stores them as on-chain
immutables.

Those static values do not correspond to the ELF bytes recorded here, and this change does not
modify that file: whether that testnet configuration is a target of this artifact update is
outside this record. The divergence is disclosed so that it is not mistaken for a match.

## 9. Verification boundary

Measured and recorded here:

- archive and per-entry hashes/sizes, byte-for-byte identity of the committed files;
- the two verification keys for the previous and the current ELF sets, with the tool versions;
- the manifest/compile checks below.

Compile checks run on this tree:

| Command | Result |
|---|---|
| `cargo check -p op-succinct-elfs` | pass (exit 0) |
| `cargo check -p op-succinct-proof-utils --features ethereum` | pass (exit 0) |
| `cargo build --release -p op-succinct-scripts --bin config --locked` | pass (exit 0) |
| `cargo test -p op-succinct-client-utils --lib` | pass — 22 tests passed |

Not performed: proof generation, joint range/aggregation proof verification, state-root or
output-root comparison, RPC or chain calls, deployment, and any rollup of remote or on-chain
configuration.

Cross-program note: the aggregation guest does not embed the range vkey. It receives
`multi_block_vkey: [u32; 8]` in its inputs and verifies each range proof against
`sha256(boot_info)` (`programs/aggregation/src/main.rs`). Compatibility between the two binaries
is therefore a property of the host-supplied inputs at aggregation time, not a static byte
property of the two files; this record neither generates a proof nor claims one was verified.