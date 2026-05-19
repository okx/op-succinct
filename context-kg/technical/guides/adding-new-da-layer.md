---
name: "adding-new-da-layer"
description: "Step-by-step guide to add a new Data Availability layer (e.g., a new blob DA provider)"
---

# Adding a New DA Layer

This guide covers adding a new DA layer (e.g., `newda`) to op-succinct, following the pattern established by Celestia and EigenDA.

## Steps

### 1. Create client and host crate pair

```
utils/newda/client/    → op-succinct-newda-client-utils
utils/newda/host/      → op-succinct-newda-host-utils
```

Add both to workspace members in root `Cargo.toml`.

### 2. Implement client-side pipeline (zkVM guest)

In `utils/newda/client/src/`:
- Implement blob provider or commitment verifier that runs inside SP1
- Must NOT import any host/signer/proof crate (zkVM guest boundary — see `knowledge-base.md` [Rule])

### 3. Implement host-side utilities

In `utils/newda/host/src/`:
- Implement `OPSuccinctHost` trait from `utils/host/src/host.rs`
- Provide `fetch()`, witness generation, and blob fetching logic
- Handle safe-head estimation for the DA layer

### 4. Create range program

```
programs/range/newda/  → op-succinct-newda-range
```

- Copy `programs/range/ethereum/src/main.rs` as template
- Replace Ethereum blob provider with newda-specific provider
- Entry point: `#[sp1_zkvm::entrypoint!(main)]`

### 5. Add Cargo feature flag

In `utils/proof/Cargo.toml`:

```toml
[features]
newda = ["op-succinct-newda-host-utils"]
```

Repeat in `validity/Cargo.toml` and `fault-proof/Cargo.toml`.

### 6. Add cfg_if branches

In `utils/proof/src/lib.rs`, add `newda` branches to both `get_range_elf_embedded()` and `initialize_host()`.

### 7. Add ELF embedding

In `utils/elfs/src/lib.rs`:

```rust
pub const NEWDA_RANGE_ELF_EMBEDDED: &[u8] =
    include_bytes!("../../../elf/newda-range-elf-embedded");
```

Build the ELF: update `utils/build/src/lib.rs` `build_all()`.

### 8. Add Dockerfile variant

Create `validity/Dockerfile.newda` and `fault-proof/Dockerfile.proposer.newda`.

### 9. Update knowledge base

- Add module docs: `modules/utils-newda-client.md`, `modules/utils-newda-host.md`, `modules/programs-range-newda.md`
- Update `conventions/feature-types.md` feature table
- Update `arch/dependency.md` with new crate dependencies

## Pitfalls

- [Rule] Never enable two DA features simultaneously — `cfg_if` only emits one `initialize_host()` impl
- [Pitfall] If the new DA has a non-standard safe-head mechanism, handle it in host utils (don't use generic +20 block offset blindly)
- [Pitfall] New DA crates may transitively pull different alloy versions — check for conflicts with sp1 patches
