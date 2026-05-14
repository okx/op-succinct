# op-succinct TEE Adaptation for tz Chain — Design

**Date:** 2026-05-14
**Source spec:** `op-succinct-tee-adaptation-spec.md`
**Scope:** L2 data-fetch layer only (SP1 proof pipeline is out of scope / future phase)

---

## 1. Problem

The op-succinct proposer and challenger are tightly coupled to standard OP Stack RPC interfaces (`optimism_outputAtBlock`, `eth_getBlockByNumber("finalized")`, `eth_getProof`). The target chain **tz** (TradeZone) does not implement these interfaces and uses a different rootClaim formula:

| | xlayer (existing) | tz (new) |
|---|---|---|
| rootClaim | `keccak256(0x00 ++ state_root ++ storage_hash ++ block_hash)` | `keccak256(blockHash ++ stateHash)` |
| Finalized height | `eth_getBlockByNumber("finalized")` | `GET /chain/confirmed_block_info` |
| Proposal target | `canonical_head + proposal_interval` | latest checkpoint height |
| UUID collision | while-loop increment | one-shot skip |

Everything else (contract, extraData format, vkey validation, `factory.create()`) is identical between the two chains.

---

## 2. Design Principle

**Extend, never replace.** The `tz` feature is selected at compile time via `cargo --features tz`. All tz-specific code lives in new files guarded by `#[cfg(feature = "tz")]`. Every modification to an existing file is annotated with `// for tz:`. The xlayer path is untouched at runtime.

---

## 3. Architecture

```
Existing (xlayer)                    New (tz feature)
─────────────────────                ──────────────────────────────
L2Provider (RootProvider<Optimism>)  TzChainClient  ← REST /chain/confirmed_block_info
                  ↓                          ↓
         L2ProviderTrait  ←──────────  TzL2Provider  (implements trait)
                  ↓                          ↓
      proposer / challenger          tz-proposer / tz-challenger  (binaries)
```

`L2ProviderTrait` is extended with two default-implemented methods so the xlayer `L2Provider` requires zero changes:

- `get_next_proposal_block()` — default returns `None` (xlayer falls through to existing host logic)
- `evict_cache_below()` — default is a no-op

---

## 4. New Files (5 total)

| File | Purpose |
|------|---------|
| `fault-proof/src/tz_chain_client.rs` | HTTP client for `/chain/confirmed_block_info`; in-memory history cache; multi-endpoint failover |
| `fault-proof/src/tz_l2_provider.rs` | `TzL2Provider` implementing `L2ProviderTrait`; `compute_tz_root_claim()` helper |
| `fault-proof/src/tz_proposer_config.rs` | `TzConfig` parsed from `TZ_RPC_URLS`, `TZ_ROLLUP_CONFIG_HASH`, `TZ_GAME_TYPE` (default 1961) |
| `fault-proof/bin/tz_proposer.rs` | `tz-proposer` binary entry point |
| `fault-proof/bin/tz_challenger.rs` | `tz-challenger` binary entry point (includes 60 s background polling task) |

---

## 5. Existing File Changes (minimal)

All changed lines carry `// for tz:` comments.

| File | Change |
|------|--------|
| `fault-proof/Cargo.toml` | Add `[features] tz`; `reqwest`/`thiserror` as optional deps; two `[[bin]]` entries |
| `fault-proof/src/lib.rs` | Three `#[cfg(feature="tz")] pub mod` declarations; two new default methods on `L2ProviderTrait` |
| `fault-proof/src/proposer.rs` | `l2_provider` field → `Arc<dyn L2ProviderTrait + Send + Sync>`; `new()` wraps Arc; add `new_with_l2_provider()`; skip `validate_anchor_l2_block` and finalized-height metric under `#[cfg(not(feature="tz"))]`; UUID collision one-shot check; `should_create_game` tz short-circuit; `sync_state` cache eviction |
| `fault-proof/src/challenger.rs` | Same field/constructor pattern; `fetch_game` cache-miss skip |

---

## 6. Key Behaviours

### rootClaim calculation (tz)
```
rootClaim = keccak256(blockHash ++ stateHash)
```
`blockHash` and `stateHash` come from `/chain/confirmed_block_info` and are guaranteed consistent by the chain.

### Cache design
`TzChainClient` keeps an in-memory `HashMap<u64, TzBlockInfo>` (no TTL). Entries are evicted via `evict_below(anchor_height)` called from `sync_state` after each anchor advancement. Upper bound ≈ 168 entries (8 days × ~21 checkpoints/day).

### Cache miss handling
- **Proposer `fetch_game`**: miss → skip rootClaim validation, game still enters `state.games` (needed for canonical-head tracking)
- **Challenger `fetch_game`**: miss → skip game entirely (cannot decide whether to challenge)

### Challenger background poller
`tz-challenger` spawns a tokio task polling `/chain/confirmed_block_info` every 60 s, continuously filling the history cache. Ensures checkpoints are cached before `sync_state` encounters them.

### ELF placeholder
`fault-proof/elfs/tz-range.elf` is an empty placeholder for Phase 1. The SP1 proof pipeline is a separate future phase; `new_with_l2_provider()` accepts `range_elf: &'static [u8]` as the injection point.

---

## 7. Environment Variables

| Variable | Used by | Default | Notes |
|----------|---------|---------|-------|
| `TZ_RPC_URLS` | proposer + challenger | required | Comma-separated REST endpoints |
| `TZ_ROLLUP_CONFIG_HASH` | proposer only | required | B256 hex matching contract deployment |
| `TZ_GAME_TYPE` | proposer + challenger | `1961` | tz dispute game type ID |

---

## 8. Implementation Sequence (Approach A — compile-first)

1. `fault-proof/Cargo.toml` — feature + optional deps + bin entries
2. `fault-proof/src/lib.rs` — trait extension + module declarations
3. `fault-proof/src/proposer.rs` — field type + `new_with_l2_provider()`
4. `fault-proof/src/challenger.rs` — same
5. New src files: `tz_chain_client.rs`, `tz_l2_provider.rs`, `tz_proposer_config.rs`
6. New bin files + placeholder ELF
7. Remaining `#[cfg]` patches in proposer/challenger (validations, metrics, UUID, cache eviction)

After steps 1–4, `cargo check` with the existing xlayer path passes. Steps 5–7 layer in tz logic.

---

## 9. Testing Plan

Inline `#[cfg(test)]` modules in each new file. No live tz node required; HTTP calls are mocked.

| Module | Key cases |
|--------|-----------|
| `tz_chain_client` | Normal parse; `data: null` → NotReady; multi-endpoint failover; `evict_below` cleanup |
| `tz_l2_provider` | `compute_tz_root_claim` correctness; cache hit; cache miss → `TzCacheMissError`; `get_next_proposal_block` interval check |
| `tz_proposer_config` | Full env parse; missing `TZ_RPC_URLS` errors; `TZ_GAME_TYPE` defaults to 1961 |

---

## 10. Out of Scope

- SP1 proof generation pipeline for tz (separate future phase)
- `utils/host/src/block_range.rs` `get_l2_header(BlockId::finalized())` call (proof script path)
- Integration tests against a live tz node
