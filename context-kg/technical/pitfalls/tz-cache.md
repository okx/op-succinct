---
name: "tz-cache"
description: "Pitfalls for the tz REST-API checkpoint cache — eviction boundary, cache-key invariant, sync mutex discipline"
---
# tz Cache Pitfalls

`utils/signer` is for signing; `utils/host` is for L2 RPC. tz adds a third pattern: an in-memory checkpoint cache keyed by L2 block height in `fault-proof/src/tz/chain_client.rs`. The cache mirrors what xlayer derives from `eth_getBlockByNumber("finalized")`, so its correctness underpins both proposer rootClaim computation and challenger validation.

## Sync `std::sync::Mutex` for the cache (NOT tokio::sync::Mutex)

[Convention] `TzChainClient.cache: std::sync::Mutex<HashMap<u64, TzBlockInfo>>` is intentionally synchronous. The lock is **never** held across `.await` — the only async write site, `get_confirmed_block_info` (`chain_client.rs:58-74`), runs `fetch_one(&url).await` first, then locks/mutates/drops the cache in a single non-async expression. Reason: `std::sync::Mutex` is faster than `tokio::sync::Mutex` and clippy will flag the latter when no `.await` happens under the lock. `tokio::sync::Mutex` is reserved for cases where the lock guard must survive an await point.

[Rule] When adding a new method on `TzChainClient` that touches `cache`, audit the call sites: any `.await` between `cache.lock()` and lock release converts the cache to a deadlock or a Send-bound violation. If the new logic genuinely needs to await under the lock, switch to `tokio::sync::Mutex` and audit all existing call sites for fairness/perf regression — do not bolt async I/O onto the existing sync lock.

**Module**: `fault-proof/src/tz/chain_client.rs`
**Source**: review-finding F-03 (Code Review A-08 R2, KG-13)
**Date**: 2026-05-19
**Hit count**: 1

## evict_below uses strict `<`; anchor lags confirmed_height

[Rule] `TzChainClient::evict_below(anchor_height)` retains entries with `*h >= anchor_height` (strict-less-than eviction). This is invoked from `OPSuccinctProposer::sync_state` end-of-iteration with `anchor_game.l2_block` as the anchor. The cache invariant is: `confirmed_height > anchor_height` always, because anchor advances only after an entire challenge cycle completes (multiple checkpoints behind the latest confirmed). Therefore `handle_game_creation` is **never** racing eviction of the very entry it is about to read. Trigger: refactoring `evict_below` to use `>` (strict-greater-than) or to evict at-or-below would silently drop the active checkpoint and turn every following `compute_output_root_at_block` call into `TzCacheMissError`, causing proposer cache-miss tolerance + challenger skip to fire spuriously. Correct approach: keep the `*h >= anchor_height` predicate; the unit tests `evict_below_drops_strict_less_than_anchor`, `evict_below_clears_when_anchor_above_all`, `evict_below_keeps_at_anchor` (`chain_client.rs:261-293`) are the contract and must not be relaxed.

**Module**: `fault-proof/src/tz/chain_client.rs:103-106`, `fault-proof/src/proposer.rs:651-663`
**Source**: review-finding F-04 (PRD A-13 §B6, Code Review A-08 R3)
**Date**: 2026-05-19
**Hit count**: 1

## compute_output_root_at_block keys cache by L2 block number, NOT "latest"

[Pitfall] `TzL2Provider::compute_output_root_at_block(l2_block_number)` (`tz/l2_provider.rs:58-64`) does a precise `HashMap::get(&height)` lookup; on miss it returns `TzCacheMissError`, **not** the latest confirmed checkpoint. Trigger: a "convenience" refactor that has the provider fall back to the latest checkpoint when the requested height is not cached (e.g. "always return whatever we have"). Why this is fatal: the challenger's `fetch_game(index)` reads `contract.l2BlockNumber()` from L1 and hands that exact height to `compute_output_root_at_block`. If the cache returns the latest checkpoint instead, the challenger compares `keccak256(latest_blockHash ‖ latest_stateHash)` against the on-chain `rootClaim` (which is `keccak256(historical_blockHash ‖ historical_stateHash)` for the requested height). Mismatch ⇒ challenger issues a challenge tx against a **valid** game, slashes its own bond, and disrupts the dispute system. Correct approach: keep the strict-key lookup; cache miss ⇒ return `TzCacheMissError`; challenger safely skips the game (FR-7). The `data:null` REST response also returns cache-miss without writing the cache, so a degraded API does not contaminate the cache with the wrong height.

[Rule] Any new method added to `TzL2Provider` or `TzChainClient` that exposes "the most recent" checkpoint MUST take a height parameter and return cache-miss on mismatch. There is no `latest()` API by design.

**Module**: `fault-proof/src/tz/l2_provider.rs:58-64`, `fault-proof/src/tz/chain_client.rs:80-99`
**Source**: review-finding F-06 (PRD A-13 §B6, Code Review A-08 R3)
**Date**: 2026-05-19
**Hit count**: 1

## Cache memory bound is semantic, not numeric

[Pitfall] `TzChainClient.cache` is an unbounded `HashMap` — there is no LRU, no TTL, no max-entry cap. It is bounded only by the anchor-driven `evict_below` call at the end of every `sync_state` iteration. In normal operation the active window between `anchor_height` and `confirmed_height` is on the order of tens of checkpoints (each ~80 bytes), so memory is not a concern. The pitfall surfaces if `sync_state` is gutted of its `evict_cache_below` call: cache grows unbounded over the lifetime of the proposer process. Trigger: refactoring `sync_state` to drop the `#[cfg(feature = "tz")]` block at the iteration end. Correct approach: keep the `evict_cache_below(anchor_game.l2_block)` call gated on `if let Some(anchor_game) = ...`; do not introduce an LRU as a "safer" alternative because it would silently drop the active checkpoint when the anchor stalls.

**Module**: `fault-proof/src/proposer.rs:651-663`, `fault-proof/src/tz/chain_client.rs:103-106`
**Source**: review-finding F-04 (PRD A-13 §B6 "缓存内存边界")
**Date**: 2026-05-19
**Hit count**: 1
