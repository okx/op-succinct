---
name: "tz-binaries"
description: "Pitfalls for tz-proposer / tz-challenger binaries — env-var coupling with shared host fetcher, unsafe set_var ordering"
---
# tz Binary Pitfalls

Pitfalls specific to `fault-proof/bin/tz_proposer.rs` and `fault-proof/bin/tz_challenger.rs`. These binaries are gated by `required-features = ["tz"]` and reuse most of the xlayer pipeline; the gotchas below come from places where reuse meets divergence.

## L2_NODE_RPC required even though the value is never consumed

[Pitfall] `fault-proof/bin/tz_proposer.rs`, `fault-proof/bin/tz_challenger.rs` call `OPSuccinctDataFetcher::new()`, which delegates to `utils/host/src/fetcher.rs::get_rpcs_from_env()`. That function calls `env::var("L2_NODE_RPC").expect("L2_NODE_RPC must be set")` and `Url::parse(...).expect(...)` at startup — **before** any tz-specific cfg branch runs. If the operator forgets to set `L2_NODE_RPC` in `.env.tz-proposer` / `.env.tz-challenger`, the binary panics during construction with a confusing message: the value is never used on the tz path because `OPSuccinctDataFetcher::new()` only validates URL parseability and never performs L2 RPC. Trigger: tz binary `.env` file pre-fills `L2_RPC` only (the documented tz variable). Correct approach: pre-set `L2_NODE_RPC` from inside the binary alongside `L2_RPC` so the operator only sees one variable in the runbook:

```rust
// fault-proof/bin/tz_proposer.rs (and tz_challenger.rs)
unsafe {
    env::set_var("L2_RPC", &tz_config.rpc_urls[0]);
    env::set_var("L2_NODE_RPC", &tz_config.rpc_urls[0]);
}
```

[Rule] Any future tz binary that calls `OPSuccinctDataFetcher::new()` must satisfy `get_rpcs_from_env()` — it requires both `L1_RPC` and `L2_NODE_RPC` to be set and parseable as `Url`, even when the resulting providers are never consumed. Reuse path: do not duplicate `OPSuccinctDataFetcher`, mirror the `env::set_var` workaround.

**Module**: `fault-proof/bin/tz_*.rs`, `utils/host/src/fetcher.rs:98-118`
**Source**: review-finding F-01 (Code Review A-08 M1, Adversarial Review A-15 N1)
**Date**: 2026-05-19
**Hit count**: 1

## OPSuccinctDataFetcher::new() vs new_with_rollup_config()

[Rule] tz binaries must use `OPSuccinctDataFetcher::new()`, **NOT** `new_with_rollup_config()`. The former (`utils/host/src/fetcher.rs:141-157`) only validates env vars and constructs lazy `ProviderBuilder` providers — zero HTTP traffic at startup. The latter issues a JSON-RPC call to fetch the rollup config from the L2 node, which tz nodes do not support (tz exposes only the REST `/chain/confirmed_block_info` endpoint, not standard OP Stack RPC). Reason: AC-9.4 ("zero L2 JSON-RPC at construction") is preserved by the no-RPC variant; using `new_with_rollup_config()` would crash on the first call against a tz endpoint that rejects `eth_*` methods. The `rollup_config_hash` for tz is read from L1 instead via `factory.game_impl(game_type).rollupConfigHash().call()` inside `tz/proposer.rs::new_with_l2_provider`.

**Module**: `fault-proof/src/tz/proposer.rs:53-129`, `fault-proof/bin/tz_proposer.rs`
**Source**: review-finding F-07 (Code Review A-08 R4, Adversarial Review A-15 — DM-9.7)
**Date**: 2026-05-19
**Hit count**: 1

## unsafe { env::set_var } must run before tokio runtime construction

[Pitfall] `tz_proposer.rs` and `tz_challenger.rs` call `unsafe { env::set_var("L2_RPC", &tz_config.rpc_urls[0]) }` from `main()` to bridge the tz-specific `L2_RPC` (REST URL list) into the shared `ProposerConfig::from_env()` path that expects a single URL. As of Rust 1.91 `env::set_var` is `unsafe` because it is unsound across threads with concurrent reads. Trigger: refactoring the binary to do env munging from inside `tokio::main` or a spawned task. Correct approach: keep the `set_var` call in synchronous `main()`, before `tokio::runtime::Builder::new_multi_thread().build()` — at that point only the main thread exists and no concurrent reader can race the writer. The `// SAFETY:` comment must explicitly state this ordering invariant so a future maintainer cannot move the call into an async context without noticing.

**Module**: `fault-proof/bin/tz_proposer.rs`, `fault-proof/bin/tz_challenger.rs`
**Source**: review-finding F-08 (Code Review A-08 R4, TD §7 row 11)
**Date**: 2026-05-19
**Hit count**: 1
