# TZ Proposer 资管 refOrderId 反查 — Technical Design

**Date**: 2026-10-14
**Author**: ghost-lookup-barracks-witness (Terran Unit)
**Jira Epic**: [TRDZN-1660](https://okcoin.atlassian.net/browse/TRDZN-1660)
**Target Branch**: `xl/reforder-lookup-early-20261014` (from `xl/tz-dev` @ `635c9155`)

## Intent

资管（Asset Management）需要在 TZ Proposer 发起远程签名时能够回调核对 refOrderId 是否由对应节点近期签发。当前 `xl/tz-dev` 分支缺少独立的资管反查入口。本设计将既有接口及必要的 Proposer 接线独立交付到 `xl/tz-dev`，提供可供资管调用的节点签发记录核验功能。

## Goals

1. **独立反查端点**: 在 Proposer 进程内启动一个轻量 HTTP 服务，提供 `GET /signer/get?refOrderId=<ID>` 端点
2. **复用现有缓存**: 利用 `XLayerRemoteClient` 已有的 `has_ref_order_id()` 方法和 LRU 缓存
3. **可配置 prefix**: 通过环境变量 `XLAYER_SIGNER_REF_ORDER_PREFIX` 配置 refOrderId 前缀，保留 MR !109 的行为
4. **完整 HTTP 契约**: 五类场景（已签发/未命中/缺失参数/空参数/非GET）的精确响应
5. **签名前登记**: 在远程签名 POST 之前，refOrderId 已写入缓存，确保回调在签名返回前可查询

## Non-Goals

- WB 的交易、leaf、proof 查询
- Defender 集成
- MR !102 的其他业务/集成功能
- 无关依赖升级、ELF 产物改动
- 真实资金或链上操作
- MR 合并、部署或发布
- 跨实例共享缓存或持久化

## Anti-Goals (What Would Make This a Failure)

- 引入 MR !102 的 WB pin / alloy 升级或其他超出范围的依赖
- 将反查端点暴露为可公网访问（无鉴权）
- 查询结果被解释为资管授权或链上确认
- 缓存无界增长

## Constraints

1. **Toolchain**: `nightly-2025-09-15` (来自目标 `rust-toolchain.toml`)
2. **依赖基线**: 保持 `xl/tz-dev` 现有依赖版本，不升级
3. **分支隔离**: 独立分支/MR，不合并到 master
4. **无真实交易**: 测试只用 mock 资管，不发起真实资金操作

## Architecture Overview

### Data Flow

```
资管回调 (GET /signer/get?refOrderId=...)
       │
       ▼
┌──────────────────────┐
│  VerifyServer        │  axum HTTP server (new)
│  GET /signer/get     │
│  ┌────────────────┐  │
│  │ has_ref_order_id│  │─── reads ──► LruCache<String, ()>
│  └────────────────┘  │
└──────────────────────┘
       ▲ cache populated by
       │
┌──────────────────────┐
│ XLayerRemoteClient   │  (existing, modified)
│ sign_transaction()   │
│  ┌────────────────┐  │
│  │ generate_ref_   │── writes ──► LruCache<String, ()>
│  │ order_id()      │  │              capacity=1000
│  └────────────────┘  │
└──────────────────────┘
```

### Component Map

| Component | File | Change Type |
|-----------|------|-------------|
| Verify Server | `utils/signer/src/xlayer_verify_server.rs` | **NEW** |
| Remote Client (prefix) | `utils/signer/src/xlayer_remote_client.rs` | MODIFY |
| Signer Lib (startup) | `utils/signer/src/lib.rs` | MODIFY |
| Proposer Entry | `fault-proof/bin/tz_proposer.rs` | MODIFY |
| Signer Cargo | `utils/signer/Cargo.toml` | MODIFY (axum dep) |

## Detailed Design

### 1. Verify Server (`xlayer_verify_server.rs`) — NEW

```rust
/// Axum-based HTTP server that exposes the asset-management refOrderId
/// verification endpoint. Shares the XLayerRemoteClient's ref_order_cache
/// via Arc for lock-free read access.
pub struct VerifyServer {
    client: Arc<XLayerRemoteClient>,
}

impl VerifyServer {
    pub fn new(client: Arc<XLayerRemoteClient>) -> Self { ... }

    /// Starts the server on `addr`. Returns immediately (spawns a tokio task).
    /// If `addr` is empty or "0", the server is NOT started.
    /// Bind failures are logged but do NOT crash the main process.
    pub fn start(self, addr: String) { ... }
}
```

**HTTP Contract**:

| Scenario | HTTP Status | code | msg | detailMsg | data |
|----------|-------------|------|-----|-----------|------|
| ID found in cache | 200 | 0 | success | "" | null |
| ID not in cache | 200 | 1 | not found | "" | null |
| Missing refOrderId param | 400 | 1 | refOrderId is required | "" | null |
| Empty refOrderId param | 400 | 1 | refOrderId is required | "" | null |
| Non-GET method | 405 | 1 | method not allowed | "" | null |

Response JSON shape:
```json
{"status": 200, "code": 0, "msg": "success", "detailMsg": "", "data": null}
```

**Handler logic**:
1. Match on method — only `GET` is accepted, all others return 405
2. Extract `refOrderId` query parameter
3. If absent or empty → 400 + "refOrderId is required"
4. Call `client.has_ref_order_id(&id).await`
5. true → 200 + `{code: 0, msg: "success"}`
6. false → 200 + `{code: 1, msg: "not found"}`

### 2. Configurable Prefix (`xlayer_remote_client.rs`) — MODIFY

**Current state** (line 55):
```rust
const REF_ORDER_ID_PREFIX: &str = "PROPOSER_TZ_";
```

**Target state**:
```rust
/// Read from XLAYER_SIGNER_REF_ORDER_PREFIX env var; fall back to
/// "PROPOSER_TZ_" when unset. Validation: must be non-empty ASCII
/// alphanumeric + underscore only.
fn resolve_ref_order_prefix() -> String {
    let raw = std::env::var("XLAYER_SIGNER_REF_ORDER_PREFIX")
        .unwrap_or_else(|_| "PROPOSER_TZ_".to_string());
    // Validate: non-empty, ASCII alphanumeric + underscore
    if raw.is_empty() || !raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        tracing::error!(prefix = %raw, "XLAYER_SIGNER_REF_ORDER_PREFIX invalid, using default");
        return "PROPOSER_TZ_".to_string();
    }
    raw
}
```

`generate_ref_order_id()` reads the prefix from an instance field (set at construction) rather than a const.

### 3. Signer Wiring (`lib.rs`) — MODIFY

**Add to `XLayerRemoteSigner` variant access**:
```rust
impl Signer {
    /// Returns a reference to the XLayerRemoteClient if this is an
    /// XLayer remote signer; None otherwise.
    pub fn xlayer_client(&self) -> Option<&Arc<XLayerRemoteClient>> {
        match self {
            Signer::XLayerRemoteSigner(client, _) => Some(client),
            _ => None,
        }
    }
}
```

**Add to `SignerLock`**:
```rust
impl SignerLock {
    pub fn xlayer_client(&self) -> Option<Arc<XLayerRemoteClient>> {
        // We can't hold the mutex lock here (would deadlock with signing)
        // Instead, extract the client reference outside the critical section.
        // Since XLayerRemoteClient is behind Arc and the Signer variant
        // is immutable after construction, this is safe.
        // Implementation: read the inner Arc, clone if XLayer variant.
        ...
    }
}
```

**Startup integration** — when `XLAYER_SIGNER_VERIFY_ADDR` is set:
1. After creating the `XLayerRemoteSigner`, extract the `Arc<XLayerRemoteClient>`
2. Create `VerifyServer::new(client.clone())`
3. Call `verify_server.start(addr)`
4. Log success or failure; do NOT crash if bind fails

### 4. Proposer Entry (`tz_proposer.rs`) — MODIFY

In `new_with_l2_provider`, after signer construction:
```rust
// Start verify server if configured
if let Some(client) = signer.xlayer_client() {
    if let Ok(addr) = std::env::var("XLAYER_SIGNER_VERIFY_ADDR") {
        if !addr.is_empty() && addr != "0" {
            let server = xlayer_verify_server::VerifyServer::new(client.clone());
            server.start(addr);
        }
    }
}
```

### 5. Cargo Dependency — MODIFY

Add to `utils/signer/Cargo.toml`:
```toml
axum = { version = "0.7", optional = true }
tokio = { workspace = true, features = ["net", "rt"] }  # already likely present
```

The `axum` dependency is optional, gated behind the existing feature that enables the XLayer remote signer. Since the verify server only runs when the XLayer signer is configured, it can share the same feature gate.

## Configuration Reference

| Env Var | Required | Default | Description |
|---------|----------|---------|-------------|
| `XLAYER_SIGNER_ENABLED` | Yes | `false` | Enable XLayer remote signer |
| `XLAYER_SIGNER_REF_ORDER_PREFIX` | No | `PROPOSER_TZ_` | Prefix for generated refOrderIds |
| `XLAYER_SIGNER_VERIFY_ADDR` | No | (empty) | Listen address for verify server; empty = disabled |

## HTTP Request/Response Examples

### Success case
```
GET /signer/get?refOrderId=PROPOSER_TZ_27_1728912345678_a1b2c3d4 HTTP/1.1
```
```json
{"status":200,"code":0,"msg":"success","detailMsg":"","data":null}
```

### Not found
```
GET /signer/get?refOrderId=UNKNOWN_ID_12345 HTTP/1.1
```
```json
{"status":200,"code":1,"msg":"not found","detailMsg":"","data":null}
```

### Missing parameter
```
GET /signer/get HTTP/1.1
```
```json
{"status":400,"code":1,"msg":"refOrderId is required","detailMsg":"","data":null}
```

### Non-GET method
```
POST /signer/get HTTP/1.1
```
```json
{"status":405,"code":1,"msg":"method not allowed","detailMsg":"","data":null}
```

## Test Strategy

### Unit Tests (in `xlayer_verify_server.rs`)
1. `test_handler_success_when_id_in_cache` — ID found → 200/code 0
2. `test_handler_not_found_when_id_absent` — ID absent → 200/code 1
3. `test_handler_missing_ref_order_id` — no param → 400/code 1
4. `test_handler_empty_ref_order_id` — `?refOrderId=` → 400/code 1
5. `test_handler_non_get_method` — POST/PUT/etc → 405/code 1
6. `test_handler_five_field_contract` — all responses have exactly 5 fields

### Unit Tests (in `xlayer_remote_client.rs`)
1. `test_prefix_from_env` — custom prefix applied
2. `test_prefix_fallback_default` — unset falls back to `PROPOSER_TZ_`
3. `test_prefix_rejects_invalid_chars` — non-ASCII/invalid chars → fallback
4. `test_prefix_rejects_empty` — empty string → fallback
5. `test_cache_eviction_at_capacity` — 1000+1 entries evicts first

### Integration Tests
1. **Mock 资管 callback before POST returns**: Start server, generate refOrderId, query before sign POST completes → 200/code 0
2. **Full binary build**: `cargo build --release --features tz -p fault-proof --bin tz-proposer` exit 0
3. **Process startup**: Launch real binary, probe `GET /signer/get?refOrderId=test` → 200/code 1 (not found, server is alive)
4. **Verify server off when addr empty**: Binary starts but endpoint is not bound

## Verification Acceptance Criteria

| # | Given | When | Then |
|---|-------|------|------|
| AC-1 | ID generated by same client | GET /signer/get with that ID | HTTP 200, code 0, msg=success |
| AC-2 | Never-generated ID | GET /signer/get | HTTP 200, code 1, msg=not found |
| AC-3 | Missing refOrderId param | GET /signer/get (no param) | HTTP 400, code 1, msg=refOrderId is required |
| AC-4 | Empty refOrderId param | GET /signer/get?refOrderId= | HTTP 400, code 1 |
| AC-5 | POST method | POST /signer/get | HTTP 405, code 1, msg=method not allowed |
| AC-6 | 1000 entries inserted | Query original (evicted) ID | HTTP 200, code 1, msg=not found |
| AC-7 | Different client instance | Query ID from other client | HTTP 200, code 1, msg=not found |
| AC-8 | XLAYER_SIGNER_VERIFY_ADDR empty | Start Proposer | No verify server bound |
| AC-9 | Custom prefix "MY_PREFIX_" | Generate refOrderId | ID starts with "MY_PREFIX_" |
| AC-10 | Full release build | cargo build command | Exit code 0 |

## Rejected Alternatives

| Alternative | Reason Rejected |
|-------------|----------------|
| Merge entire MR !102 | Contains WB queries, Defender, unrelated upgrades beyond scope |
| Use existing MR !108 branch directly | !108 is already merged into !102; cannot extract cleanly |
| Persistent DB for refOrderIds | Over-engineered for cache semantics; violates "no new storage" constraint |
| gRPC instead of HTTP | Existing contract is HTTP; axum is lighter for single GET endpoint |
| Share cache across instances (Redis) | Out of scope; per-instance cache is the stated requirement |

## Commit Plan

1. **Commit 1**: Add verify server (`xlayer_verify_server.rs`) + axum dep
2. **Commit 2**: Make prefix configurable in `xlayer_remote_client.rs`
3. **Commit 3**: Wire signer access + startup in `lib.rs`
4. **Commit 4**: Wire proposer entry in `tz_proposer.rs`
5. **Commit 5**: Add unit + integration tests

Total: ≤ 5 commits (within the 5-commit limit)

## Files Changed

| File | Change |
|------|--------|
| `utils/signer/Cargo.toml` | Add axum optional dep |
| `utils/signer/src/xlayer_verify_server.rs` | **NEW** — verify HTTP server |
| `utils/signer/src/xlayer_remote_client.rs` | Configurable prefix |
| `utils/signer/src/lib.rs` | xlayer_client() accessor + verify server startup |
| `fault-proof/bin/tz_proposer.rs` | Wire verify server startup |

## References

- Jira Epic: [TRDZN-1660](https://okcoin.atlassian.net/browse/TRDZN-1660)
- Source reference (verify server): [3a7a6918](https://gitlab.okg.com/github/op-succinct/-/blob/3a7a6918f3a5dda8081aae66b4d1811f7b4cb941/utils/signer/src/xlayer_verify_server.rs)
- Source reference (remote client): [3a7a6918](https://gitlab.okg.com/github/op-succinct/-/blob/3a7a6918f3a5dda8081aae66b4d1811f7b4cb941/utils/signer/src/xlayer_remote_client.rs)
- Original reverse-lookup MR: [!108](https://gitlab.okg.com/github/op-succinct/-/merge_requests/108)
- Prefix config MR: [!109](https://gitlab.okg.com/github/op-succinct/-/merge_requests/109)
- Target baseline: [xl/tz-dev @ 635c9155](https://gitlab.okg.com/github/op-succinct/-/tree/635c9155d2479b971e1812d9e70e46be1da6a89e)
- Signer pitfalls: `context-kg/technical/pitfalls/signer.md`
- XLayer signing flow: `context-kg/technical/core-flows/xlayer-remote-signing.md`