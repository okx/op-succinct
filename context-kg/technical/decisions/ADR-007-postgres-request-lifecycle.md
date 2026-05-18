---
name: "ADR-007-postgres-request-lifecycle"
description: "ADR: 使用 PostgreSQL + sqlx 持久化证明请求生命周期和链锁协调"
---

# ADR-007: PostgreSQL 管理请求生命周期

## Status

Accepted

## Context

Proposer 服务需要：
- 在崩溃后恢复正在进行的证明请求（集群证明可能耗时数小时）
- 可查询的审计跟踪（指标、调试、合约提交状态）
- 多实例协调（防止多个 proposer 同时证明相同区间）

## Decision

**使用 PostgreSQL + sqlx 持久化证明请求生命周期，使用行级链锁防止并发冲突。**

请求状态机: `Unrequested → WitnessGeneration → Execution → Prove → Complete → Relayed`（另有 `Failed` / `Cancelled` 终态）

追踪的关键字段：`req_type` (Range/Aggregation), `mode` (Real/Mock), `proof` (BYTEA), `relay_tx_hash`, 及各阶段耗时。

链锁机制（`validity/src/db/client.rs` 的 `add_chain_lock()` 方法）：

```sql
INSERT INTO chain_locks (l1_chain_id, l2_chain_id, locked_at)
VALUES ($1, $2, NOW())
ON CONFLICT (l1_chain_id, l2_chain_id) DO UPDATE SET locked_at = NOW()
```

数据库连接在 `DriverDBClient::new()` 中建立，迁移自动运行（`sqlx::migrate!("./migrations")`）。当前有 4 个迁移文件（`validity/migrations/`）。

## Alternatives Considered

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| Redis | 低延迟；适合缓存 | 非持久（断连即丢失状态）；证明可能耗时 6+ 小时 | **否决** |
| 纯内存 | 零外部依赖 | 崩溃即丢失；多实例无法共享 | **否决** |
| PostgreSQL + sqlx | ACID 事务；SQL 查询；JSONB 支持；成熟运维工具 | 额外运维依赖 | **采纳** |

## Consequences

- **正面**: 崩溃恢复、多实例协调、可查询审计
- **负面**: 部署 proposer 必须同时部署 PostgreSQL；schema 变更需编写迁移
- **中性**: 连接池化降低了 DB 延迟影响
