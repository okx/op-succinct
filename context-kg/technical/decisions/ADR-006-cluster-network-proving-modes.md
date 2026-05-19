---
name: "ADR-006-cluster-network-proving-modes"
description: "ADR: 同一二进制支持 Network 和 Cluster 两种证明模式，通过 SP1_PROVER 环境变量切换"
---

# ADR-006: Cluster 与 Network 双证明模式

## Status

Accepted

## Context

SP1 提供两种证明服务模式：
- **Network**: Succinct 官方证明网络，按市场拍卖定价
- **Cluster**: 自建集群，使用 SP1 集群 gRPC 服务

不同部署场景对成本、延迟和数据主权有不同要求。

## Decision

**同一二进制同时支持 Network 和 Cluster 两种证明模式，通过 `SP1_PROVER` 环境变量切换。**

```rust
// utils/proof/src/lib.rs
pub fn is_cluster_mode() -> bool {
    std::env::var("SP1_PROVER").unwrap_or_default() == "cluster"
}
```

两种模式使用不同的数据库字段追踪状态：
- Network: `proof_request_id` (B256)
- Cluster: `cluster_proof_handle` (JSONB: `{proof_id, proof_output_id}`)

fault-proof 服务中通过 `ProofProvider` enum（`fault-proof/src/prover.rs`）统一分发：`Network | Mock | Cluster`。

## Alternatives Considered

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| 仅支持 Network | 实现简单 | 无法自托管；按量付费成本高 | **否决** |
| 仅支持 Cluster | 自主可控 | 失去社区验证网络的灵活性 | **否决** |
| 双模式同二进制 | 灵活切换；统一运维 | 双代码路径；DB schema 更复杂 | **采纳** |
| 编译时选择模式 | 精简二进制 | 运营方需要两套构建；切换需重编译 | **否决** |

## Consequences

- **正面**: Cluster 模式消除按次计费，适合高频证明场景
- **负面**: DB schema 需同时容纳两种字段（migration `04_add_cluster_proof_handle.sql`）；两种模式间无自动故障转移
- **中性**: 切换模式需修改环境变量并重启服务（无运行时热切换）
