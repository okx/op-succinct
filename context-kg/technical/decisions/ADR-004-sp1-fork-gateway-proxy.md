---
name: "ADR-004-sp1-fork-gateway-proxy"
description: "ADR: 全量 patch sp1/slop crates 指向 OKX fork 以支持 gateway proxy"
---

# ADR-004: SP1 Fork 策略（Gateway Proxy）

## Status

Accepted

## Context

OKX 生产环境运行在受限网络中（防火墙、NAT、代理层）。原版 SP1 集群需要直连 gRPC 和 HTTP 端点，无法通过 API 网关（APISIX）路由。

需要修改 `sp1-sdk` 以支持 `SP1_GATEWAY_HOST` 环境变量，将所有集群请求路由到网关并附加认证中间件。

## Decision

**所有 sp1-* 和 slop-* crate 必须打 patch 指向 OKX fork: `github.com/okx/sp1#feat/gateway-proxy-v6.1.0`。**

Cargo.toml `[patch.crates-io]` 中共 patch 了 **46 个 crate**（sp1-sdk、sp1-prover、slop-basefold 等全部依赖）。此规则在 `knowledge-base.md` 和 `pitfalls/dependencies.md` 中以 [Rule] 标记强制执行。

**为什么需要 patch 所有 crate？** Hokulea（EigenDA 验证库）传递依赖 `sp1-primitives`、`sp1-hypercube` 和多个 `slop-*` crate。如果仅 patch `sp1-sdk`，会出现同一 crate 的两个版本（git vs crates.io），导致链接错误和版本冲突。

## Alternatives Considered

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| 上游 PR 合并 | 无需维护 fork | 上游不一定接受 OKX 特定需求 | 长期目标，短期不可行 |
| 仅 patch sp1-sdk | 改动最小 | 传递依赖冲突（hokulea） | **否决** |
| 全量 patch | 版本一致；无冲突 | 维护成本高；每次 SP1 升级需 rebase | **采纳** |
| HTTP 代理层 | 不修改代码 | gRPC 代理配置复杂；无法在 SDK 层注入认证 | **否决** |

## Consequences

- **正面**: 生产环境可通过 gateway 访问 SP1 集群
- **负面**: 每次 SP1 上游升级（如 v6.1.0 → v6.2.0）需要 rebase fork 分支；移除任何 patch 会立即破坏生产集群网关认证
- **中性**: 开发者必须使用 fork 分支或共享 staging 环境
