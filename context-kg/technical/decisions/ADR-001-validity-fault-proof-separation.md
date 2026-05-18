---
name: "ADR-001-validity-fault-proof-separation"
description: "ADR: validity 与 fault-proof 必须作为独立服务，禁止互相依赖"
---

# ADR-001: Validity 与 Fault-Proof 服务分离

## Status

Accepted

## Context

OP Succinct 支持两条完全独立的 L1 合约路径来提交证明：

1. **Validity (L2OutputOracle)** — 有效性证明路径，proposer 循环提交状态根（`validity/src/contract.rs` → `OPSuccinctL2OutputOracle`）
2. **Fault Proof (DisputeGameFactory + FaultDisputeGame)** — ZK 故障证明路径，通过链上博弈树管理争议（`fault-proof/src/contract.rs` → `DisputeGameFactory`, `OPSuccinctFaultDisputeGame`, `AnchorStateRegistry`）

两者的智能合约接口、操作流程（循环提交 vs 博弈树管理）和安全模型完全不同。

## Decision

**validity 和 fault-proof 必须作为两个完全独立的服务存在，彼此之间不得有 Cargo 依赖。**

- `validity/Cargo.toml` 不得引用 `fault-proof` 中的任何 crate
- `fault-proof/Cargo.toml` 不得引用 `validity` 中的任何 crate
- 两者共享底层工具库（`utils/proof`, `utils/signer`, `utils/host`），但不共享业务逻辑

此规则在 `knowledge-base.md` 中以 [Rule] 标记强制执行。

## Alternatives Considered

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| 合并为单一服务 | 减少部署组件 | 操作流程完全不同；耦合增加维护和测试复杂度 | **否决** |
| 独立服务 + 共享工具库 | 关注点分离；独立部署和扩缩容；测试隔离 | 部分工具代码存在轻微重复 | **采纳** |

## Consequences

- **正面**: 可独立部署、独立测试、独立扩缩容
- **负面**: 运营方如果两条路径都要支持，需同时运行两个服务
- **中性**: 共享工具库的变更可能同时影响两个服务，需协调测试
