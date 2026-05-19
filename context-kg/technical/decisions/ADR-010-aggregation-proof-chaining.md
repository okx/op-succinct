---
name: "ADR-010-aggregation-proof-chaining"
description: "ADR: 线性聚合证明设计 — 在 zkVM 内验证 SNARK 链 + L1 header 反向遍历 + L2 连续性断言"
---

# ADR-010: 聚合证明链设计

## Status

Accepted

## Context

单个范围证明验证一段连续区块的状态转换。要在 L1 上验证整个区间，如果逐个提交范围证明，gas 成本与证明数量成正比 O(N)。需要将 N 个范围证明压缩为 1 个链上可验证的聚合证明。

## Decision

**聚合证明在 zkVM guest（`programs/aggregation/src/main.rs`）中验证每个范围证明的 SNARK，反向遍历 L1 header 链，并断言 L2 状态连续性。**

核心流程：
1. 验证每个 BootInfo 的范围证明: `sp1_lib::verify_sp1_proof(multi_block_vkey, sha256(boot_info))`
2. 断言连续性: `prev.l2PostRoot == curr.l2PreRoot`
3. 反向遍历 L1 headers: 验证 hash 链
4. 确认所有 `boot_info.l1Head` 存在于 L1 header 链中
5. 输出合并的 `AggregationOutputs`（首个 l2PreRoot 到最后一个 l2PostRoot）

```
Range Proof 1 (blocks 0-10)  ─┐
  l2PreRoot=A, l2PostRoot=B    │
                                ├─→ Aggregation Proof
Range Proof 2 (blocks 11-20) ─┤    Output: l2PreRoot=A
  l2PreRoot=B, l2PostRoot=C    │           l2PostRoot=C
                                │           l1Head=latest
L1 Header Chain ──────────────┘
```

**关键踩坑点**（修改此程序前必须了解）：
- L2 区块跳跃（如 [0-10] → [15-20]，跳过 11-14）导致 `l2PostRoot` 断言失败
- 范围证明使用不同版本的 `multi_block_vkey` 会导致验证失败
- L1 header 链必须由 host 端完整收集并传入（zkVM 内无法派生）
- 混合不同证明模式（如 Core + Compressed）会导致 guest 验证失败

详细流程见 `core-flows/aggregation-proof.md`，模块设计见 `modules/programs-aggregation.md`。

## Alternatives Considered

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| 逐个提交范围证明 | 实现简单 | gas 成本 O(N)；不可扩展 | **否决** |
| 递归聚合（树形） | 并行化潜力 | 实现复杂；需要中间证明层 | 未来可能 |
| 线性聚合（当前） | 实现清晰；验证链简单 | 聚合时间 O(N)；需完整 L1 header 链 | **采纳** |

## Consequences

- **正面**: 将 N 个范围证明压缩为 1 个，显著降低 L1 验证 gas 成本
- **负面**: Guest 程序逻辑复杂，小错误会静默破坏证明；Range 和 Aggregation 必须使用相同 `multi_block_vkey`（版本耦合）
- **中性**: L1 header 链需要 host 端完整收集并传入（增加见证生成复杂度）
