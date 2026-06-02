# Tradezone op-succinct 测试报告

## 1. 术语

| 术语 | 描述 |
|---|---|
| op-succinct | 基于 SP1 zkVM 的 OP Stack 链 fault-proof 方案 |
| Range guest | 单个区间的 zkVM 程序，证明 N 个区块 replay 的状态转换 |
| Aggregation guest | 把多段 range proof 聚合成单个 proof |
| DexState | tradezone 的应用状态（含订单簿、持仓、预测市场等） |
| Proposer | 提交 output root → 请求/聚合 proof → 上链的服务 |
| Challenger | 当 proposer 作恶或故障提交错误 output root 时发起挑战的服务 |
| SP1 cluster | 自部署的 SP1 prover 集群 |
| SP1 Network | Succinct Labs 托管的 prover 网络 |
| Snapshot-replay | tradezone 节点缺指定高度 DexState 时，从历史 snapshot + 区块 replay 还原 |

## 2. 背景

需要为 tradezone 实现一套基于 op-succinct 的挑战证明机制。tradezone 不使用以太坊做 DA，因此不会向以太坊提交 batch 数据，与通用 OP 链的主要差异：

- 无 L1 DA：boot info 中 `l1Head` 与 `rollupConfigHash` 强制为 0
- 应用状态用 DexState（msgpack 序列化）
- Proposer 向 tradezone 节点拉指定高度 DexState；节点缺该高度时按需做 snapshot-replay 还原

上线前需评估系统功能完备性、性能可承载能力与持续运行稳定性，组织本次测试。

## 3. 测试目标

- **核心功能**：验证 e2e 难覆盖但属于卡点的功能项
- **性能**：在不同 TX 密度与 DexState 大小下量化 proof 生成耗时，给出 `PROPOSAL_INTERVAL` 与并行度的选择依据
- **稳定性**：在贴近 prod 配置的负载下，验证系统能否长时间稳定产 proof

## 4. 核心功能测试

| # | 测试项 | 测试结果 |
|---|---|---|
| F1 | 全交易类型冒烟出 proof（复用 tradezone 冒烟场景跑通 range + agg proof） |  |
| F2 | Aggregation 单 range / 多 range 都跑通 |  |
| F3 | Proof mode 双跑通（plonk + groth16） |  |
| F4 | mock / local cluster / SP1 network 都跑通 |  |
| F5 | 5G DexState + 30k blocks 单段 range 跑通 |  |
| F6 | 大 gap snapshot-replay（从老 snapshot + 区块回放还原 `DexState@N`） |  |

## 5. 性能测试

### 5.1 测试方法

构造不同 TX 数量与 DexState 大小的组合，通过 sp1-cluster bench（compressed proof）跑单段 range proof，记录 total instructions 与端到端 proof 耗时。

**测试环境**：64 core / L20 × 4 / 500GB RAM，SP1 v6.1.0。

### 5.2 测试数据

| 用例 | TX | DexState | Instructions (G) | Proof 耗时 |
|---|---|---|---|---|
| C1 | 30k | 100MB | 20.42 | 1330s（实测） |
| C2 | 60k | 100MB | 24.80 | ~1620s |
| C3 | 90k | 100MB | 29.23 | ~1910s |
| C4 | 30k | 200MB | 31.44 | ~2050s |
| C5 | 30k | 300MB | 41.80 | ~2730s |

### 5.3 结论

- 每 5000 笔交易 proof 耗时约 48 秒
- DexState 每 100MB 额外增加约 720 秒

按此估算，5GB DexState + 36000 个区块（每区块 5000 笔交易）单段 range proof：

- 交易耗时：36000 × 48s ≈ 480 小时
- DexState 耗时：5120 × 7.2s ≈ 10 小时
- **合计约 490 小时（约 20 天）**

## 6. 稳定性测试

### 6.1 测试配置

| 项 | 值 |
|---|---|
| TX 密度 | 50 笔/block |
| Proposal 间隔 | 600 blocks/game |
| 挑战频率 | 1 challenge / 10 games |
| 持续时长 | 16 小时（仍在持续运行中） |

### 6.2 结论

可以持续正常生成 proof。
