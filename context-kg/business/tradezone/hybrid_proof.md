---
name: "hybrid_proof"
description: "TradeZone ZK Proof 证明基座：TEE+ZK 混合证明架构、挑战-响应时序、模块设计、协议定义、两期建设路线"
source: "https://okg-block.sg.larksuite.com/wiki/YCaxwpBqMi1StekDE9YlfySfg4j"
---

# TradeZone ZK Proof 证明基座

## 背景

TradeZone 当前采用 TEE（可信执行环境）作为链下执行结果的证明机制。为进一步提升可验证性与去信任化程度，计划引入 ZK 证明，升级为 **TEE + ZK 混合证明**架构。

核心参考：[TZ ZK Proof - PRD](https://okg-block.sg.larksuite.com/wiki/UTWNwKpMgiwcGUkAezZlil8vgsd)

## 关键概念

| 术语 | 说明 |
|------|------|
| **App Hash** | 全量 DexState 计算出的 Hash 值，每 2000 个 Block 计算一次 |
| **State Root** | Merkle Root Hash，每个 Batch（36000 个 Block）计算一次，提交到 L1；Witness Builder 和 Guest Client 都会计算 |
| **Snapshot** | DexState 快照，每 10000 个 Block 落盘一次 |
| **Batch** | 36000 个 Block，ZK 证明的基本粒度单元 |
| **Guest Client** | 运行在 SP1 ZKVM 中的代码实例，输入 Batch + DexState + App Hash，输出 ZK Proof |

## 数据流规格

| 模块 | 输入 | 输出 |
|------|------|------|
| **Sequencer** | Block | App Hash、DexState |
| **Witness Builder** | Batch（36000 Block） | Batch、DexState（第一期全量 / 第二期命中部分）、App Hash（第二期改为 State Root） |
| **Guest Client** | Batch（36000）、DexState、App Hash（第二期改为 State Root） | ZK Proof |

## 系统架构

组件分布：

```
[ Ethereum ]
  Dispute Contracts

[ L2 ]
  L2 Sequencer
  RPC

[ Proving Service ]
  Proposer
  Witness Builder
  ZK Prover

[ 外部 ]
  Challenger
```

带编号的数据流（对应时序步骤）：

```
1. L2 Sequencer → RPC            执行&同步 block
   L2 Sequencer → Witness Builder 同步 block

2. Witness Builder → Proposer    轮询 block 和 latest state root

3. Proposer → Dispute Contracts  提交世界状态 Hash，等待被挑战
   RPC → Challenger               同步区块

4. Challenger → Dispute Contracts 发起挑战（按需）

5. Proposer ← Dispute Contracts  监听到被 Challenge

6. Proposer → Witness Builder    请求获取 Witness

7. Proposer → ZK Prover          generate proof

8. Proposer → Dispute Contracts  提交 proof，Resolve Challenge
```

## 挑战-响应时序

### 阶段 1：链的执行与同步

1. Sequencer 执行区块：`process_block(old_state, block_batch) = new_state`
2. Sequencer 同步区块到 RPC
3. Sequencer 同步区块到 Witness Builder
4. RPC 同步区块到 Challenger

### 阶段 2：提案提交

1. Proposer 请求 Witness Builder 获取最新区块执行结果
2. Witness Builder 返回 `process_block(old_state, block_batch)` 的结果 `new_state`
3. Proposer 向 L1 提交提案（`process_block(old_state, block_batch) = new_state`）并缴纳提案押金
4. L1 登记提案，开始等待挑战期

### 阶段 3：发起挑战

1. Challenger 本地计算 `new_state' ≠` 链上声明 `new_state`，认定提案错误
2. Challenger 向 L1 发起挑战，缴纳挑战押金
3. L1 提案进入被挑战状态，重置证明截止时间

### 阶段 4：提交零知识证明

1. Proposer 检测到提案被挑战，开始生成证明
2. Proposer 请求 Witness Builder 生成 Witness
3. Witness Builder 返回 Witness：`part of old_state` + `block_batch` + `old_state_root`
4. Proposer 携带 Witness 请求 ZK Prover 生成证明
5. ZK Prover 返回证明
6. Proposer 向 L1 提交 ZK 证明，参数：
   - 1st block hash of block_batch
   - last block hash of block_batch
   - state root of old_state
   - state root of new_state
   - last block height of block_batch
7. L1 调用 verify 函数（参数同上）

### 结算逻辑

| 结果 | 触发条件 | 处理 |
|------|---------|------|
| **Proposer 胜出** | 证明有效 | Proposer 申请结算；挑战押金归 Proposer；L2 最新可信状态更新为 new_state |
| **Challenger 胜出** | 截止时间到仍无有效证明 | Challenger 申请结算获得提案押金；Proposer 告警暂停，人工介入排查修复后重启，评估影响补偿用户 |

## 模块设计

| 模块 | 功能 |
|------|------|
| **Dispute Contracts** | 记录提案；接受挑战；验证证明；记录 L2 链状态（最新块高和 Root） |
| **ZK Program** | 运行在 ZKVM 里的 program，定义 Sequencer 执行区块的逻辑和证明生成方式 |
| **Proposer** | **提案管理**：同步合约提案；创建新提案（从 Witness Builder 获取最新块高和 Root，找到 parent 提案后创建）；结束提案（resolve/claimCredit）。**应对挑战**：监听挑战事件；调用 Witness Builder 生成 Witness；用 Witness 调用 Prover 生成 Proof；发送 Proof 交易到 L1 |
| **Witness Builder** | 同步 L2 Sequencer 区块；提供 RPC 接口让 Proposer 查询最新块高和 Hash；提供 RPC 接口响应 Proposer 的 Witness 生成请求 |
| **ZK Prover** | 响应 Proposer 的 Proof 生成请求；提供 SP1 host server 供 Proposer 调用（参考 [sp1-cluster](https://github.com/succinctlabs/sp1-cluster)） |

## 协议定义

### Dispute Contracts

合约需定义：
1. **创建 game 字段**：extraData 的数据结构与编码方式
2. **证明验证逻辑**：验证证明所需的数据与编码方式

### ZK Program

需定义：
1. **Program 的输入输出**
2. **证明所需数据与计算方法**（须与合约验证逻辑保持一致）

### Witness Builder RPC

| 接口 | 说明 |
|------|------|
| 查询最新块高 + App Hash | 推荐使用 `/v1/chain/confirmed_block_info` |
| Witness 生成请求 | 响应 Proposer 发起的 Witness 构建请求 |

### ZK Prover

Proposer 配置项需支持使用自定义 SP1 host server（Local SP1 VM 或 Cloud SP1 VM）。

## 两期建设路线

### 第一期

目标：以全量 DexState 作为 App Hash 输入，完成基础 ZK 证明生成与挑战机制。

| 任务 | 说明 |
|------|------|
| Process Block 代码拆分 | 将 Process Block 拆成可被直接调用的 package |
| Proposer 改造 | Rust 版本替换；Dispatcher 支持分发到 Cloud SP1 或 Local SP1 |
| ZK Witness Builder | 以全量 DexState 作为输入转发给 SP1；同步 Block 作为 SP1 的 input；逻辑内置于 RPC 节点 |
| L1 合约支持 | 新增 TZ ZK game type 支持 |
| Guest Client | 依赖 Process Block 代码拆分；可在 SP1 ZKVM 中运行并生成 Proof 通过验证 |
| 完整性测试 | Fuzz 测试，所有交易的 happy path 在 ZKVM 中运行一遍 |
| Game Attribution | Finalize 时间：1 天 |
| Local SP1 VM | 提供 SP1 host server 供 Proposer 调用 |

### 第二期

目标：引入 Merkle Tree 计算 State Root，完善 TEE 兜底与挑战治理机制。

| 任务 | 说明 |
|------|------|
| ZK Proof 生成失败 case 处理 | 极端情况下 ZK Proof 无法生成时，TEE 兜底或 Security Council 治理 |
| 挑战 & 治理机制设计 | Batch 押金金额；挑战者成功收益设计 |
| ZK Witness Builder 增加 Merkle Tree 计算逻辑 | 对输入 DexState 做 state root 计算并校验；执行结束后构造 Merkle Tree 计算 Root Hash |
| Local replay check | Sequencer + Witness Builder |
| 量化 State Root 与 App Hash 计算性能差距 | 为升级决策提供数据 |
| TEE 增加 Merkle Tree 计算逻辑 | TEE 路径对齐 ZK 路径 |
| 在 RPC 节点上增加 getMerkle proof 接口 | — |
| Prover 性能优化 | — |
| 加强完整性测试 | Fuzz 测试，所有代码逻辑分支在 ZKVM 中运行一遍 |
| 解决 Batch 必须以万为整数倍的限制 | — |
| Multi Prover（Local + Cloud） | — |
| Prove range 优化 | 从指定 Batch 细化到指定 Block |

> TODO：考虑 TEE 实现和 ZK 共用同一套 Proposer/Challenger 代码
