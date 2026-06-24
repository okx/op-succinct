# Calldata-Eager Segment Dispute Game Spec

> **Scope**: TradeZone (tz) chain 上的 fault-proof dispute protocol（calldata DA 变体）
> **基础**: 在现有 OP-stack fault-proof 基础设施之上演进；**不改造**任何 L1 系统合约（`DisputeGameFactory` / `AccessManager` / `AnchorStateRegistry` / `SP1VerifierGateway`），也**不新增 game type 数字**——复用 TZ 现有的 `TZ_FAULT_GAME_TYPE` slot，通过 `factory.setImplementation` 切换 impl。
>
> **核心设计要点**：
> - **CWIA-eager commit**：proposer 在 `create()` 时即通过 CWIA extraData 提交全 batch 的 `numSegments - 1` 个 intermediate segment hash
> - **Per-game variable batchSize + numSegments**：proposer 在 create 时自主决定 batch 范围与段数；合约层只约束 `1 ≤ numSegments ≤ MAX_NUM_SEGMENTS` 和 `batchSize % numSegments == 0`
> - **SEGMENT_SIZE 派生（不存 storage）**：`SEGMENT_SIZE = batchSize / numSegments`，纯 view derive
> - **State machine 4 态**：`Unchallenged / Challenged / UnchallengedAndValidProofProvided / Resolved`（UnchallengedAndValidProofProvided 通道见 §6 Phase 3.5 早 finalize）
> - **challenge + counter 合一**：单一 `challenge(k)` 函数
> - **L bond 即时 push**：prove Step 3 发放给 prover，resolve 不再遍历
> - **`prove(bytes)` 早 finalize 通道**（可选）：无 challenger 时一次性证明全 batch，跳过 challenge 窗口等待
> - **零 blob 依赖、零 KZG 验证**：intermediate roots 全程走 CWIA immutable args，链上直接 SLOAD-级读取

---

## 一、协议目标

把 OPSuccinct 现有的 "batch-level zk aggregation" dispute 替换为：

- **CWIA-eager DA commit**：proposer 在 `create()` 阶段就把全 batch 的 `numSegments - 1` 个 intermediate segment hash 通过 CWIA extraData 上链——immutable args 永久存储，零 retention 焦虑
- **per-game variable batch size + segment size**：`batchSize` 与 `numSegments` 均由 proposer 在 create 时自主决定；合约约束 `1 ≤ numSegments ≤ 256` 与 `batchSize % numSegments == 0`，单 game `SEGMENT_SIZE = batchSize / numSegments` 派生
- **segment-level dispute**：被挑战时只 prove 单个 segment（`SEGMENT_SIZE` blocks）的 STF 有效性
- **permissionless multi-challenger**：任何人都能 challenge 任意 segment，每地址至多 counter 1 段、每 segment 至多被 1 个 challenger counter

### 关键属性

- **DA 永久可访问**：intermediate roots 在 CWIA immutable args 中永久存储，game 生命周期内任何时刻可读（无 blob 18-day retention 风险）
- **零 KZG / 零 blob fee**：proposer 用普通 tx 提交 game，避免 EIP-4844 独立 fee market 的不确定性
- **链上交互极简**：每个 game 仅 `create` / `challenge(k)` / `prove(k, ...)` / `resolve()` 四个生命周期入口

### 复杂度

- **Interactive rounds**: O(1)
- **Prover work**: O(batchSize) on optimistic path（生成 intermediate roots 时 replay 全 batch），O(|D|) on dispute path（|D| = 被挑 segment 数）
- **On-chain proof calldata**: O(1) per disputed segment（仅 1 个 SP1 proof，无 KZG opening）
- **On-chain DA per create**: `36 + 32 × (numSegments - 1)` bytes calldata（典型 N=200 → ~6.4 KB；上限 N=256 → ~8.2 KB）

### 协议本质

> **CWIA-Eager Segment-Level Multi-Challenger Dispute Game**

### 与 blob 变体的关系

本 spec 与 `SPEC_GAME_V2.md`（blob 变体）共享同一状态机、同一 bond 经济模型、同一 dedup 规则、同一 first-mismatch winner-takes-all 设计、同一 resolve 与 claimCredit 流程。**唯一结构差异**：

| 维度 | Blob 变体（V2） | Calldata 变体（本 spec） |
|---|---|---|
| Intermediate roots DA | EIP-4844 blob + KZG commitment | CWIA extraData (immutable args) |
| Prove path 校验 claimPre/Post | KZG opening (precompile 0x0A) × 2 | 直接 SLOAD-级 CWIA 读 × 2 |
| `SEGMENT_SIZE` | 合约层 constant = 10 | per-game variable (`batchSize / numSegments`) |
| 适用 N 上限 | 4096（blob 容量） | 256（calldata cost） |
| Roots retention | 18 days (blob)，PeerDAS 后可能更短 | 永久（CWIA immutable args） |
| 提交 tx 类型 | Type-3（含 blob sidecar） | 普通 tx |

定位：**Calldata 变体适用于生产正常吞吐场景**（TZ 现实负载、XLayer 1s 出块），blob 变体保留用于极端吞吐场景。两份 spec 独立，部署时根据链特性选择。

---

## 二、部署架构与角色

### 2.1 多链共享 L1 基础设施

沿用 OP-stack 标准：`DisputeGameFactory` / `SP1VerifierGateway` 跨链共享；`AccessManager` / `AnchorStateRegistry` 每链一个；`TZ_FAULT_GAME_TYPE` slot 通过 `setImplementation` 切换 impl 完成 TEE → 当前协议升级。

### 2.2 角色与信任假设

| 角色 | 数量 | 信任假设 |
|---|---|---|
| **Proposer** | 1 per game | untrusted |
| **Challenger** | 0..numSegments-1 permissionless | **1-of-N honest 假设**：至少一个诚实 challenger 能在 `MAX_CHALLENGE_DURATION` 窗口内 select 真 mismatch。诚实 challenger 应：(1) 使用 MEV-protected mempool；(2) 本地 replay batch STF 找 first-mismatch |
| **Prover** | 0..numSegments permissionless | untrusted；prove 路径 frontrun 防护通过 `proverAddress` 进 zk public input 实现 |
| 其他系统合约 | — | 沿用 OP-stack 标准 |

**信任简化点**：与 blob 变体不同，本 spec 下 challenger 客户端**不需要连接 beacon node / archive EL client / 第三方 blob indexer**——所有 intermediate roots 在 L1 合约 storage 即可直读（CWIA immutable args 通过 `intermediateRoot(k)` getter 暴露）。

---

## 三、术语与编码

### 3.1 协议参数

| 参数 | 类型 / 值 | 备注 |
|---|---|---|
| `MAX_NUM_SEGMENTS` | `uint64 constant = 256` | 合约层编译期常量；intermediate roots 数量上限，受 calldata cost 实操约束（部署 game 时 8 KB extraData，~$2-10 gas 量级） |
| `MAX_CHALLENGE_DURATION` | `Duration immutable`（典型 1 day） | constructor 注入 |
| `MAX_PROVE_DURATION` | `Duration immutable`（典型 1 day） | constructor 注入 |
| `batchSize` | `uint64 storage` (per-game) | initialize 时计算 = `l2SequenceNumber() - startingOutputRoot.l2SequenceNumber`；约束：`batchSize > 0 ∧ batchSize % numSegments == 0` |
| `numSegments` | `uint64 storage` (per-game) | initialize 时从 CWIA extraData 长度反推；约束：`1 ≤ numSegments ≤ MAX_NUM_SEGMENTS`（下界允许 N=1 退化为 single-batch 模式） |
| `SEGMENT_SIZE` | view derive (per-game) | = `batchSize / numSegments`；**不存 storage**，调用方按需 derive |
| `numIntermediateRoots` | 派生 | = `numSegments - 1`（端点不计入；详见 §3.4） |

> **理论 vs operational 上限**：
> - **理论上限** `numSegments ≤ 256` —— calldata cost 软约束（8 KB extraData）
> - **operational ceiling 进一步取决于** challenger 在 `MAX_CHALLENGE_DURATION = 1d` 窗口内 replay 全 batch STF 的算力。numSegments 越大、batchSize 越大，replay 压力越大：
>   - 典型部署 numSegments=200, batchSize=36000 → 普通硬件 ~2-3h replay 完成，1d 窗口有 ~20h buffer
>   - 极限 numSegments=256, batchSize 上限取决于硬件
> - **生产部署建议**：proposer 应在 propose 时按 challenger 能在窗口内 replay 完成的水平选择 batchSize / numSegments

### 3.2 Segment hash 编码

对于 batch `B = [block_{s+1}, ..., block_{s+batchSize}]`（其中 `s = startingOutputRoot.l2SequenceNumber`），定义 `numSegments + 1` 个 boundary state：

```
segment_hash_k = keccak256(blockHash_{s + SEGMENT_SIZE*k} ‖ stateRoot_{s + SEGMENT_SIZE*k})    for k ∈ [0, numSegments]
```

其中：
- `segment_hash_0 = startingOutputRoot.root`（链上已知，来自 parent game 或 anchor）
- `segment_hash_{numSegments} = rootClaim()`（CWIA arg #2，链上已知）
- `segment_hash_1, ..., segment_hash_{numSegments-1}` = `numSegments-1` 个**中间** boundary state（CWIA extraData 中；N=1 时无 intermediate）

> 与 `sp1-range-program` 输出的 `BootInfoStruct.l2PostRoot` 编码一致（`keccak_join(blockHash, stateRoot)`）。

### 3.3 CWIA Calldata Layout

CWIA (Clones-With-Immutable-Args) 把每个 game instance 的不可变参数压成 calldata 紧跟在 selector 后。完整 layout：

```
位置                                            长度              内容
0x00..0x04                                      4 B               function selector
─────────────── CWIA standard args (0x14..0x54) ───────────────
0x04..0x18                                      20 B              gameCreator address (CWIA arg #1)
0x18..0x38                                      32 B              rootClaim (CWIA arg #2)
0x38..0x58                                      32 B              l1Head (CWIA arg #3)
─────────────── extraData (0x58..0x58+0x24+0x20×(N-1)) ───────────────
0x58..0x78                                      32 B              l2SequenceNumber (extraData 字段 1)
0x78..0x7C                                      4 B               parentIndex (extraData 字段 2)
0x7C..0x7C+0x20×(N-1)                          32 × (N-1) B      intermediateRoot[0..N-2] (extraData 字段 3 ★, 0-indexed)
─────────────── CWIA suffix ───────────────
最后 2 B                                        2 B               CWIA suffix
```

**完整 calldata 总长公式**：

```
TOTAL_CALLDATA = 0x04 (selector) + 0x14 (creator) + 0x20 (rootClaim) + 0x20 (l1Head)
               + 0x20 (l2SeqNum) + 0x04 (parentIdx) + 0x20 × (numSegments - 1) (intermediateRoots)
               + 0x02 (suffix)
               = 0x7E + 0x20 × (numSegments - 1)
```

**N=1 退化模式**：`numSegments == 1` 时 `intermediateRoot[]` 段为空，总 calldata = `0x7E`，与原 op-succinct `OPSuccinctFaultDisputeGame.sol` 字节级一致。

**extraData 返回值**（getter）：从 0x54 起 `0x24 + 0x20 × (N-1)` bytes。

### 3.4 CWIA Helper Getter

CWIA helper offset **相对 CWIA payload 起点**（即 gameCreator address 起点 = calldata 0x04），不是 calldata 绝对位置。getter 实现：

```solidity
// CWIA standard args (沿用原合约)
function gameCreator() public pure returns (address) {
    return _getArgAddress(0x00);
}
function rootClaim() public pure returns (Claim) {
    return Claim.wrap(_getArgBytes32(0x14));
}
function l1Head() public pure returns (Hash) {
    return Hash.wrap(_getArgBytes32(0x34));
}

// extraData 字段 1, 2
function l2SequenceNumber() public pure returns (uint256) {
    return _getArgUint256(0x54);
}
function parentIndex() public pure returns (uint32) {
    return _getArgUint32(0x74);
}

// extraData 字段 3 — Option E 新增
/// @notice 读取第 k 个 intermediate root（**0-indexed**, k ∈ [0, numSegments-2]）
/// @dev    含义：`intermediateRoot(0)` = 起点之后第一个中间 boundary (即 segment_hash_1)
///                `intermediateRoot(N-2)` = 终点之前最后一个中间 boundary (即 segment_hash_{N-1})
/// @dev    不含端点：起点 `startingOutputRoot.root` 与终点 `rootClaim()` 都不通过此 getter 访问
/// @dev    必须是 view 不是 pure：bound check 读 storage `numSegments`
function intermediateRoot(uint64 k) public view returns (bytes32) {
    // numSegments >= 1 是 §11 Invariant 7 保证的（initialize 时强校验）
    // numSegments == 1 时, 表达式 numSegments - 1 = 0, k >= 0 永远 true → 任何 k 都 revert ✓
    if (k >= numSegments - 1) revert IndexOutOfRange();
    return _getArgBytes32(0x78 + 0x20 * k);
}

/// @notice 一次性读全部 intermediate roots（bulk getter, 不含端点）
/// @dev    返回 bytes memory，长度 = 0x20 × (numSegments - 1)；N=1 时返回空 bytes
/// @dev    场景：链下 challenger client 一次性 fetch 全 batch roots，减少 RPC round-trip
function intermediateRoots() public view returns (bytes memory) {
    if (numSegments <= 1) return new bytes(0);   // N=1 退化时无 intermediate root
    return _getArgBytes(0x78, 0x20 * (numSegments - 1));
}

// extraData 整体
function extraData() public view returns (bytes memory) {
    // 长度 = 0x24 (l2SeqNum + parentIdx) + 0x20 × (numSegments - 1) (intermediateRoots)
    // numSegments 必须先从 storage 读 → 故是 view 不是 pure
    return _getArgBytes(0x54, 0x24 + 0x20 * (numSegments - 1));
}
```

**CWIA 索引约定**：
- `intermediateRoot(k)` 接受 `k ∈ [0, numSegments-2]`（**0-indexed**）, 含义是"起点之后第 k+1 个 boundary"
- 起点 `boundary 0 = startingOutputRoot.root` 不通过此 getter 访问；调用方应直接读 storage
- 终点 `boundary numSegments = rootClaim()` 不通过此 getter 访问；调用方应直接读 CWIA standard arg #2
- `intermediateRoot(k)` 与 segment 编号的关系: `intermediateRoot(k)` = boundary[k+1]，对应 segment k 的 **claimPost** (或 segment k+1 的 claimPre)
- **`intermediateRoot(k)` 与 segment-level `disputes[k]` / `challenge(k)` / `prove(k)` 共享同一 0-indexed namespace** (k ∈ [0, N-2] vs [0, N-1])，差别仅在上界 —— intermediate root 比 segment 少一个（端点 boundary[N] 不存）

### 3.5 Game Type 复用

**复用 TZ 现有 `TZ_FAULT_GAME_TYPE` slot**，通过 `factory.setImplementation(TZ_FAULT_GAME_TYPE_impl)` 替换；不新增 game type 数字。AccessManager / AnchorStateRegistry / 角色不变。

---

## 四、Bond 参数

| 名称 | 出资方 | 时机 |
|---|---|---|
| `CREATE_BOND` | proposer，通过 `DisputeGameFactory.create{value:}()` 附带 | 创建 game 时一次性 |
| `CHALLENGER_BOND` | 每个 challenger，通过 `challenge{value:}(k)` 附带 | challenge segment k 时一次性 |

### Bond 约束（按重要性排序）

**约束 1（下界，防 grief honest proposer）**：

```
CHALLENGER_BOND ≫ 单次 SEGMENT_SIZE-block zk proof 的总 gas 成本（建议 10× 以上）
```

理由：恶意 challenger 挑战 proposer 能 prove 的合法 segment（L 路径），让 proposer 付 prove gas，然后 L bond 流给 proposer。若 `CHAL_BOND < prove_cost`，proposer 抵御一次虚假挑战还净亏 → 攻击者可重复 grief。10× 是为多 segment 联合 grief 留 safety margin。

> **注**：本 spec 下 SEGMENT_SIZE 是 per-game variable，故 prove_cost 也随 game 变化。bond 参数按 **预期最大 SEGMENT_SIZE 部署场景** 的 prove cost 校准。生产建议在 game create 链下校验 SEGMENT_SIZE 是否超过 bond 经济可承受范围。

**约束 2（上界，保 honest challenger 激励）**：

```
CREATE_BOND ≫ CHALLENGER_BOND（建议 10×，并视 L2 经济价值上调）
```

理由：honest challenger 在 CHALLENGER_WINS（§9.4.a）时拿 `CREATE_BOND` 独占（lowest-S winner takes all）+ 自己 CHAL_BOND 退还。若 `CHAL_BOND > CREATE_BOND`，挑战的下行风险（误选 decoy index 损失 CHAL_BOND）超过上行收益，理性 challenger 不会参与——破坏 1-of-N honest 假设。

> 注：本约束已隐含 "CREATE_BOND ≫ challenger 工作成本"——challenger 的 replay / 网络成本远小于 CHAL_BOND，CHAL_BOND 又远小于 CREATE_BOND。

### 推荐数量级（仅示意，部署时按经济模型校准）

| 项 | 量级 |
|---|---|
| 单次 prove cost (SP1 + L1 gas) | ~$100-300（按 SEGMENT_SIZE = 100 估） |
| `CHALLENGER_BOND` | ~$1k-3k（≈ 10× prove cost） |
| `CREATE_BOND` | ~$10k-100k+（≈ 10× CHAL_BOND，按 L2 batch 经济价值上调） |
| **propose calldata cost**（D.4.4）| ~$2-10（典型 N=200 → 6.4 KB extraData × 16 gas/byte × gas price） |

> **propose cost 经济模型说明**：proposer 用普通 tx 携带 CWIA extraData（含 `numSegments - 1` 个 32-byte intermediate root）。每 byte calldata = 16 gas（non-zero），N=256 上限对应 ~8.2 KB extraData ≈ 130k gas。当前 mainnet ~$0.02/k gas，约 $2-3 per propose。**此费用不计入** CREATE_BOND ——由 proposer 在 tx 内承担。

**整合关系**：

```
prove_cost  ≪  CHALLENGER_BOND  ≪  CREATE_BOND
   约束 1 (下界)      约束 2 (上界)
```

### 技术约束

- `CHALLENGER_BOND` / `CREATE_BOND` 都用 `uint256`，与原合约 bond 链路完全一致；`ChallengerInfo.bond` 同 `uint256`，无 packing 约束、无 cast、无截断不变量。

---

## 五、状态机

合约同时维护两个 state：
- **`GameStatus`**（来自 OP-stack `IDisputeGame` 接口，3 值：`IN_PROGRESS / DEFENDER_WINS / CHALLENGER_WINS`）
- **`ProposalStatus`**（本合约定义，**4 值**：`Unchallenged / Challenged / UnchallengedAndValidProofProvided / Resolved`）

### 5.1 极简状态机

```
       create() (含 CWIA extraData)
            │
            ▼
     ┌──────────────┐
     │ Unchallenged │ (ProposalStatus, 4 态)
     └──────────────┘
        │
        ├── prove(bytes)(proofBytes) [§6 Phase 3.5, 无 challenger 时早证 overload]
        │       ▼
        │   ┌──────────────┐
        │   │  UnchallengedAndValidProofProvided  │
        │   └──────────────┘
        │       │
        │       └── resolve() ──→ Resolved + GameStatus=DEFENDER_WINS (早 finalize, 跳过 clock 等待)
        │
        ├── timeout(MAX_CHALLENGE_DURATION) ──→ resolve() ──→ Resolved + GameStatus=DEFENDER_WINS
        │
        └── challenge(k) × ≥1  [permissionless, 每地址 ≤1 counter，每 k ≤1 challenger，付 CHALLENGER_BOND]
                ▼
            ┌──────────────┐
            │  Challenged  │
            └──────────────┘
                │
                │  prove(k) × ∀ k 已 counter  [不改 status; Step 4 即时 push L bond]
                │  (per-segment 状态在 disputes[k]; ProposalStatus 仍 Challenged)
                │
                ├── timeout(proveDeadline) ∧ totalProved < totalCountered ──→ resolve() ──→ Resolved + GameStatus=CHALLENGER_WINS
                └── timeout(proveDeadline) ∧ totalProved == totalCountered ──→ resolve() ──→ Resolved + GameStatus=DEFENDER_WINS

     ┌──────────────┐
     │   Resolved   │  (终态; 入口来自上述任一 resolve())
     └──────────────┘
```

> 任意时刻 `parentStatus == CHALLENGER_WINS` 触发**parent-forced CHW**（详见 §6 Phase 3 / §9.4.b）：bypass gameOver()，任何 ProposalStatus（含 UnchallengedAndValidProofProvided）直接推到 `Resolved + CHALLENGER_WINS`，覆盖正常分支。

> 所有终止箭头都意味着 `resolve()` 被调用：**ProposalStatus 同步转为 `Resolved`**，**GameStatus 从 `IN_PROGRESS` 转为 DEFENDER_WINS / CHALLENGER_WINS**。终态后不可再变。
>
> **Resolved 之后的两个 post-state 操作**（不改 ProposalStatus / GameStatus）：
> - `closeGame()`：把 `bondDistributionMode` 从 `UNDECIDED` 推到 `NORMAL` 或 `REFUND`
> - `claimCredit(addr)`：bond 结算 + 转账（单一入口；内部自动 settle S-path）

### 5.2 状态枚举

**ProposalStatus**（本 spec 定义）：

```solidity
enum ProposalStatus {
    Unchallenged,       // 初始状态（无 challenger, 也未 `prove(bytes)`）
    Challenged,         // ≥1 challenger 已 counter segment，等待 proof
    UnchallengedAndValidProofProvided,         // §6 Phase 3.5 早 finalize 标记态：无 challenge + `prove(bytes)` 已验整 batch；等 resolve() consume
    Resolved            // 终态：resolve() 已调
}
```

> **vs V1**：V1 ProposalStatus 5 态（Unchallenged / Challenged / U+VP / C+VP / Resolved）→ 本 spec 4 态。差异：
> - **删除 C+VP**：multi-segment 下 prove(k) Step 4 即时 push L bond 给 prover，无 game-wide 中间态需求
> - **保留 U+VP**（同 V1 命名，V1 alignment-first）：含义不变（无 challenge + 整 batch 已验）

**GameStatus** & **BondDistributionMode**：复用 OP-stack 标准（详见 `src/dispute/lib/Types.sol`）。`BondDistributionMode` 顺序固定为 `{ UNDECIDED, NORMAL, REFUND }`（UNDECIDED = 0，storage 默认值）。

---

## 六、各阶段详细规范

### Phase 0 — Create (含 CWIA extraData)

**入口**：`DisputeGameFactory.create{value: CREATE_BOND}(TZ_FAULT_GAME_TYPE, rootClaim, extraData)`——普通 tx 即可（无须 Type-3）。

**关键机制**：intermediate roots 由 proposer 在 `extraData` 中提供，通过 CWIA 机制成为 game 实例的 immutable args，永久 SLOAD-级可读。

**extraData layout**：

```
[l2SequenceNumber (uint256, 32 bytes),
 parentIndex (uint32, 4 bytes),
 intermediateRoot[0] (bytes32, 32 bytes),       // 0-indexed: = segment_hash_1 (boundary 1)
 intermediateRoot[1] (bytes32, 32 bytes),       // = segment_hash_2 (boundary 2)
 ...
 intermediateRoot[numSegments - 2] (bytes32, 32 bytes)]  // = segment_hash_{N-1} (boundary N-1)
```

extraData 总长 = `0x24 + 0x20 × (numSegments - 1)`，对应整 CWIA calldata 总长 = `0x7E + 0x20 × (numSegments - 1)`。

**N=1 退化**：`numSegments == 1` 时 `intermediateRoot[]` 段为空，extraData 仅含 `[l2SequenceNumber, parentIndex]`，36 bytes，CWIA calldata 总长 0x7E，与原 op-succinct 完全一致。

**initialize() 不变式**（含 CWIA 长度反推 + parent integrity 4 项校验 + 鉴权 + bond）：

- **基本鉴权**：
  - `!initialized`（否则 revert `AlreadyInitialized`）——防 re-init
  - `msg.sender == DISPUTE_GAME_FACTORY`（否则 revert `IncorrectDisputeGameFactory`）
  - `ACCESS_MANAGER.isAllowedProposer(gameCreator())`（否则 revert `BadAuth`）

- **CWIA 长度合法性 + numSegments 反推**：

  ```solidity
  // CWIA 总 calldata 长度 = 0x7E + 0x20 × (numSegments - 1)
  // 即 (calldatasize() - 0x7E) 必须是 0x20 的整数倍
  uint256 cz = calldatasize();
  if (cz < 0x7E) revert BadExtraData();                         // 下限：必须 ≥ N=1 长度
  uint256 extraRootsLen = cz - 0x7E;
  if (extraRootsLen % 0x20 != 0) revert BadExtraData();         // 必须是 32-byte 倍数
  uint64 _numSegments = uint64(extraRootsLen / 0x20) + 1;       // N = (extraRootsLen / 32) + 1
  if (_numSegments < 1 || _numSegments > MAX_NUM_SEGMENTS)
      revert InvalidNumSegments(_numSegments);                  // 范围约束：1 ≤ N ≤ 256
  ```

  > **N=1 边界**：extraRootsLen == 0 → _numSegments = 1 → 通过下界检查（>= 1）
  > **N=256 边界**：extraRootsLen == 32 × 255 = 8160 → _numSegments = 256 → 通过上界检查 (<= 256)
  > **N=257 越界**：extraRootsLen == 32 × 256 = 8192 → _numSegments = 257 → revert `InvalidNumSegments`

- **`startingOutputRoot` 决定 + 写入 storage（parent integrity 校验）**：
  - `parentIndex() != uint32.max` 时：从 factory 读 parent，`startingOutputRoot = Proposal({l2SequenceNumber: parent.l2SequenceNumber(), root: parent.rootClaim()})`；require `isGameRespected ∧ !isGameBlacklisted ∧ !isGameRetired ∧ parent.status() != CHALLENGER_WINS ∧ startingOutputRoot.l2SequenceNumber > getAnchorRoot().l2SequenceNumber`（任一失败 → revert `InvalidParentGame`，5 子条件聚合到同一 error）
  - `parentIndex() == uint32.max`（首个 game / retirement recovery）时：从 `getAnchorRoot()` 读，`startingOutputRoot = Proposal({root: anchorRoot, l2SequenceNumber: anchorL2SeqNum})`。注：与 V1 baseline (`OPSuccinctFaultDisputeGame.sol:282-287`) 一致，本路径不显式 check `anchorRoot == 0`；信任 ASR 永不返回未配置 anchor。

- **batchSize 派生 + 整除校验**：
  - `l2SequenceNumber() > startingOutputRoot.l2SequenceNumber`（否则 revert `UnexpectedRootClaim`）
  - `uint64 _batchSize = uint64(l2SequenceNumber() - startingOutputRoot.l2SequenceNumber)`
  - `_batchSize % _numSegments == 0`（必须为 numSegments 整数倍；否则 revert `InvalidBatchSize`）——保证 `SEGMENT_SIZE = _batchSize / _numSegments` 为正整数
  - `_batchSize / _numSegments >= 1`（即 `_batchSize >= _numSegments`；隐式由整除 + numSegments ≥ 1 保证）

- **状态初始化**（前 5 项与原合约 [line 296-316](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L296) 写入顺序一致，新增字段追加在后）：
  - **原合约同顺序部分**：
    1. `claimData = ClaimData({parentIndex: parentIndex(), status: Unchallenged, proveDeadline: Timestamp.wrap(uint64(block.timestamp + MAX_CHALLENGE_DURATION + MAX_PROVE_DURATION)), claim: rootClaim()})`（**单字段 deadline**：仅存 `proveDeadline`；`challengeEnd` 不存 storage，由 view function `challengeEnd() = createdAt + MAX_CHALLENGE_DURATION` derive）
    2. `initialized = true`
    3. `refundModeCredit[gameCreator()] += msg.value`（deposit ledger）
    4. `createdAt = Timestamp.wrap(uint64(block.timestamp))`
    5. `wasRespectedGameTypeWhenCreated = (ASR.respectedGameType() == GAME_TYPE)`
  - **新增字段（追加在后）**：
    6. `batchSize = _batchSize`、`numSegments = _numSegments`（前置校验步骤计算）
    7. `lowestSIndex = LOWEST_S_NOT_SET = type(uint64).max`（**必须显式写入**——Solidity 默认 `uint64` 是 0，会被 lazy compute 误判为"已计算且 lowest 是 segment 0"；详见 §六 Phase 4 lazy compute 逻辑 + Invariant 16）
  - **默认值无需显式写**：`bondDistributionMode = UNDECIDED (=0)`、`totalCountered = 0`、`totalProved = 0`、`createBondPushedAtResolve = false`、`claimData.prover = address(0)` 均为 Solidity zero 默认值，无需 SSTORE

#### Phase 0 canonical initialize() pseudo-code

```solidity
function initialize() external payable {
    // === 基本鉴权（与 V1 [line 247-265](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L247) 同顺序）===
    if (initialized) revert AlreadyInitialized();
    if (address(DISPUTE_GAME_FACTORY) != msg.sender) revert IncorrectDisputeGameFactory();
    if (!ACCESS_MANAGER.isAllowedProposer(gameCreator())) revert BadAuth();

    // === CWIA 长度合法性 + numSegments 反推（multi-segment 新增）===
    uint256 cz;
    assembly { cz := calldatasize() }
    if (cz < 0x7E) revert BadExtraData();                       // 下限：必须 ≥ N=1 长度
    uint256 extraRootsLen = cz - 0x7E;
    if (extraRootsLen % 0x20 != 0) revert BadExtraData();       // 必须是 32-byte 倍数
    uint64 _numSegments = uint64(extraRootsLen / 0x20) + 1;     // N = (extraRootsLen / 32) + 1
    if (_numSegments > MAX_NUM_SEGMENTS) revert InvalidNumSegments(_numSegments);
    //      _numSegments ≥ 1 由 extraRootsLen ≥ 0 蕴含；上界 256 显式校验

    // === Parent integrity check（与 V1 [line 290-326](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L290) 同 pattern）===
    if (parentIndex() != type(uint32).max) {
        // 链上 parent: 从 factory 读 parent game proxy
        (,, IDisputeGame proxy) = DISPUTE_GAME_FACTORY.gameAtIndex(parentIndex());

        // 4 项 ASR / parent 合规校验聚合到同一 InvalidParentGame error
        if (
            !ANCHOR_STATE_REGISTRY.isGameRespected(proxy) ||
            ANCHOR_STATE_REGISTRY.isGameBlacklisted(proxy) ||
            ANCHOR_STATE_REGISTRY.isGameRetired(proxy)
        ) revert InvalidParentGame();

        startingOutputRoot = Proposal({
            l2SequenceNumber: OPSuccinctTzSegmentDisputeGame(address(proxy)).l2SequenceNumber(),
            root:             Hash.wrap(OPSuccinctTzSegmentDisputeGame(address(proxy)).rootClaim().raw())
        });

        if (proxy.status() == GameStatus.CHALLENGER_WINS) revert InvalidParentGame();

        // anchor advance check: parent.l2SeqNum 必须 > anchor.l2SeqNum（防 stale parent）
        (, uint256 anchorL2SeqNum) = ANCHOR_STATE_REGISTRY.getAnchorRoot();
        if (startingOutputRoot.l2SequenceNumber <= anchorL2SeqNum) revert InvalidParentGame();
    } else {
        // parentIndex == uint32.max（首个 game / retirement recovery）
        // 注：V1 baseline (OPSuccinctFaultDisputeGame.sol:282-287) 同款不 check anchorRoot == 0；信任 ASR
        (Hash anchorRoot, uint256 anchorL2SeqNum) = ANCHOR_STATE_REGISTRY.getAnchorRoot();
        startingOutputRoot = Proposal({ root: anchorRoot, l2SequenceNumber: anchorL2SeqNum });
    }

    // === l2SequenceNumber sanity（V1 [line 331](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L331) 同检）===
    if (l2SequenceNumber() <= startingOutputRoot.l2SequenceNumber) revert UnexpectedRootClaim();

    // === batchSize 派生 + 整除校验（multi-segment 新增）===
    uint64 _batchSize = uint64(l2SequenceNumber() - startingOutputRoot.l2SequenceNumber);
    if (_batchSize % _numSegments != 0) revert InvalidBatchSize();
    //   _batchSize / _numSegments >= 1 由整除 + _numSegments ≥ 1 + _batchSize ≥ 1 (上一行 sanity) 蕴含

    // === 状态初始化（前 5 项与 V1 [line 296-316](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L296) 一致；新增字段追加）===
    // 1) ClaimData 结构赋值（单写 SSTORE 批量，编译器 packs 进 slot 1+2+3）
    claimData = ClaimData({
        prover:        address(0),                                  // §6 Phase 3.5 写 msg.sender; 默认 0
        proveDeadline: Timestamp.wrap(uint64(
                         block.timestamp + MAX_CHALLENGE_DURATION.raw() + MAX_PROVE_DURATION.raw()
                       )),
        parentIndex:   parentIndex(),
        status:        ProposalStatus.Unchallenged,
        claim:         rootClaim()
    });
    // 2) 防 re-init
    initialized = true;
    // 3) Deposit ledger (gameCreator 付 CREATE_BOND)
    refundModeCredit[gameCreator()] += msg.value;
    // 4) Lifecycle 时间戳
    createdAt = Timestamp.wrap(uint64(block.timestamp));
    // 5) ASR respected-type snapshot（OP-stack 标准 finality 信号）
    wasRespectedGameTypeWhenCreated =
        GameType.unwrap(ANCHOR_STATE_REGISTRY.respectedGameType()) == GameType.unwrap(GAME_TYPE);

    // 6) Multi-segment 新增字段
    batchSize    = _batchSize;
    numSegments  = _numSegments;
    lowestSIndex = LOWEST_S_NOT_SET;   // ★ 必须显式写 sentinel；Solidity 默认 0 会被误判为"已计算"

    // 7) Solidity-zero 默认值无需 SSTORE：
    //    bondDistributionMode = UNDECIDED (=0)
    //    totalCountered = 0, totalProved = 0
    //    createBondPushedAtResolve = false
    //    claimData.prover 已在 ClaimData 结构赋值中显式写 address(0)（也可省略走 zero default，此处显式 for readability）
}
```

**Phase 0 不变式 + revert mapping**（按上面 pseudo-code 执行顺序）：

| revert 顺序 | 触发条件 | error |
|---|---|---|
| 1 | `initialized == true` | `AlreadyInitialized` |
| 2 | `msg.sender != DISPUTE_GAME_FACTORY` | `IncorrectDisputeGameFactory` |
| 3 | `!ACCESS_MANAGER.isAllowedProposer(gameCreator())` | `BadAuth` |
| 4 | `calldatasize() < 0x7E` ∨ `(calldatasize() - 0x7E) % 0x20 != 0` | `BadExtraData` |
| 5 | `numSegments > MAX_NUM_SEGMENTS (256)` | `InvalidNumSegments(actual)` |
| 6 | parentIndex 链上 game: 任一 ASR 校验失败 ∨ parent CHW ∨ stale parent (l2SeqNum ≤ anchor) | `InvalidParentGame` |
| 7 | `l2SequenceNumber() ≤ startingOutputRoot.l2SequenceNumber` | `UnexpectedRootClaim` |
| 8 | `batchSize % numSegments != 0` | `InvalidBatchSize` |

> 注：`parentIndex == uint32.max + anchor 未配置` 不显式 check（与 V1 baseline 一致，信任 ASR 永不返回未配置 anchor）。早期 spec draft 列过 `AnchorRootNotFound` revert，已 drop 以与实现保持一致。

校验顺序遵循 §11.9 mutator first-check 协议：基本鉴权 → 输入合法性 → parent integrity → batch 算术合法性 → state 写入。

**事件**：无（与原合约一致——create 由 factory 的 `DisputeGameCreated` event 承担信号；off-chain indexer 拿到 game 地址后通过 `intermediateRoot(k)` getter 按需读取 intermediate roots）

---

### Phase 1 — Challenge (含 select)（合并）

**接口**：

```solidity
function challenge(uint64 k) external payable returns (ProposalStatus);
```

**语义定位**：**唯一的 challenger 入口**——同时完成"加入争议"与"选具体 segment"两件事。intermediate roots 在 create 时已上链 CWIA，challenger 可直接通过 `intermediateRoot(k)` getter 读取并指定 mismatch segment。

**不变式**：
- 每地址至多 counter 1 段（`challengers[msg.sender].countered` dedup）
- 每 segment 至多被 1 个 challenger counter（`disputes[k].counteredBy` dedup；**index dedup** 保证 lowest-S 唯一性）
- 仅在 `claimData.status ∈ {Unchallenged, Challenged}` 时允许（**multi-challenger 设计**：Challenged 状态下仍可继续 counter 新 segment；UnchallengedAndValidProofProvided / Resolved 拒绝入场）
- 不修改任何 deadline（`proveDeadline` 在 initialize 时一次性写入；`challengeEnd()` 是 immutable-derived view = `createdAt + MAX_CHALLENGE_DURATION`，无 storage 字段）

**revert mapping**（按 §11.9 mutator first-check 协议，与 V1 [line 436](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L436) 同顺序）：

| revert 顺序 | 触发条件 | error |
|---|---|---|
| 1 | `status != GameStatus.IN_PROGRESS` | `GameAlreadyResolved` |
| 2 | `claimData.status == UnchallengedAndValidProofProvided` | `AlreadyFullProved` |
| 3 | `block.timestamp ≥ challengeEnd()` | `ClockTimeExceeded` |
| 4 | `!ACCESS_MANAGER.isAllowedChallenger(msg.sender)` | `BadAuth` |
| 5 | `msg.value != CHALLENGER_BOND` | `IncorrectBondAmount` |
| 6 | `challengers[msg.sender].countered` | `AlreadyCountered` |
| 7 | `k >= numSegments` | `IndexOutOfRange` |
| 8 | `disputes[k].counteredBy != address(0)` | `ClaimAlreadyChallenged` |

**效果**：

```solidity
challengers[msg.sender] = ChallengerInfo({
    bond: CHALLENGER_BOND,           // uint256，与原合约 bond 链路一致
    countered: true,
    counteredIndex: k
});

disputes[k] = DisputeEntry({
    counteredBy: msg.sender,
    proved: false,
    provedBy: address(0)
});

refundModeCredit[msg.sender] += msg.value;  // deposit ledger 累加
totalCountered++;

if (claimData.status == ProposalStatus.Unchallenged) {
    claimData.status = ProposalStatus.Challenged;
}
```

**事件**：`event Challenged(address indexed challenger, uint64 indexed segment)`

> **Frontrun 防护**：诚实 challenger 应通过 MEV-protected mempool 提交，避免 sock-puppet 抢占 segment slot。链上不做强防护（详见 §十）。

> **Off-chain client 行为**：challenger 取 roots、本地 replay、first-mismatch 搜索、race-loss 处理详见 §13.1 / §13.2；full-batch prover 客户端详见 §13.3。

---

### Phase 2 — Prove Step (permissionless, per-segment)

**接口**（per-segment 直接 2 参数，无 struct 包装）：

```solidity
/// @notice Per-segment STF proof; selector `prove(uint64,bytes)` 与 V1 `prove(bytes)` 不同。
///         配对的 full-batch 早 finalize 通道 `prove(bytes)`（§6 Phase 3.5）共享 "prove" 函数名（重载）—— 实例两套：
///           - `prove(uint64 k, bytes calldata proofBytes)` — 本接口（per-segment, 仅 segment k 被 counter 后可调）
///           - `prove(bytes calldata proofBytes)`           — §6 Phase 3.5（full-batch, 无 challenger 早 finalize, selector 与 V1 一致）
/// @param  k           segment index, k ∈ [0, numSegments)
/// @param  proofBytes  SP1 aggregation proof bytes (raw)
function prove(uint64 k, bytes calldata proofBytes) external returns (ProposalStatus);
```

> **selector 设计**：
> - V1 单段 `prove(bytes)` selector → 本 spec **`prove(bytes)`（早 finalize）** 继承（§6 Phase 3.5），与 V1 完全一致 —— V1 N=1 退化路径下二者语义等价
> - 本 spec **新增** `prove(uint64,bytes)` selector for per-segment dispute 路径 —— 4-byte selector 不同，区块浏览器 / etherscan 自然区分
> - 同函数名"prove" 两个 overload：Solidity ABI 标准支持，工具链直接渲染为两个独立接口

> **gas 开销**：直接 2 参数无需 abi.decode struct，**比之前 SegmentProof 包装节省 ~500-1000 gas**。

> **返回值语义**：返回 `ProposalStatus`，**永远是 `Challenged`**（直到 resolve 才推进到 `Resolved`）。返回值仅用于 API 对称性，调用者通常无需读取。

**与 blob 变体（V2）的差异**：

V2 blob 的 `prove(bytes)` 内部 abi.decode 一个 7 字段的 SegmentProof struct（含 KZG opening proof / commitment）。本 spec 砍 KZG 后仅剩 segmentIndex + zkProof 2 字段，**进一步简化为直接 2 个 function 参数**：

| 字段 | Blob 变体 (V2) struct | Calldata 变体（本 spec）参数 |
|---|---|---|
| `segmentIndex` (uint64) | abi-decoded from `proofBytes` | **直接 function 参数 `k`** |
| `claimPre` (bytes32) | caller 传入 + KZG opening | **不需要** — 合约从 storage / CWIA 派生 |
| `claimPost` (bytes32) | caller 传入 + KZG opening | **不需要** |
| `commitment` (bytes 48) | KZG commitment | **不需要** — 无 KZG |
| `proofPre / proofPost` (bytes 48 each) | KZG opening proofs | **不需要** |
| `zkProof` (bytes) | abi-decoded from `proofBytes` | **直接 function 参数 `proofBytes`** |

**caller 接口从"abi.encode 7 字段 struct"→"2 个 function 参数"**：链下 SDK 简化，无需 ABI struct 编码。

**不变式 + revert mapping**（按 §11 Invariant 27 统一 mutator first-check 协议；k = function 参数）：
- **First check**：`status != GameStatus.IN_PROGRESS` → revert `GameAlreadyResolved`（与 V1 [line 436](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L436) 同顺序）
- `claimData.status != Challenged` → revert（Unchallenged / UnchallengedAndValidProofProvided 时无可证 segment；细分 error 见下）：
  - `claimData.status == Unchallenged` → revert `IndexNotCountered`（segment 尚未被 challenge，无法 prove；prove(uint64,bytes) 只在 Challenged 状态可用）
  - `claimData.status == UnchallengedAndValidProofProvided` → revert `AlreadyFullProved`（game 已被 full-batch 早证，应走 resolve 而非 per-segment prove）
- 仅当 `claimData.status == Challenged` 下推到余下校验：
  - `block.timestamp < Timestamp.unwrap(claimData.proveDeadline)` → revert `ClockTimeExceeded`（prove 窗口截止；initialize 时一次性写入，永不更新）
  - `k < numSegments` → revert `IndexOutOfRange`（per-game storage）
  - `disputes[k].counteredBy == address(0)` → revert `IndexNotCountered`（segment k 未被 counter，无可证目标）
  - `disputes[k].proved` → revert `AlreadyProved`（segment k 已 prove；防同 segment 重复 push L bond）
- **任何人都可调用**（permissionless prover）。Frontrun 防护：`proverAddress = msg.sender` 进入 zk public input
- SP1 verifier 失败 → revert（SP1 内部 throw / require pattern）

**3 步验证流程**（**原子执行**：任一步骤失败整笔 revert，无 partial 写入；prover 可重试同一 `(k, proofBytes)` 直到 proveDeadline）：

#### Step 1 — 派生 `claimPre`（合约内部，无 caller 输入）

`claimPre = boundary[k]`，按 0-indexed `intermediateRoot(i) = boundary[i+1]` 反推 → `boundary[k] = intermediateRoot(k - 1)`（k ≥ 1）；起点端 (k=0) 单独读 storage。

```solidity
bytes32 claimPre;
if (k == 0) {
    claimPre = Hash.unwrap(startingOutputRoot.root);   // 起点端：链上 storage (boundary 0)
} else {
    claimPre = intermediateRoot(k - 1);                // 中间：CWIA immutable arg (boundary k = intermediateRoot(k-1))
}
```

> **CWIA 读 gas**：`intermediateRoot(i)` 是 view function（bound check 读 `numSegments` storage 一次 SLOAD ~2.1k gas），底层 `_getArgBytes32(0x78 + 0x20 * i)` —— calldata 直读零 SLOAD，gas ~50。整 prove 路径 intermediateRoot 调用 2-4 次（claimPre + claimPost + numSegments 检查），总开销相对 SP1 verify ~250k 可忽略。

#### Step 2 — 派生 `claimPost`（合约内部，无 caller 输入）

`claimPost = boundary[k+1]`，按 0-indexed `intermediateRoot(i) = boundary[i+1]` 反推 → `boundary[k+1] = intermediateRoot(k)`（k ≤ N-2）；终点端 (k = N-1) 单独读 CWIA arg #2。

```solidity
bytes32 claimPost;
if (k == numSegments - 1) {
    claimPost = Claim.unwrap(rootClaim());             // 终点端：CWIA standard arg #2 (boundary N)
} else {
    claimPost = intermediateRoot(k);                   // 中间：CWIA immutable arg (boundary k+1 = intermediateRoot(k))
}
```

#### Step 3 — 验证 zk proof（SEGMENT_SIZE-block segment）

构造 `AggregationOutputs`：

```solidity
// AggregationOutputs struct 定义在 src/lib/Types.sol，字段顺序 / 名称与原合约 line 387-395 完全一致
uint64 _segSize = batchSize / numSegments;            // SEGMENT_SIZE 派生 (uint64 除法 ~5 gas)
AggregationOutputs memory publicValues = AggregationOutputs({
    l1Head:               Hash.unwrap(l1Head()),                                  // CWIA arg #3；tz-aggregation 程序通过 `inputs.latest_l1_checkpoint_head` 透传，game.l1Head() drives end-to-end（V1 line 388 同 pattern）
    l2PreRoot:            claimPre,                                                // 来自 Step 1
    claimRoot:            claimPost,                                               // 来自 Step 2
    claimBlockNum:        uint64(startingOutputRoot.l2SequenceNumber + _segSize * (k + 1)),  // 起点 + SEGMENT_SIZE * (k+1)
    rollupConfigHash:     ROLLUP_CONFIG_HASH,                                      // immutable = 0
    rangeVkeyCommitment:  RANGE_VKEY_COMMITMENT,                                   // immutable
    proverAddress:        msg.sender                                               // frontrun 防护
});

SP1_VERIFIER.verifyProof(AGGREGATION_VKEY, abi.encode(publicValues), proofBytes);   // 失败时自然 revert
```

> **复用 sp1-range-program**：program 接受动态 block 范围 STF 验证，**不**在 ELF 内 hardcode SEGMENT_SIZE；合约层通过 `claimBlockNum = startingOutputRoot.l2SequenceNumber + (batchSize / numSegments) * (k+1)` 公式间接强制单 dispute 为 SEGMENT_SIZE-block 单位。这样未来调整 segment 粒度（如改 max N、或允许更大 batch）只需改合约常量 + 重部署，**无需 program 端 vkey rotation**。
>
> 与 blob 变体（V2）相同的 sp1-range-program 适用本 spec —— 同 vkey 可被两套 dispute game 共享。

> **`proverAddress` 与 contract wallet 兼容性**：EOA prover 推荐；多签 / Gnosis Safe 兼容；ERC-4337 ⚠️ EntryPoint 才是 msg.sender，会丧失 frontrun 防护粒度，生产部署应避免。

#### Step 4 — 标记 proved 并即时 push L bond

```solidity
disputes[k].proved = true;
disputes[k].provedBy = msg.sender;
totalProved++;

// L bond 即时发放：把 challenger 的 CHAL_BOND 转给 prover
address challenger = disputes[k].counteredBy;
uint256 lBond = challengers[challenger].bond;
challengers[challenger].bond = 0;                // 消费 bond field（不动 countered——防止 re-challenge）
normalModeCredit[msg.sender] += lBond;           // prover 即时入账
```

> **为什么即时发放而非 resolve 时统一处理**：
> - 让所有角色（proposer / S challenger / L challenger / pure prover）共用单一 `claimCredit(self)` 入口（详见 Phase 4），与原合约 API 一致
> - prover 不需要再调 settleSegment 等额外函数——prove 一次完成所有 L bond push
> - 避免 resolve() 遍历 disputed segments 的 worst-case gas 问题（multi-challenger 最坏 `numSegments` 个 SSTORE）

> **`countered` flag 保证不能 re-challenge**（详见 §十一 Invariant 13）：prove 仅清 `bond` 字段，**不动 `countered`**。`challengers[challenger].countered == true` 永久保持，后续 `challenge(k')` 因 `!countered` require 失败而 revert——bond 清零不解锁 re-challenge。

> **REFUND mode 兼容性**：NORMAL credit 写入在 REFUND 下作废，但 challenger 的 `refundModeCredit[challenger]` 仍保有原始 CHAL_BOND 可原路退还，守恒成立（详见 §9.6.2 不变式）；prover 损失 SP1 工作成本是 design-accepted 的不对称（详见 §9.6.5）。

**事件**：`event Proved(address indexed prover, uint64 indexed segment)`

---

### Phase 3 — Resolve

**接口**：`function resolve() external returns (GameStatus);`

**Revert mapping**（按 pseudocode 内执行顺序）：

| revert 顺序 | 触发条件 | error |
|---|---|---|
| 1 | `status != GameStatus.IN_PROGRESS` | `ClaimAlreadyResolved` (V1 alias) |
| 2 | `getParentGameStatus() == IN_PROGRESS` | `ParentGameNotResolved` |
| 3 | parent DEFENDER_WINS ∧ `!gameOver()` | `GameNotOver` |
| 4 | parent DEFENDER_WINS ∧ `claimData.status == Resolved` (unreachable，由 #1 拦截，sanity) | `InvalidProposalStatus` |

**判定矩阵**（成功路径 GameStatus 输出）：parent CHW 覆盖 → CHW；否则按 `claimData.status` 分支 → Unchallenged/UnchallengedAndValidProofProvided → DW；Challenged ∧ `totalProved == totalCountered` → DW；Challenged ∧ `totalProved < totalCountered` → CHW。详细 bond 流向见 pseudocode + §9.4。

**parent-forced CHW 覆盖语义**：若 `getParentGameStatus() == CHALLENGER_WINS`，**优先级最高**强制 GameStatus = CHALLENGER_WINS；bond 处理详见 §9.4.b。无需 `gameOver()` guard——parent CHW 意味着 `startingOutputRoot` 来源于 invalid chain，本 game 必 CHW，honest challenger 在窗口内外都无法挽救，race condition 不存在，早 resolve 让 honest challenger 更快通过 `claimCredit` 拿回 CHAL_BOND。

#### Phase 3 canonical resolve() pseudo-code

```solidity
function resolve() external returns (GameStatus) {
    if (status != GameStatus.IN_PROGRESS) revert ClaimAlreadyResolved();   // resolve 用 V1 alias (§11 Inv 31)

    // Parent integrity check 必须先做（B2 修复）：
    //   parent IN_PROGRESS → revert ParentGameNotResolved  (与原合约 line 437-439 对齐)
    //   parent CHALLENGER_WINS → forced CHW（优先级最高，§9.4.b bond 处理）
    //   parent DEFENDER_WINS → 进入普通 resolve 路径
    GameStatus parentStatus = getParentGameStatus();
    if (parentStatus == GameStatus.IN_PROGRESS) revert ParentGameNotResolved();
    if (parentStatus == GameStatus.CHALLENGER_WINS) {
        status = GameStatus.CHALLENGER_WINS;
        // §9.4.b burn 路径：S == ∅ 时（totalCountered == 0 或全部 prove 完）burn CREATE_BOND；
        // S != ∅ 时由 claimCredit S-path lazy 分发给 lowest-S challenger。详细伪代码见 §9.4.b。
        if (totalProved == totalCountered) {
            normalModeCredit[address(0)] += CREATE_BOND;    // NORMAL-mode burn 标记
            createBondPushedAtResolve = true;
        }
        // L bond 已在 prove Step 4 即时 push，resolve 不操作
        resolvedAt = Timestamp.wrap(uint64(block.timestamp));
        claimData.status = ProposalStatus.Resolved;
        emit Resolved(GameStatus.CHALLENGER_WINS);
        return GameStatus.CHALLENGER_WINS;
    }

    // 普通 resolve 路径（parent 已 DEFENDER_WINS）
    if (!gameOver()) revert GameNotOver();

    if (claimData.status == ProposalStatus.Unchallenged
     || claimData.status == ProposalStatus.UnchallengedAndValidProofProvided) {
        // 两路径 bond 流向一致：无 challenger 接收 → CREATE_BOND 退 proposer
        // Unchallenged: clock 自然到期；UnchallengedAndValidProofProvided: §6 Phase 3.5 早 finalize 标记态
        status = GameStatus.DEFENDER_WINS;
        normalModeCredit[gameCreator()] += CREATE_BOND;
    } else if (claimData.status == ProposalStatus.Challenged) {
        // gameOver() 已保证 proveDeadline 到期（§12.6.1），无需重复 require
        if (totalProved == totalCountered) {
            // §9.3 DW: 全部 disputed segment 都已 prove
            status = GameStatus.DEFENDER_WINS;
            normalModeCredit[gameCreator()] += CREATE_BOND;
        } else {
            // §9.4.a CHW: ≥1 disputed segment 未 prove
            status = GameStatus.CHALLENGER_WINS;
            // CREATE_BOND 不在此 push；由 claimCredit S-path lazy compute lowestSIndex 后发给该 challenger
        }
        // L bond 已在 prove Step 4 即时 push，resolve 不操作
    } else {
        revert InvalidProposalStatus();   // status == Resolved 应已 revert (复用 V1 error)
    }

    resolvedAt = Timestamp.wrap(uint64(block.timestamp));
    claimData.status = ProposalStatus.Resolved;
    emit Resolved(status);
    return status;
}

function getParentGameStatus() private view returns (GameStatus) {
    if (parentIndex() == type(uint32).max) return GameStatus.DEFENDER_WINS;  // 无 parent
    (,, IDisputeGame proxy) = DISPUTE_GAME_FACTORY.gameAtIndex(parentIndex());
    return IDisputeGame(address(proxy)).status();
}
```

**事件**：`event Resolved(GameStatus status)` —— 沿用 OP-stack 标准。

---

### Phase 3.5 — Optional Early Finalize (`prove(bytes)` overload)

**接口选择**：本 phase 暴露 `prove(bytes calldata proofBytes)` —— 与 V1 [`prove(bytes)`](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L382) **selector 完全一致**。与 §6 Phase 2 的 `prove(uint64,bytes)` 是 Solidity **同名函数重载**（不同签名生成不同 4-byte selector）：

```solidity
prove(uint64,bytes)   // §6 Phase 2: per-segment, k 已被 counter 的路径
prove(bytes)          // §6 Phase 3.5: full-batch early finalize, 无 challenger 路径 (selector 与 V1 一致)
```

**语义定位**：可选的 fast-path —— 在 challenge 窗口内一次性证明 `startingOutputRoot.root → rootClaim` 全 batch 范围（覆盖整 `numSegments` × `SEGMENT_SIZE` blocks 的 STF），把 game 标记为"已全证"。**status 翻转仍需后续 `resolve()` 完成**，与 V1 `prove()` + `resolve()` 两段式对齐 —— 本接口只验证 + 标记，不直接 finalize。

**与 `prove(uint64,bytes)` 互斥**：前者要求 `disputes[k].counteredBy != 0`（challenge 后 per-segment），后者要求 `claimData.status == Unchallenged`（无人 counter）；public input 的 `claimBlockNum` 不同（全 batch vs `SEGMENT_SIZE × (k+1)`），同 `AGGREGATION_VKEY` + `RANGE_VKEY_COMMITMENT` 可验证两种 proof。独立 selector 让 explorer / 工具链区分两条独立路径。

**接口**：

```solidity
/// @notice 全 batch 证明通道：proposer（或任何 prover）在无人挑战时一次性证明整 batch，
///         推进 claimData.status 到 UnchallengedAndValidProofProvided；不直接 finalize，需后续 resolve() consume。
/// @dev    Selector 与 V1 `prove(bytes)` 一致；V1 N=1 退化路径下二者语义等价。
/// @param  proofBytes  SP1 aggregation proof，public input 见下
function prove(bytes calldata proofBytes) external;
```

**Revert mapping**（按执行顺序）：

| revert 顺序 | 触发条件 | error |
|---|---|---|
| 1 | `status != GameStatus.IN_PROGRESS` | `GameAlreadyResolved` (§11 Inv 27, V1 line 436) |
| 2 | `claimData.status == UnchallengedAndValidProofProvided` | `AlreadyFullProved` |
| 3 | `claimData.status == Challenged` | `NotUnchallenged` |
| 4 | `block.timestamp >= challengeEnd()` | `ChallengeWindowEnded` |
| 5 | `getParentGameStatus() == CHALLENGER_WINS` | `ParentAlreadyLost` |
| 6 | SP1 verify 失败 | (SP1 内部 throw) |

**说明**：
- #1 拦截 `Resolved`，后续无需重复枚举；#2/#3 通过后 `claimData.status == Unchallenged`，由 Inv 11 自动蕴含 `totalCountered == 0`，无冗余校验
- #5 parent-CHW 预检挡 parent CHW 已落定但 prover 不知情的情形，避免 ~280k gas + off-chain SP1 工作浪费；race window（`prove(bytes)` 先落然后 parent CHW 后落）需 prover SDK 自检 + 私有 mempool 抗 race
- **permissionless**：任何人都可调；frontrun 防护靠 zk public input `proverAddress = msg.sender`

**2 步执行流程**（原子；不改 status，只标记）：

#### Step 1 — 派生 public input + SP1 verify

与 §6 Phase 2 Step 3 `prove(uint64,bytes)` **唯一差别**：`claimBlockNum = startingOutputRoot.l2SequenceNumber + batchSize`（全 batch 跨度）而非 `SEGMENT_SIZE × (k+1)`（per-segment）。其余字段（`l1Head = Hash.unwrap(l1Head())`, `l2PreRoot`, `claimRoot`, `rollupConfigHash`, `rangeVkeyCommitment`, `proverAddress=msg.sender`）一致。SP1 aggregation 程序原生支持任意 block delta，同 vkey 可验证两种 proof。

#### Step 2 — 推进 `claimData.status → UnchallengedAndValidProofProvided` + 记录 prover address

```solidity
claimData.status = ProposalStatus.UnchallengedAndValidProofProvided;   // 4 态中独立标记，不借用 Unchallenged
claimData.prover = msg.sender;                   // 记录 prover address (V1 ClaimData.prover 对齐)
emit UnchallengedAndValidProofProvided(msg.sender);
```

> **不动 GameStatus**：与 V1 `prove()` 对齐——只推进 `claimData.status`，GameStatus 翻转由后续 `resolve()` 完成。用独立枚举值（非借用 Unchallenged）显式标记早证态，off-chain indexer 单读 `claimData.status` 即可判别。

**gameOver() 短路逻辑**（详见 §12.6.1）：

```solidity
function gameOver() public view returns (bool) {
    ProposalStatus s = claimData.status;
    if (s == ProposalStatus.Resolved) return true;
    if (s == ProposalStatus.UnchallengedAndValidProofProvided) return true;     // ★ early-finalize 标记态
    if (s == ProposalStatus.Unchallenged) {
        return block.timestamp >= Timestamp.unwrap(challengeEnd());
    }
    // s == Challenged: two terminal triggers
    //   (a) Early-finalize: challengeEnd 已过 + 所有已 challenged 段被 prove
    //       （challengeEnd guard MANDATORY，详见下方 SAFETY NOTE）
    //   (b) 正常 timeout: proveDeadline 到期
    if (block.timestamp >= Timestamp.unwrap(challengeEnd()) && totalProved == totalCountered) {
        return true;
    }
    return block.timestamp >= Timestamp.unwrap(claimData.proveDeadline);
}
```

> **SAFETY — challengeEnd guard on Challenged 早完成不可省略**：
>
> Challenged 状态下 `totalProved == totalCountered` 在 challenge 窗口内只是瞬态等式（仍可来新 challenger）。若省略 guard，bot 可抢跑 resolve() 锁 DW，剥夺后到 challenger 的合法下注权——收益（节约 ≤ MAX_PROVE_DURATION 等待）不足以 justify 这一漏洞。修复：`challengeEnd` 已过 ∧ `totalProved == totalCountered` 两条件 AND，缺一不可。
>
> **vs UnchallengedAndValidProofProvided**：UnchallengedAndValidProofProvided 早完成跳过 challenge 窗口是 §6.3.5 的 design intent（proposer 抢先 prove(bytes) 锁 game，`challenge()` 主动 revert AlreadyFullProved）；Challenged 状态下未加 guard 的早完成是**意外副作用**。

**resolve() UnchallengedAndValidProofProvided 分支**：详见 §6.3 resolve pseudo-code（UnchallengedAndValidProofProvided 与 Unchallenged 合并分支，bond 流向一致——无 challenger → CREATE_BOND 退 proposer）。

**事件**：`event UnchallengedAndValidProofProvided(address indexed prover)`（独立于 `Proved(prover, segment)`，便于 indexer 区分两条路径）

**典型时间线（happy path）**：

```
T0 ─── T0+0.1d ───────── T0+0.2d ────── T0+1d (challengeEnd) ─── ...
│         │                 │              │
create    prove(bytes)      resolve()      无关
          (off-chain ~30min  (任何人)
           for ~250k blocks) → DW finalized
```

→ 整 finalize 时间 ≈ 链下 prove + 2 笔链上 tx ≪ 1 day 的 challenge 窗口等待。

**与 challenge() 的并发竞态**：`claimData.status` 单字段原子翻转保证两者最多一方推进。`prove(bytes)` 先落 → 后到 `challenge(k)` 因 `claimData.status == UnchallengedAndValidProofProvided` revert `AlreadyFullProved`；反之 `challenge(k)` 先落 → `prove(bytes)` revert `NotUnchallenged`。SDK 据此区分"被另一 challenger 占可换 game" vs "已 full-proved 应放弃"两种 race-loss。

**N=1 退化**：`batchSize == SEGMENT_SIZE`，`prove(bytes)` 与 `prove(0,...)` public input 完全等价；接口仍互斥（前者要求无 counter，后者要求 k 已 counter）。N=1 路径几乎完全恢复 V1 OPSuccinctFaultDisputeGame 语义，仅 challenge ABI 改名 `challenge(uint64)`，prove 多一个 `(uint64,bytes)` overload。

**Gas 与经济注**：`prove(bytes)` ~280k gas + resolve() ~50k gas；off-chain SP1 prove 全 batch 比 per-segment 贵 → 仅当下游需要 fast finalize（bridge / sequencer 续期 / governance）时划算，honest case 默认走"无 challenge → challengeEnd 后 resolve DW"路径（链下 0 成本，链上 1 day 延迟）。

---

### Phase 4 — Bond Settlement (`closeGame` + `claimCredit`)

**总体设计**：
- **`resolve()`**：DW 路径显式 push CREATE_BOND 给 proposer；CHW 路径不 push，留池等待 lazy 分配
- **`closeGame()`**：纯 mode gating——按 ASR `isGameProper` 把 `bondDistributionMode` 从 UNDECIDED 推到 NORMAL/REFUND，不写 bond
- **`claimCredit(_recipient)`**：所有角色统一提款入口——内部首调 `closeGame()`；NORMAL mode 下 S-path challenger 段未结算时 lazy settle（CHAL_BOND + 可能 CREATE_BOND），末尾读 ledger 转账
- **lazy 设计**：每个 S challenger 自付 settle 成本；CREATE_BOND 在 first S-claimer 触发 lazy lowestSIndex 计算后归属自动确定，避免 closeGame O(N) gas bomb

> **vs OP-stack `FaultDisputeGame.sol`**：OP-stack 用 `resolveClaim(claimIndex, numToResolve)` + ResolutionCheckpoint 分批续传；本 spec 用 first-touch lazy compute on `claimCredit`——目的相同，手段贴近 V1 单 `claimCredit` API。

---

#### 6.4.1 `closeGame()` — 纯 mode gating

**接口**：`function closeGame() public;`

**Canonical pseudo-code**（与原合约 [closeGame](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L531) 完全一致）：

```solidity
function closeGame() public {
    // 1. Idempotency: 已 NORMAL 或 REFUND 直接 return（不 revert，避免破坏 claimCredit 内部调用链）
    if (bondDistributionMode == BondDistributionMode.NORMAL
     || bondDistributionMode == BondDistributionMode.REFUND) {
        return;
    } else if (bondDistributionMode != BondDistributionMode.UNDECIDED) {
        revert InvalidBondDistributionMode();   // sanity
    }

    // 2. Game 必须 finalized（ASR 视角，含 dispute game finality delay）
    if (!ANCHOR_STATE_REGISTRY.isGameFinalized(IDisputeGame(address(this)))) {
        revert GameNotFinalized();
    }

    // 3. 尝试推进 anchor game；失败不阻塞（多 game 竞争 anchor 时只有一个成功）
    try ANCHOR_STATE_REGISTRY.setAnchorState(IDisputeGame(address(this))) {} catch {}

    // 4. 判 mode：proper game → NORMAL，否则 REFUND
    bool properGame = ANCHOR_STATE_REGISTRY.isGameProper(IDisputeGame(address(this)));
    bondDistributionMode = properGame
        ? BondDistributionMode.NORMAL
        : BondDistributionMode.REFUND;

    emit GameClosed(bondDistributionMode);
}
```

**Revert mapping**（按执行顺序）：

| revert 顺序 | 触发条件 | error |
|---|---|---|
| 1 | `bondDistributionMode ∉ {UNDECIDED, NORMAL, REFUND}` | `InvalidBondDistributionMode` |
| 2 | `!ANCHOR_STATE_REGISTRY.isGameFinalized(...)` | `GameNotFinalized` |

**关键设计要点**（与 V1 原合约一致）：
- **Idempotent**：已 NORMAL/REFUND 直接 return（不 revert）——`claimCredit()` 每次都先走 `closeGame()`，必须容忍重复调用
- **`isGameFinalized` 前置 gate**：ASR 定义 `resolvedAt + finality_delay ≤ block.timestamp`（governance veto 缓冲），未到则 revert。与 V1 [line 543](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L543) 同 pattern
- **`try-catch setAnchorState` silent failure intentional**：与 V1 [line 550](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L550) 对齐。anchor 推进失败**不阻塞 bond distribution**——bond 流向已由 resolve() + prove() + claimCredit 完全确定，与 anchor 状态独立；catch 后仍 `bondDistributionMode = NORMAL`，emit `GameClosed`
- **`isGameProper` 决定 mode**：proper → NORMAL；否则 REFUND
- **不写 ledger**：所有 bond 分发在 resolve() / prove() Step 4 / claimCredit() S-path settle 中完成

**事件**：`event GameClosed(BondDistributionMode mode);`

---

#### 6.4.2 `claimCredit()` — 单一提款入口 + lazy S-path settle

**接口**：`function claimCredit(address _recipient) external;`

**语义定位**：**所有角色的统一提款入口** —— proposer / S challenger / L challenger / pure prover 共用此函数；任意第三方也可代付 gas 调 `claimCredit(target)`。匹配原 [OPSuccinctFaultDisputeGame.sol:500](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L500) 单一 claimCredit API 设计。

**调用前提**：内部首调 `closeGame()` lazy gating（确保 `bondDistributionMode` 已决定）。

**Canonical pseudo-code**：

```solidity
uint64 constant LOWEST_S_NOT_SET = type(uint64).max;
// uint64 public lowestSIndex;  // 由 initialize() 显式写为 LOWEST_S_NOT_SET (§6 Phase 0)
//                              // CHW 路径下首次 S claim 时 lazy 计算覆写

function claimCredit(address _recipient) external {
    closeGame();   // lazy gating: 确保 bondDistributionMode 已决定（idempotent，已设置则 no-op）

    // === REFUND mode：完全沿用原合约路径，所有 depositor 原路退还 ===
    if (bondDistributionMode == BondDistributionMode.REFUND) {
        uint256 credit = refundModeCredit[_recipient];
        if (credit == 0) revert NoCreditToClaim();
        refundModeCredit[_recipient] = 0;
        normalModeCredit[_recipient] = 0;   // 双清零防 double-claim 跨 mode
        _transfer(_recipient, credit);
        return;
    }

    // === NORMAL mode 内部 settlement ===
    // 若 _recipient 是 S-path challenger 且 segment 未结算 → lazy push CHAL_BOND + 可能的 CREATE_BOND
    if (challengers[_recipient].countered) {
        uint64 k = challengers[_recipient].counteredIndex;
        DisputeEntry storage d = disputes[k];
        if (!d.proved && !d.claimed) {
            // S path: 退还 CHAL_BOND
            d.claimed = true;
            uint256 selfBond = challengers[_recipient].bond;
            challengers[_recipient].bond = 0;
            normalModeCredit[_recipient] += selfBond;

            // CHALLENGER_WINS 时 lowest-S winner takes all CREATE_BOND
            // 但若 §9.4.b parent-CHW + totalCountered==0 已 burn CREATE_BOND，跳过本块
            if (status == GameStatus.CHALLENGER_WINS && !createBondPushedAtResolve) {
                if (lowestSIndex == LOWEST_S_NOT_SET) {
                    // Lazy 计算（首调用者付遍历成本，bounded by numSegments ≤ 256）
                    uint64 found = LOWEST_S_NOT_SET;
                    for (uint64 j = 0; j < numSegments; j++) {
                        DisputeEntry storage dj = disputes[j];
                        if (dj.counteredBy != address(0) && !dj.proved) {
                            found = j;
                            break;
                        }
                    }
                    // Inv 32: status == CHW ∧ !createBondPushedAtResolve ⟹ S != ∅
                    // (resolve() CHW 分支保证 — empty-S 路径已 burn 并 set createBondPushedAtResolve)
                    // 若 found == LOWEST_S_NOT_SET 即合约严重 bug；spec/impl 用 assert
                    assert(found != LOWEST_S_NOT_SET);
                    lowestSIndex = found;
                }
                if (k == lowestSIndex) {
                    normalModeCredit[_recipient] += CREATE_BOND;
                }
            }
        }
        // L path 或 d.claimed 已 true：无需 settle（L bond 已在 prove Step 4 即时发给 provedBy）
    }

    // === 最终转账 ===
    uint256 credit = normalModeCredit[_recipient];
    if (credit == 0) revert NoCreditToClaim();
    refundModeCredit[_recipient] = 0;   // 双清零
    normalModeCredit[_recipient] = 0;
    _transfer(_recipient, credit);
}

function _transfer(address to, uint256 amount) internal {
    (bool ok, ) = to.call{ value: amount }(hex"");
    if (!ok) revert BondTransferFailed();
}
```

**各角色的 claimCredit 行为表**：

| 角色 | settle 块行为 | 最终转账 |
|---|---|---|
| **proposer** | 跳过 settle 块（challengers[proposer].countered == false）；读 `normalModeCredit[proposer]`（resolve 时已 push CREATE_BOND if DW） | CREATE_BOND（DW）/ 0 revert NoCreditToClaim（CHW）|
| **S challenger**（lowest）| 自动 settle：refund CHAL_BOND + CREATE_BOND 独占 | CHAL_BOND + CREATE_BOND |
| **S challenger**（非 lowest）| 自动 settle：仅 refund CHAL_BOND | CHAL_BOND |
| **L challenger**（segment 已 prove）| settle 块识别 `d.proved == true`，no-op；normalModeCredit 为 0 | 0 → revert NoCreditToClaim |
| **pure prover**（非 challenger）| 跳过 settle 块；读累计 L bonds（prove Step 4 已 push）| Σ L bonds 该 prover 赚到的 |
| **REFUND mode 下所有角色** | 走 refundModeCredit 分支 | 原始 deposit |

**Revert mapping**（按执行顺序）：

| revert 顺序 | 触发条件 | error |
|---|---|---|
| 1 | `closeGame()` 内部 revert（详见 §6.4.1 表） | (透传) |
| 2 | REFUND mode ∧ `refundModeCredit[_recipient] == 0` | `NoCreditToClaim` |
| 3 | NORMAL mode lazy compute 后 `found == LOWEST_S_NOT_SET` (sanity) | `assert` (Inv 32 保证不触发) |
| 4 | NORMAL mode settle 后 `normalModeCredit[_recipient] == 0` | `NoCreditToClaim` |
| 5 | `_transfer` 外部 call 失败 | `BondTransferFailed` |

**lazy 计算正确性 + reentrancy**（详细论证见 §10 安全分析）：
- O(numSegments) 扫描成本由首个 S claimer 承担（N=256 最坏 ~540k gas，典型 loop 早退）；`lowestSIndex` 写入对所有 caller 可见
- 抢调用顺序不影响 CREATE_BOND 最终归属（sock-puppet `k ≠ lowestSIndex` 拿不到，真正 lowest-S 后续调按存储值领）
- `d.claimed` per-segment flag 防同一 challenger 重复 settle
- CEI 模式：`_transfer` 是唯一外部调用且放末尾，所有 ledger 写入先行；reentrancy 二次调用因 `normalModeCredit == 0` revert `NoCreditToClaim`

**事件**：无（与原合约一致 —— claimCredit 不 emit；off-chain indexer 通过 ETH transfer trace / receipt logs 追踪提款）

---

#### 6.4.3 DisputeEntry 新增 `claimed` 字段

为支持 §6.4.2 的 lazy per-segment settle，`DisputeEntry` 增加 `bool claimed` 字段标记 "该 segment 的 S-path CHAL_BOND 已 push 给 challenger"：

```solidity
struct DisputeEntry {
    address counteredBy;      // 20 B
    bool    proved;           //  1 B
    bool    claimed;          //  1 B  ★ 新增 (§6.4.2 lazy settle 标记)
    address provedBy;         // 20 B
}
```

Packing：slot a = counteredBy(20B) + proved(1B) + claimed(1B) = 22B / 32B ✓；slot b = provedBy(20B) ✓。仍 2 slots。

**§6.4.2 invariant**：`claimed == true ⟹ challengers[d.counteredBy].bond == 0`（已结算）；反之 `claimed == false ∧ d.proved == false ∧ status == Resolved ⟹` 该 S challenger 的 claimCredit 仍可触发 settle。

---

**Resolve race attack 防护**：`!gameOver()` guard 强制 resolve 仅在 challenge / prove 窗口结束后进行；OP-stack 原合约 [line 449-454](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L449) 同 pattern。

---

## 七、CWIA Layout 边界规则

### 7.1 Open Interval 设计

CWIA extraData 中存的 intermediate roots **不包含端点** `segment_hash_0` 与 `segment_hash_{numSegments}`（链上已知，分别来自 parent game / anchor 与 CWIA `rootClaim()`）。

```
segment_hash_0          ← startingOutputRoot.root (链上 storage; boundary 0)
segment_hash_1          ← intermediateRoot(0) (CWIA, extraData[0]; 0-indexed: i=0 → boundary 1)
segment_hash_2          ← intermediateRoot(1) (CWIA, extraData[1]; boundary 2)
...
segment_hash_{N-1}      ← intermediateRoot(N-2) (CWIA, extraData[N-2]; boundary N-1)
segment_hash_N          ← rootClaim() (CWIA standard arg #2; boundary N)
```

**索引关系**：`intermediateRoot(i) = boundary[i+1]` (i ∈ [0, N-2])；起点端 boundary[0] 与终点端 boundary[N] 不进 intermediateRoot 名空间。

总 boundary 数 = `numSegments + 1`；CWIA extraData 携带的 root 数 = `numSegments - 1`（open interval：两端不计）。

### 7.2 Dispute index 与 boundary 的映射

设 dispute index `k` 标记 segment[k] (boundary[k] → boundary[k+1])。按 `intermediateRoot(i) = boundary[i+1]` 反推：boundary[k] = intermediateRoot(k-1)（中间）/ boundary[k+1] = intermediateRoot(k)（中间）。

| Dispute index k | Segment 范围 | claimPre 来源 (boundary k) | claimPost 来源 (boundary k+1) |
|---|---|---|---|
| `k = 0` | block (s, s+SEGMENT_SIZE] | startingOutputRoot.root (storage) | `intermediateRoot(0)` (or `rootClaim()` if N=1) |
| `1 ≤ k ≤ numSegments - 2` | block (s+SEGMENT_SIZE*k, s+SEGMENT_SIZE*(k+1)] | `intermediateRoot(k - 1)` | `intermediateRoot(k)` |
| `k = numSegments - 1` | block (s+batchSize-SEGMENT_SIZE, s+batchSize] | `intermediateRoot(N - 2)` | `rootClaim()` |

其中 `s = startingOutputRoot.l2SequenceNumber`。

### 7.3 N=1 退化情形

- 只有 segment 0，dispute index k ∈ {0}
- `claimPre = startingOutputRoot.root`、`claimPost = rootClaim()` —— 都来自链上已知字段
- CWIA extraData 中 0 个 intermediate root，长度 = 0x24（仅 l2SeqNum + parentIdx），与原 op-succinct 字节级兼容
- 协议层视角：相当于 V0 op-succinct 模式 + 本协议的 multi-challenger / dedup / bond 经济模型外壳

### 7.4 `numSegments + 1` boundary 校验完整性

- `segment_hash_0` 不可造假：合约层强制 `startingOutputRoot.root` 来自 parent.rootClaim() 或 anchor，proposer 不能 override
- `segment_hash_N` 不可造假：是 CWIA `rootClaim()`，game UUID 的一部分；factory 创建时已确定，proposer 无法事后修改
- `segment_hash_1..N-1` 可以由 proposer 任意选择，但需要对其负责：被挑战的段如果 root 错，proposer 在 prove 阶段无法生成合法 SP1 proof → CHW 失 CREATE_BOND

→ 端点强约束 + 中间经济激励约束的双层防护。

---

## 八、Clock & Timeline 设计

### 8.1 单 Deadline 字段 + 派生 challengeEnd (initialize 一次性写入，永不更新)

```solidity
struct ClaimData {
    address prover;                  // §6 Phase 3.5 `prove(bytes)` 写 msg.sender；address(0) = 未 `prove(bytes)`；与 V1 ClaimData.prover 对齐
    Timestamp proveDeadline;         // ← initialize 写入 createdAt + MAX_CHALLENGE_DURATION + MAX_PROVE_DURATION，永不更新
    uint32 parentIndex;              // 与 prover + proveDeadline pack 进同 slot (20+8+4=32B ✓)
    ProposalStatus status;           // 4-value enum; slot 2 alone
    Claim claim;                     // = rootClaim(); slot 3
}

// challengeEnd 不存 storage，纯派生 view function
function challengeEnd() public view returns (Timestamp) {
    return Timestamp.wrap(uint64(Timestamp.unwrap(createdAt)) + Duration.unwrap(MAX_CHALLENGE_DURATION));
}
```

**与原合约的差异**：原 op-succinct 在 ClaimData 中有 `deadline` 单字段，在 challenge 时滚动更新为 `block.timestamp + MAX_PROVE_DURATION`。本 spec **保留单字段**（rename 为 `proveDeadline`），但改为 initialize 时一次性写入——**绝对时间锚定**而非滚动更新。`challengeEnd` 由 `createdAt + MAX_CHALLENGE_DURATION` 派生 view 计算（immutable + storage 一次 SLOAD ~2.1k gas，调用 site 远少于 SSTORE 节省）。

**为什么用绝对锚定**：
- 防 Resolve race attack：原合约滚动 deadline 在多次 challenge 时窗口会扩大，本 spec 锁定 absolute window
- 简化 invariant：`challengeEnd < proveDeadline` 永久成立（同 initialize 时刻派生 / 写入，二者用同一 `createdAt` 锚点），便于 resolve / claimCredit 各分支判断
- challenger 在 challenge 窗口内任意时刻 select 都不影响 prove 窗口长度——保护后到 challenger 的 prove 公平性

**为什么单字段（不双字段）**：
- 节省 1 个 storage slot（ClaimData 从 3 slot 降到 2 slot，详见 §12.3 slot 映射表）
- 节省 1 次 SSTORE / initialize（gas: ~20k）
- `challengeEnd` 调用频率低（仅 challenge 入口检查 + Unchallenged 路径 resolve 检查），view 函数 SLOAD `createdAt` 一次 ~2.1k gas vs SSTORE 节省 ~20k，**净节省**

### 8.2 时间线

```
T0 = createdAt = block.timestamp (initialize 时刻)
challengeEnd  = T0 + MAX_CHALLENGE_DURATION       (≈ T0 + 1d)
proveDeadline = challengeEnd + MAX_PROVE_DURATION (≈ T0 + 2d)

Phase 1 (challenge window):    [T0, challengeEnd)
Phase 2 (prove window):        [T0_first_challenge or any T, proveDeadline)
                                ↑ challenger 可在 challenge window 内任意时刻 select
                                  prover 可在 select 之后任意时刻 prove
Phase 3 (resolve trigger):     block.timestamp >= proveDeadline (or sooner if status==Unchallenged + timeout)
Phase 4 (bond settlement):     any time after resolve
```

### 8.3 Clock 不变式

- **Invariant 8a**：`challengeEnd() < proveDeadline` 永久成立
- **Invariant 8b**：`block.timestamp ≥ proveDeadline` 时 game 必可 resolve（无论 status 是 Unchallenged / Challenged）
- **Invariant 8c**：challenge() 调用必须满足 `block.timestamp < challengeEnd()`
- **Invariant 8d**：prove() 调用必须满足 `block.timestamp < proveDeadline`
- **Invariant 8e**：resolve() 调用必须满足 `block.timestamp >= challengeEnd()`（Unchallenged 路径）或 `block.timestamp >= proveDeadline`（Challenged 路径）

### 8.4 时间参数推荐（生产部署）

| 参数 | 推荐值 | 调整原则 |
|---|---|---|
| `MAX_CHALLENGE_DURATION` | 1 day | 给 challenger 足够时间本地 replay 全 batch + 网络下载 / archive 查询 |
| `MAX_PROVE_DURATION` | 1 day | 给 prover 足够时间生成 SEGMENT_SIZE-block SP1 proof（含队列等待 / 重试） |

本 spec 下 SEGMENT_SIZE 是 per-game variable，不同 game 的 prove cost 不同。建议 `MAX_PROVE_DURATION` 按**预期最大 SEGMENT_SIZE** 部署场景的 prove 时长（含 buffer）校准。

---

## 九、Bond 分配规则

### 9.1 双账本设计

```solidity
mapping(address => uint256) public refundModeCredit;    // deposit ledger（永久跟踪 deposit）
mapping(address => uint256) public normalModeCredit;    // settlement ledger（NORMAL mode 写入）
```

- `refundModeCredit[addr]`：每次 deposit（initialize / challenge）累加；REFUND mode 下从此 ledger 退还
- `normalModeCredit[addr]`：在 prove（L bond push）/ resolve（CREATE_BOND 分配）/ closeGame 中写入；NORMAL mode 下从此 ledger 退还

**两个账本独立**——同一地址在 NORMAL / REFUND 下结算源不同；REFUND 不消费 NORMAL 字段。

### 9.2 Bond 集合定义

设 `D = {k : disputes[k].counteredBy != 0}`（被 select 的 dispute 集合）。

定义三个 partition：
- **S = {k ∈ D : disputes[k].proved == false}** —— "unproved" 集合（CHW 的依据）
- **L = {k ∈ D : disputes[k].proved == true}** —— "proved" 集合（DW 的依据；prove 时 L bond 已 push）
- **W = {k ∉ D}** —— "unchallenged" 集合（不影响 bond 分配）

恒等式：`|D| = |S| + |L|`、`totalCountered = |D|`、`totalProved = |L|`。

### 9.3 各 mode 下 bond 流向

#### NORMAL mode + DEFENDER_WINS

发生于以下**三种**触发条件之一（与 §6 Phase 3 resolve() 4 态分支 + parent-DW 前提一致）：

1. **Clock-Unchallenged**：`claimData.status == Unchallenged ∧ block.timestamp ≥ challengeEnd()`（无 challenger，等到 challenge 窗口截止）
2. **UnchallengedAndValidProofProvided**（§6 Phase 3.5 早 finalize 通道）：`claimData.status == UnchallengedAndValidProofProvided`（`prove(bytes)` 已验整 batch，可在 challengeEnd 前任意时刻 resolve）
3. **Clock-Challenged-allProved**：`claimData.status == Challenged ∧ block.timestamp ≥ proveDeadline ∧ totalProved == totalCountered`（即 `S = ∅`，全部 disputed segment 都已 prove）

```
proposer:
  normalModeCredit[proposer] += CREATE_BOND      ← 退回 CREATE_BOND

L 集合各 segment:
  normalModeCredit[provedBy] += CHAL_BOND        ← 已在 prove Step 4 即时 push（不在此处重复处理）

S 集合 = ∅（DW 前提；触发 1、2 时 totalCountered=0 自然蕴含；触发 3 时由 totalProved==totalCountered 保证）

注：触发 1、2 时 totalCountered=0，L=∅，无 CHAL_BOND 涉及，bond 流向退化为"仅 CREATE_BOND 退 proposer"
```

#### NORMAL mode + CHALLENGER_WINS

发生于：`block.timestamp ≥ proveDeadline ∧ totalProved < totalCountered`（即 `S ≠ ∅`，至少一段 unproved）。

资金归属详见 **§9.4.b.1 Case B**（S ≠ ∅）：CREATE_BOND → lowest-S challenger via lazy compute（§9.5）；非 lowest S 段 challenger 退回 CHAL_BOND；L 段 CHAL_BOND 已在 prove() Step 4 即时 push 给 prover。

#### REFUND mode

发生于：`isGameProper(this) == false`（game retired / blacklisted / parent chain integrity broken）。

资金归属详见 **§9.4.b.1 REFUND 模式列**：所有原始 depositor 从 `refundModeCredit` 原路退还，NORMAL 写入失效（claimCredit 走 refundModeCredit 分支）；prover SP1 工作无补偿（design-accepted 不对称，详见 §9.6.5）。

### 9.4 First-mismatch Winner Takes All（CREATE_BOND 分配）

#### 9.4.a 设计原理

CHW 时 CREATE_BOND 全额给 **lowest-S 的 challenger**（first-mismatch winner takes all），而非平分给 S 集合 —— 这是 anti-multi-divergence-dilution 的核心。

**Multi-divergence dilution 攻击**：proposer 构造多段 STF 断点的 batch，用 sock-puppet challenge 非 lowest 段。若 CREATE_BOND 平分，attacker 可分走一半 reward。
**防御**：仅 lowest-S challenger（最早断点 = honest 第一个发现者）拿 CREATE_BOND；attacker sock-puppet 在非 lowest 段拿不到 reward，反而损失 CHAL_BOND → 攻击经济不可行。

完整资金归属枚举见 §9.4.b.1。

#### 9.4.b Parent-forced CHW 的 bond 处理

**触发条件**：`getParentGameStatus() == CHALLENGER_WINS`。本 game 整 batch 的执行假设破坏，proposer 选错 parent 是其自身责任（应在 propose 前 link parent 时核查 parent 状态）。

**双分支**（resolve() 内）：

```
if (totalProved == totalCountered):
    // S = ∅ — 无 lowest-S challenger 接收 CREATE_BOND（lazy compute 被 §9.5
    //         的 `!d.proved` 门控）。涵盖 (a) totalCountered == 0 含 Unchallenged
    //         与 UnchallengedAndValidProofProvided，(b) totalCountered > 0 全证（V2 新边界 case）。
    //         两子情形折叠为同一 burn 路径：
    normalModeCredit[address(0)] += CREATE_BOND
    createBondPushedAtResolve = true     // 防 lazy claimCredit 重复处理
    // 不清零 refundModeCredit[gameCreator()] — burn 仅在 NORMAL mode 生效；
    //     REFUND mode override 需要保留 refundModeCredit 以回滚给 proposer
else:
    // S ≠ ∅ — 走正常 CHW lowest-S winner takes all（§9.4.a）
    // CREATE_BOND lazy push 给 lowestSIndex challenger via claimCredit（§9.5）
```

具体资金归属（NORMAL × REFUND 双模式、3 个 sub-case）详见 **§9.4.b.1**。

> **NOTE — REFUND-mode override**（与 V1 baseline 一致）：上述 burn 是 **NORMAL mode** 行为。若 closeGame() 因 `ASR.isGameProper() == false` 把 `bondDistributionMode` 设为 REFUND（Guardian 拉黑 / retire / paused），CREATE_BOND **退回 proposer**（不 burn），所有 NORMAL 结算 ledger 失效。
>
> **实现要点**：burn 分支 **必须仅** 写 `normalModeCredit[address(0)]`，**不能** 清零 `refundModeCredit[gameCreator()]`，否则 REFUND flip 时 proposer 无法回滚。该 ledger entry 在 REFUND mode 下不被读取（claimCredit 走 refundModeCredit 分支），自动失效。完整 invariant 见 §9.6（refundModeCredit 永不被 resolve/prove 修改）。

#### 9.4.b.1 Parent-CHW 资金归属完整二维表

下表枚举 parent-forced CHW 路径下，所有可能的 `(totalCountered, totalProved)` 配置在 NORMAL 与 REFUND 模式下每个角色的资金归属。**任何实现必须满足此表**（与 §11 Invariant 6 ledger 守恒一致）。

##### 设定

- **N** = `totalCountered`，**P** = `totalProved`，0 ≤ P ≤ N
- **S** = `{ k | k 被 challenge 但未被 prove }`，`|S| = N − P`
- **CREATE_BOND**：proposer 在 initialize 时存入的押金（从 `factory.initBonds(GAME_TYPE)` 读取）
- **CHAL_BOND**：每个 challenger 调 `challenge(k)` 时存入的押金
- 合约总持有 ETH：`CREATE_BOND + N × CHAL_BOND`
- **prove(k) Step 4 即时分发**：每次成功的 `prove(k, π)` 把 `challengers[k_challenger].bond` 推到 `normalModeCredit[msg.sender]`（详见 §6 Phase 2）

##### 模式触发

- **NORMAL**：`closeGame()` 时 `ASR.isGameProper() == true`（正常 game 结算）
- **REFUND**：`closeGame()` 时 `ASR.isGameProper() == false`（governance emergency 路径 — Guardian 拉黑 / retire / paused）

##### Case A：N = 0（无人挑战，含 Unchallenged 与 UnchallengedAndValidProofProvided）

合约持有 ETH = `CREATE_BOND`<br/>
`resolve()` 进入 burn 分支：`normalModeCredit[address(0)] += CREATE_BOND`，`createBondPushedAtResolve = true`

| 角色 | NORMAL 模式 | REFUND 模式 |
|---|---|---|
| Proposer | 0（`normalModeCredit[proposer]` 为 0，claimCredit revert `NoCreditToClaim`） | **CREATE_BOND**（从 refundModeCredit 退回） |
| UnchallengedAndValidProofProvided Prover（若有） | 0（SP1 工作无补偿，§9.4.b NOTE） | 0（同左） |
| address(0) | CREATE_BOND（ledger 记账，无 ETH 出口） | — |

**合约最终余额**：NORMAL = CREATE_BOND（**burned**，永久 stranded）；REFUND = 0

##### Case B：N > 0, P < N（S ≠ ∅，有未证明段）

合约持有 ETH = `CREATE_BOND + N × CHAL_BOND`<br/>
prove() Step 4 已分发：`P × CHAL_BOND` → P 个 prover 的 `normalModeCredit`<br/>
`resolve()` 走 fall through（不进入 burn 分支）；CREATE_BOND 在 claimCredit 由 lazy lowestSIndex 给 lowest-S（§9.4.a / §9.5）

| 角色 | NORMAL 模式 | REFUND 模式 |
|---|---|---|
| Proposer | 0 | **CREATE_BOND** |
| **L-path Challenger**（P 个段对应，其 CHAL_BOND 已被 prover 拿走） | 0 | CHAL_BOND |
| **S-path Challenger，非 lowest-S**（N − P − 1 个） | CHAL_BOND（settle block 退） | CHAL_BOND |
| **S-path Challenger，lowest-S**（1 个） | CHAL_BOND + **CREATE_BOND**（settle + winner-takes-all lazy push） | CHAL_BOND |
| Prover（P 个，每个证明 1 段） | CHAL_BOND/人（prove() Step 4 即时 push） | 0（normalModeCredit 失效；SP1 工作无补偿，§9.6.5） |

**合约最终余额**：NORMAL = 0（全部分完）；REFUND = 0

##### Case C：N > 0, P = N（S = ∅，全部段被证明）

合约持有 ETH = `CREATE_BOND + N × CHAL_BOND`<br/>
prove() Step 4 已分发：`N × CHAL_BOND` → N 个 prover 的 `normalModeCredit`<br/>
`resolve()` 进入 burn 分支：`normalModeCredit[address(0)] += CREATE_BOND`，`createBondPushedAtResolve = true`<br/>
（**此 sub-case 为 V2 新引入的边界 case**；V1 single-challenger 模型下不存在）

| 角色 | NORMAL 模式 | REFUND 模式 |
|---|---|---|
| Proposer | 0 | **CREATE_BOND** |
| Challenger（N 个，**全部 L-path**，CHAL_BOND 给 prover） | 0 | CHAL_BOND |
| Prover（N 个，每个证明 1 段） | CHAL_BOND/人 | 0（normalModeCredit 失效） |
| address(0) | CREATE_BOND（ledger 记账） | — |

**合约最终余额**：NORMAL = CREATE_BOND（**burned**）；REFUND = 0

##### 综合资金来源 × 模式去向

| 资金来源 | NORMAL 模式去向 | REFUND 模式去向 |
|---|---|---|
| **CREATE_BOND**（proposer initialize 存入） | Case A: **burn** to address(0)<br/>Case B: → **lowest-S challenger**（§9.4.a winner-takes-all）<br/>Case C: **burn** to address(0) | **所有 case：退回 proposer**（§9.6.5 emergency rollback 原则） |
| **CHAL_BOND**（每个 challenger 挑战时存入） | L 路径段：→ **prover**（prove() Step 4 即时 push）<br/>S 路径段：→ **challenger 自己**（claimCredit settle block） | **所有 case：退回原 challenger**（refundModeCredit 在 challenge 时已记录，不被 resolve/prove 修改） |
| **Prover SP1 工作成本** | 拿对应 L 段 CHAL_BOND 作奖励 | **REFUND 模式无补偿**（normalModeCredit 写入失效；§9.6.5 design-accepted） |

##### 守恒不变量摘要（详见 §11 Invariant 6）

```
NORMAL 模式（resolve 之后）:
    Σ normalModeCredit[addr] over all addr 
    == CREATE_BOND + N × CHAL_BOND - burn_amount
    
    burn_amount = CREATE_BOND  当 totalProved == totalCountered (Case A 与 C)
    burn_amount = 0            当 totalProved < totalCountered (Case B)

REFUND 模式（永久成立）:
    Σ refundModeCredit[addr] over all addr 
    == CREATE_BOND + N × CHAL_BOND

refundModeCredit 只在 initialize 与 challenge 时累加，resolve 与 prove 都不修改它。
```

##### 一句话语义总结

- **NORMAL 模式**：CREATE_BOND 给 lowest-S 或 burn；CHAL_BOND 按 L/S 路径分发给 prover/challenger；prover 拿 L 段 CHAL_BOND 作 SP1 工作奖励。
- **REFUND 模式**：所有 depositor 原路退回，整体 override NORMAL 结算；prover SP1 工作无补偿（与 §9.6.5 一致）。
- **核心设计原则**：REFUND mode = "这个 game 不算数"，emergency rollback 整体 override NORMAL-mode 结算。

#### 9.4.b.2 UnchallengedAndValidProofProvided + Parent-CHW 的 prover 经济损失

UnchallengedAndValidProofProvided game 在 parent CHW 时走 `totalProved == totalCountered → CREATE_BOND burn` 分支（UnchallengedAndValidProofProvided 蕴含 totalCountered == 0，落入 §9.4.b.1 Case A）。

- **`claimData.prover` 损失整 batch 的 SP1 工作成本**（batchSize >> SEGMENT_SIZE，远比 per-segment 高）
- **协议层无补偿**：`prove(bytes)` 是 best-effort fast-finalize 通道
- **推荐 prover 行为**：在 parent 状态不稳定（IN_PROGRESS + active challenger / governance event）时不应主动 `prove(bytes)`
- **`claimData.prover` 字段保留**为审计 / 仲裁 / 未来扩展 reward hook 留资料

与 §9.6.5 prover-loses-in-REFUND 是同性质的 design-accepted 不对称。

#### 9.4.c Per-game Clean Separation 与 Challenger Off-chain 行为规则

**问题**：parent game 后续 CHW 时，是否回收已经在本 game prove() 给 prover 的 CHAL_BOND（V1 sweep 行为）？

**本 spec 决策：不回收**。每个 game 各自结算，clean separation（与 §9.6.5 / §9.6.6 同原则）。

##### 协议语义二分

Challenger 调 `challenge(k)` 等价于对**一个特定命题**的对赌：

> "给定 `startingOutputRoot.root` 作为前提，segment k 的状态转移是错的"

这与另一个独立命题 "`startingOutputRoot.root` 本身是错的"（应 challenge parent game）是**两个不同的 fault 战场**。

| Challenger 想战的命题 | 应去的战场 |
|---|---|
| "R_parent 是错的" | challenge parent game |
| "假设 R_parent 对，段 k 是错的" | challenge child game 段 k |

**Prover 的 SP1 证明**在密码学上验证给定 `(R_pre, R_post, blockNum, configHash, vkey)` 之间的状态转移一致性，**与 R_pre 是否对应真实链状态无关**。因此：

- Challenger 在 child game 挑战段 k = **承诺"假设 parent 正确"的前提**
- Prover 提供合法 SP1 证明 = 在 challenger 选择的前提下**赢得对赌**
- 即使后续 parent 被证明 CHW，child 的对赌结果**不回滚**

##### 设计权衡

| 设计 | Challenger 激励 | Prover 激励 |
|---|---|---|
| V1 sweep（parent CHW 时 challenger 回收所有 bond） | 可机会主义 challenge 所有 child（赌 parent CHW 拿回 bond） | 工作收益不稳定，做真实工作也可能被回收 |
| **本 spec（V2，保留 prover L-bond）** | 必须谨慎挑选战场，challenge child = 接受"假设 parent 对"的风险 | 数学正确即可获 CHAL_BOND，激励对齐 |

V2 是更干净的纳什均衡 — 每个 game 各自结算。

##### Challenger SDK 实现规则（MUST）

每次准备 `challenge(k)` 之前，challenger off-chain 工具**必须**：

1. **先验证 `parent.status()` 与 parent 的 fraud 信号**
2. **若 parent 已 CHW 或观察到 parent fraud 信号但未 resolve**：应去 `challenge` parent game 而非 child；当前 child game 的 CHAL_BOND 在 parent-CHW Case B/C 中大概率落入 prover（见 §9.4.b.1）
3. **若 parent 状态稳定（DEFENDER_WINS 或确认即将 DW）**：才在 child game 上 challenge(k)

不遵守此规则的 challenger 自担风险 — 协议层不补偿。

### 9.5 Lazy `lowestSIndex` Compute

#### 9.5.1 实现

```solidity
uint64 public lowestSIndex;          // initialize 时设 type(uint64).max sentinel
uint64 constant LOWEST_S_NOT_SET = type(uint64).max;

// 注：lazy compute 逻辑内联在 §6.4.2 claimCredit() 的 NORMAL+CHW 分支中（首调 S-path challenger 触发）。
//     此处仅展示算法骨架以便理解：
//
// 进入条件（claimCredit 内）:
//   - status == CHALLENGER_WINS
//   - bondDistributionMode == NORMAL
//   - !createBondPushedAtResolve  (parent-CHW + totalCountered==0 burn 路径已排除)
//   - lowestSIndex == LOWEST_S_NOT_SET (首次)
//
// 计算:
uint64 found = LOWEST_S_NOT_SET;
for (uint64 j = 0; j < numSegments; j++) {
    DisputeEntry storage dj = disputes[j];
    if (dj.counteredBy != address(0) && !dj.proved) {
        found = j;
        break;     // 遍历升序，第一个命中即 lowest
    }
}
assert(found != LOWEST_S_NOT_SET);   // Inv 32: CHW ∧ !createBondPushedAtResolve ⟹ S != ∅
lowestSIndex = found;
```

#### 9.5.2 何时触发

Lazy compute 在 `claimCredit(_recipient)` 内部，**首个 S-path challenger 调用** claimCredit 时触发（详见 §6.4.2 pseudo-code）——不在 resolve 阶段强制计算，避免 resolve 路径 worst-case 遍历。

> **第三方可代付**：任何人可调 `claimCredit(anyAddr)` 提前 trigger lazy compute（若 anyAddr 不是 S challenger，settle 块不进入，但 `claimCredit` 不会主动 trigger compute——compute 仅在 S-path 内部进行）。要预付 gas，需要选一个真实 S challenger 地址作 recipient。

#### 9.5.3 gas 分析

- worst case：numSegments = 256，全部 selected，全部 proved 除最后一个 → 256 个 disputes[k] SLOAD ≈ 2.5k gas × 256 ≈ 640k gas
- typical case：numSegments = 10-100，lowest 是前几个 → few × SLOAD ≈ 几 k gas

→ worst case 在 256 上限下仍可接受（< 1M gas，远低于 block gas limit）。

### 9.6 不变式

#### 9.6.1 Bond 守恒（NORMAL mode）

```
sum(normalModeCredit[addr] for all addr after closeGame)
  ==
CREATE_BOND + |D| × CHAL_BOND - burn_amount
```

其中：

- `burn_amount > 0`（= CREATE_BOND）iff parent-forced CHW 且 `totalProved == totalCountered`（详见 §9.4.b 与 §9.4.b.1 Case A/C）
- 否则 `burn_amount = 0`
- burn 计入 `normalModeCredit[address(0)]`，技术守恒严格 ==，无 leakage

完整资金归属枚举见 §9.4.b.1 三 case 表格。

#### 9.6.2 Bond 守恒（REFUND mode）

```
sum(refundModeCredit[addr] for all addr at deposit time)
  ==
sum(claimCredit 退还总额)
  ==
CREATE_BOND + |D| × CHAL_BOND
```

#### 9.6.3 L bond 守恒

```
对每个 k ∈ L:
  prove() Step 4 时：
    challengers[challenger].bond from CHAL_BOND → 0
    normalModeCredit[provedBy] += CHAL_BOND
  → 单 segment 守恒
```

#### 9.6.5 Prover 在 REFUND mode 的设计不对称

prove 时 L bond 即时 push 进 `normalModeCredit[prover]`，但**未消费** `refundModeCredit[challenger]`。若 game 最终走 REFUND mode：
- prover 的 `normalModeCredit[prover]` 写入作废
- challenger 的 `refundModeCredit[challenger]` 仍保有原始 CHAL_BOND，可原路退还

→ prover 损失 SP1 工作成本，challenger 拿回 CHAL_BOND。**这是 design-accepted 的不对称**：REFUND 是 governance 紧急路径，prover 应主动 monitor 上游 anchor 状态决定是否参与；同时 prover 不应在 game 状态不稳定（parent risky / chain governance event）时 prove。

#### 9.6.6 Parent-CHW 下 Prover 保留 L-bond

**Invariant**：本 game 通过 prove() Step 4 push 给 prover 的 L-bond，不因后续 parent CHW 回滚（与 §9.6.5 同原则："一旦在 NORMAL-mode 路径上结算，协议层不逆向回滚"）。

设计 rationale 与 challenger off-chain 行为规则详见 **§9.4.c**。

---

## 十、攻击面与防护

### 10.1 攻击分类与防御映射

| 攻击 | 防御机制 | 防御层 |
|---|---|---|
| **Multi-divergence dilution** | First-mismatch winner-takes-all（§9.4.a）+ social-layer race-loss-skip convention（§13.2 规则 2） | 经济 + social |
| **Decoy mismatch trap**（proposer 在右侧伪造可 prove 段 trap 粗心 challenger） | Social-layer first-mismatch only（§13.2 规则 1）+ race-loss-skip（§13.2 规则 2） | social |
| **Frontrun honest challenger 抢 segment slot** | Off-chain MEV-protected mempool；链上极简不做强防护；配合 race-loss-skip 保证 honest race loss 后退而求其次也不会变 W | off-chain + social |
| **Frontrun honest prover 抢 prove tx**（attacker 抢先 broadcast 用 same `(k, proofBytes)`） | `proverAddress = msg.sender` 进 zk public input —— attacker 用 honest proof 但替换 msg.sender，proof.publicValues.proverAddress 不匹配 → SP1 verify revert | on-chain |
| **Pile-on dilution**（多马甲 select 同一 index 稀释 reward） | Index-level dedup（§六 Phase 1）：每个 k 只能被 1 个 challenger select | on-chain |
| **Unbounded challenger DoS / resolve gas bomb**（不限数量小号挂号导致 resolve / claimCredit 爆 gas） | Per-segment dedup → `|D| ≤ numSegments ≤ MAX_NUM_SEGMENTS = 256` → lazy compute worst case bounded | on-chain |
| **Sock-puppet self-challenge** | First-mismatch winner-takes-all + race-loss-skip → sock-puppet 在非 lowest 段 select 无 CREATE_BOND 收益，自损 CHAL_BOND | 经济 |
| **Reentrancy in claimCredit** | OP-stack 标准 `claimCredit` checks-effects-interactions pattern | on-chain |
| **Parent-forced CHW grief**（attacker 在 parent CHW 时反复 trigger resolve 浪费 gas）| `gameOver()` check bypassed only when parent CHW —— 提早 resolve 不浪费时间 | on-chain |
| **Fast-finalize censoring DOS**（恶意 challenger frontrun `prove(bytes)` 把 game 强制走完整 ~2d 流程，自损 CHAL_BOND 换取 fast-finalize 失效）| **设计接受**——`prove(bytes)` 是 best-effort 优化通道，**不**承诺 liveness。详见 §10.3 | 设计接受 |
| **Same-range multi-N spam**（同 rootClaim + 不同 `numSegments` 通过 factory.create UUID 不冲突，可并存多个 game）| **设计接受**——honest case 无害（每 game 独立 challenge / bond），malicious case attacker 付 CREATE_BOND × N 自损。详见 §10.5 | 设计接受 |

### 10.2 与 blob 变体不存在的攻击面

本 spec 下**不存在**以下 blob 变体特有攻击：

- **Fast-supplyBlob race attack**（V2: proposer + 马甲快速 challenge + supplyBlob 压缩 selectDeadline）—— 本 spec 无 supplyBlob phase
- **Blob KZG forgery**（V2: 伪造 KZG commitment 让 precompile 验证错误 polynomial）—— 本 spec 无 KZG
- **Blob retention expiry**（V2: blob 18-day retention 内 challenge 窗口外的 forensic 不可行）—— 本 spec roots 永久存 CWIA
- **PeerDAS sampling DoS**（V2: post-Fusaka challenger 拿不到完整 blob）—— 本 spec 直接 L1 storage 读

### 10.3 Fast-finalize censoring DOS（设计接受）

**攻击场景**：
1. proposer / 第三方 prover 在 mempool 提交 ``prove(bytes)`(proof)` tx
2. 恶意 challenger 监听 mempool，frontrun 一个 `challenge(k)`（任意 segment，甚至完全 honest 的 game）
3. challenge 落块 → `claimData.status` 推到 `Challenged`
4. `prove(bytes)` 因 `claimData.status != Unchallenged` revert
5. game 强制进入 ~2 day 完整 challenge+prove 流程
6. 后续 proveDeadline 内 honest prover 调 `prove(k)` 把 segment 证下来，恶意 challenger 损失 CHAL_BOND

**攻击经济**：
- attacker 损失：1 × CHAL_BOND per game
- 攻击收益：fast-finalize 失效（game finalize 从 ~min 推迟到 ~2 day）
- 若**目标方对 fast finalization 的支付意愿 > CHAL_BOND**（bridge / sequencer 续期 / 时间敏感的 governance），attacker 可经济持续 grief

**为什么设计接受**：

| 选项 | 评估 | 决策 |
|---|---|---|
| (a) 抬 CHAL_BOND 到 grief 不可行 | 影响 honest challenger 经济门槛 | ✗ 损害 1-of-N 假设 |
| (b) 加 `challenge(k)` 的 minDelay（`prove(bytes)` 在 createdAt 后 1h 内独占）| 增加状态复杂度；honest challenger 仍要等 1h | ✗ 复杂度不值 |
| (c) 接受 DOS，承诺 `prove(bytes)` = best-effort | 协议简单；产品层用其他机制保 fast finality | **✓ 选择** |

**协议侧承诺与建议**：
- `prove(bytes)` 是 **optional fast-path**，**不承诺 liveness**——任何 challenger 都能廉价阻断
- 真正需要稳定 fast finalization 的场景（bridge withdrawals / sequencer financing）应当走链下提速机制（committee signing / fault-proof off-chain finality oracle / L2 sequencer commitments），**不应依赖 `prove(bytes)`**
- 普通 happy-path：无 challenger → 等 `MAX_CHALLENGE_DURATION` (~1 day) → 自然 resolve DW（无 DOS 风险）

**与原 op-succinct V1 对比**：
- V1 `prove()` 也可被同样 grief（attacker 用 challenge() 抢先把 game 推到 Challenged，但 V1 challenge() 不需要 challenger 提供任何 segment 信息），DOS 模式相同
- V1 同样设计接受（"prove does it for speed, not money"）
- 本 spec 沿用 V1 决策路径，无新增 DOS 风险（攻击面对称）

### 10.4 与原 op-succinct 共享的攻击面

本 spec 沿用 OP-stack / 原 op-succinct 标准防御：

- **Reproposal griefing**（factory.create UUID 防重复）—— 原合约 [line 229-247](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L229) 长度严格 == 校验
- **Parent CHW propagation**（recursive CHW from parent）—— resolve() 内部 `getParentGameStatus()` 检查
- **AccessManager bypass**（unauthorized proposer / challenger）—— `isAllowedProposer` / `isAllowedChallenger` 入口校验
- **ASR retired / blacklisted**（game 跨 impl 切换 / governance retired）—— closeGame() → REFUND mode

### 10.5 Same-range multi-N 并存（设计接受）

**机制**：factory.create UUID = `keccak(gameType, rootClaim, extraData)`。本 spec 下 `extraData` 内容 = `l2SequenceNumber || parentIndex || intermediateRoots[...]`，长度 = `0x24 + 0x20 × (numSegments - 1)`。**任何 extraData 维度差异都会产生不同 UUID**：
- 不同 `numSegments` → extraData 长度不同 → 不同 UUID
- 同 `numSegments` 但不同 `intermediateRoots` 内容 → 同长度不同 hash → 不同 UUID

因此 factory 允许同 `(rootClaim, batch range)` 但不同 N **或** 不同 intermediate-roots 序列的多个 game 并存。

**场景与影响**：

| 场景 | 行为 |
|---|---|
| **Honest 两 proposer 用不同 N** | 两 game 独立 challenge / resolve；都正确 → 都 DW，各自拿回 CREATE_BOND；只有一个能成 anchor（first to `ASR.setAnchorState`），其余 setAnchorState try-catch 失败但 bond 仍按 NORMAL 分配 |
| **Honest proposer 用同 N 但不同 intermediate roots** | 两 game 独立 challenge / resolve；提交错 intermediate 的会在 segment 级 challenge 中输；honest proposer 不需要预先和其他 proposer 协调 intermediates（自己的 SP1 工作能证明的 boundaries 就是正确的）|
| **同一 proposer 自己分裂 propose** | 付 CREATE_BOND × M 次（M = 变体数），每个独立竞赛；**没有经济收益**，纯自损 |
| **Bond 守恒** | per-game CREATE_BOND + CHAL_BOND 独立账本，互不串。§11 Invariants 1/2 仍成立 |
| **Challenge 行为** | 每个 game 各自独立挑战；§9.4.a multi-divergence dilution 防御在 game 内部生效，**不跨 game**（每 game 独立 lowest-S）|

**设计 rationale**：
- `numSegments` 是 per-game **可变**参数（§3 设计要点），proposer 自选分段策略；factory UUID 自然反映这种灵活性
- factory 层 dedup（"同 rootClaim 只允许一个 game"）会**牺牲 per-game 可变 N**的设计灵活性，得不偿失
- honest case 无害；malicious case 自损 —— **没有需要 spec 防御的实际威胁**

**Proposer / off-chain 行为约定**：
- Honest proposer：自由选 `numSegments` 创建 game，**无需查链上有无其他 N 的同 range game**——自己 game 的胜负只取决于自己 rootClaim 是否正确
- Off-chain indexer：同 batch range 可显示多个 game，按各自 status + bond outcome 独立追踪；anchor 候选按 ASR 内部策略选
- **不需要 SDK / monitor 做跨 game 去重**

> **vs V1**：V1 `numSegments` 固定隐式 = 1（单段），factory UUID 只受 rootClaim / parent 影响，不存在 multi-N 并存。本 spec 引入 per-game variable N 后**新增**了这个攻击面，但分析后确认无害。

---

## 十一、合约不变式

### 11.1 全局守恒不变式

1. **Deposit ledger 守恒**：`sum(refundModeCredit[addr] over all addr) == CREATE_BOND + totalCountered × CHAL_BOND`，永久成立
2. **Settlement ledger 守恒（NORMAL mode 后）**：`sum(normalModeCredit[addr] over all addr) == CREATE_BOND + totalCountered × CHAL_BOND - burn_amount`，其中 `burn_amount > 0` 仅在 §9.4.b parent-forced CHW + `totalProved == totalCountered` 时（含子情形 (a) totalCountered == 0 与 (b) totalCountered > 0 且全证 S = ∅；后者由 burn 路径显式处理，否则 CREATE_BOND 会 stranded）
3. **Bond field 守恒**：每个 `challengers[challenger].bond` 从 CHAL_BOND 起始；prove(k) 时清零（消费）；resolve 时如未 prove 则在 settlement 中 push 回 normalModeCredit
4. **Mode 单调**：`bondDistributionMode` 从 `UNDECIDED` 单向推进到 `NORMAL` 或 `REFUND`，永不回退
5. **Status 单调**：`status` 单向推进 `IN_PROGRESS → DEFENDER_WINS | CHALLENGER_WINS`；`ProposalStatus` 沿两条并行路径单向推进 `Unchallenged → {Challenged | UnchallengedAndValidProofProvided} → Resolved`，4 态间不可逆转

### 11.2 Per-game 派生不变式

6. **batchSize-numSegments 整除**：`batchSize % numSegments == 0`（initialize 时强校验，永久成立）
7. **numSegments 范围**：`1 ≤ numSegments ≤ MAX_NUM_SEGMENTS = 256`（initialize 时强校验）
8. **CWIA layout 完整性**：`calldatasize() == 0x7E + 0x20 × (numSegments - 1)`（initialize 时强校验）
9. **Deadline 单调**：`challengeEnd() ≤ proveDeadline` 永久成立 —— `challengeEnd()` 是 `createdAt + MAX_CHALLENGE_DURATION` 派生 view，`proveDeadline` 是 initialize 时写入的 `createdAt + MAX_CHALLENGE_DURATION + MAX_PROVE_DURATION`；二者基于同一 `createdAt`，且 `MAX_PROVE_DURATION ≥ 0` 保证严格序，永不更新

### 11.3 状态机不变式

10. **Resolved 终态**：`claimData.status == Resolved` 时所有 mutator function (challenge / prove / `prove(bytes)` / resolve) revert（注：`status` 是 GameStatus 顶层字段，`claimData.status` 是 ProposalStatus 内部字段，二者独立）
11. **Challenged 必有 challenger**：`claimData.status == Challenged` ⟺ `totalCountered ≥ 1`
12. **prove 必先 challenge**：`disputes[k].proved == true` ⟹ `disputes[k].counteredBy != address(0)`
13. **`countered` flag 永久保持**：prove(k) 时只清 `challengers[challenger].bond`，**不动** `challengers[challenger].countered` —— 防 re-challenge
14. **Index dedup 永久**：`disputes[k].counteredBy != address(0)` 后永久保持，不会被任何 mutator 重置

### 11.4 Lazy compute 不变式

15. **lowestSIndex sentinel**：initialize 时显式写 `lowestSIndex = type(uint64).max` —— Solidity default 0 会被 lazy compute 误判为"已计算且 lowest 是 segment 0"，必须显式 sentinel
16. **lowestSIndex 单调**：一旦 `_computeLowestSIndexIfNeeded()` 写入，`lowestSIndex` 永不更新（CHW 状态下 S 集合凝固）

### 11.5 CWIA 完整性不变式

17. **rootClaim 不可变**：CWIA standard arg #2 不可在 game 生命周期内修改
18. **intermediateRoot 不可变**：CWIA extraData 部分不可在 game 生命周期内修改
19. **startingOutputRoot 不可变**：initialize 时写入 storage 后永不修改

### 11.6 `prove(bytes)` 路径不变式

20. **`prove(bytes)` 前提**：`prove(bytes)` 仅在 `claimData.status == Unchallenged ∧ totalCountered == 0 ∧ block.timestamp < challengeEnd()` 时可调；任一条件破坏即 revert（参见 §6 Phase 3.5 revert mapping）。`totalCountered == 0` 由 `claimData.status == Unchallenged` 隐式蕴含（Invariant 11：`claimData.status == Challenged ⟺ totalCountered ≥ 1`），但保留显式 require 作防御性校验
21. **`prove(bytes)` 推进 claimData.status**：`prove(bytes)` 写 `claimData.status = ProposalStatus.UnchallengedAndValidProofProvided` + `claimData.prover = msg.sender`，**不动** `status`（仍是 `IN_PROGRESS`）—— `GameStatus` 翻转由后续 `resolve()` 完成。与 V1 `prove()` 推 `claimData.status = U+VP` + 写 `claimData.prover` 但不动 game.status 完全对齐
22. **`prove(bytes)` 与 challenge 互斥**：`claimData.status` 单字段原子翻转保证两者最多一方推进——`prove(bytes)` 先落块 → `UnchallengedAndValidProofProvided` → 后到 `challenge(k)` 因 §6 Phase 1 require `claimData.status == Unchallenged` revert `AlreadyFullProved`；反之先到 `challenge(k)` 推到 `Challenged` → 后到 `prove(bytes)` 因同 require revert `NotUnchallenged`
23. **UnchallengedAndValidProofProvided → gameOver() 立即短路**：`claimData.status == UnchallengedAndValidProofProvided` 在 §12.6.1 `gameOver()` 的第 2 检查（早于 challengeEnd / proveDeadline clock 判定）即返回 true；任何后续 `resolve()` 都可在 challengeEnd 前完成 finalize
24. **resolve() UnchallengedAndValidProofProvided 分支**（**前提**：`parentStatus == DEFENDER_WINS`）：`claimData.status == UnchallengedAndValidProofProvided` 在 resolve() 进入独立分支，直接推到 `DEFENDER_WINS`；bond 流向与"无 challenge + clock 到期"完全一致（CREATE_BOND 退 gameCreator，无 CHAL_BOND 涉及）。
    > **parent-CHW 例外**：若 `parentStatus == CHALLENGER_WINS`，§6 Phase 3 resolve() 在 gameOver() / claimData.status 分支**之前**就强制 `status = CHALLENGER_WINS`，**UnchallengedAndValidProofProvided 标记不能挽救一个 starting state 已错的 game**。此时 `totalCountered == 0`（UnchallengedAndValidProofProvided 蕴含），走 §9.4.b 子情形 → CREATE_BOND burn，`claimData.prover` 损失 SP1 工作成本（与 §9.6.5 prover REFUND mode 同性质不对称）。
25. **`prove(bytes)` 单次性**：`claimData.status` 仅从 `Unchallenged` 单向推进到 `UnchallengedAndValidProofProvided`，不可逆、不可重写（require `claimData.status == Unchallenged → revert AlreadyFullProved`）
26. **`claimData.prover` 字段语义**：`claimData.status == UnchallengedAndValidProofProvided ⟺ claimData.prover != address(0)`（同一 `prove(bytes)` tx 内原子写入）。
    > **V1 对齐**：字段保留在 ClaimData 内，名字与 V1 [ClaimData.prover](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L73) 一致；语义"谁提供了让 game 早 finalize 的 proof"也对应 V1。本 spec 把 per-segment prover 拆出去由 `disputes[k].provedBy` 接管；game-wide early-finalize prover 留在 `ClaimData.prover`，与 V1 ClaimData shape 1:1 对齐（仅去掉 `counteredBy`）。
    > **不参与协议核心逻辑**：核心 invariants 与 mutator 函数全用 `claimData.status` 判别；`claimData.prover` 仅用于 accountability / SDK 直读 / event indexer 便利（event 已带，storage 为冗余但有对齐价值）。
27. **`prove(bytes)` 与 per-segment prove 的 SP1 public input 独立**：`prove(bytes)` 的 `claimBlockNum = startingOutputRoot.l2SequenceNumber + batchSize`（全 batch 跨度）；prove(k) 的 `claimBlockNum = startingOutputRoot.l2SequenceNumber + SEGMENT_SIZE × (k + 1)`（per-segment 跨度）。两者共用同一 `AGGREGATION_VKEY + RANGE_VKEY_COMMITMENT` 但 public input 不重叠，零 proof 复用风险

### 11.7 Slot 9 字段互斥（packing 安全性）

28. **Slot 10 字段时序互斥**（`fullProver` 字段已迁入 `ClaimData.prover` 后 slot 10 仅剩 `lowestSIndex` + `createBondPushedAtResolve` 两字段）：
    - `lowestSIndex` 在 §6.4.2 claimCredit S-path 内 lazy 写入；`createBondPushedAtResolve` 在 §6 Phase 3 resolve() parent-CHW + totalCountered==0 分支写入
    - 两字段都在 `status → Resolved` **之后**写入，**与 prove-time / `prove(bytes)`-time 字段无 dirty-write 冲突**
    - 结论：同 slot 内两字段虽 packed，但写入路径互斥，无冲突
    - **`ClaimData.prover` 时序**：slot 1（与 proveDeadline / parentIndex 同 slot）仅在 `prove(bytes)` tx 写入；initialize 写入 proveDeadline + parentIndex 时 prover 默认 0；之后状态机只在 Unchallenged → UnchallengedAndValidProofProvided 转换一次写入 prover，与 slot 1 其它字段不再有写入冲突

### 11.8 Lazy settle 字段（§6.4.2）

29. **`disputes[k].claimed` 单向**：S-path challenger 首次 claimCredit 时由 false 写为 true，永不回退。Invariant 11 蕴含 `claimed == true ⟹ challengers[d.counteredBy].bond == 0`（同一 tx 内原子写入）
30. **REFUND mode 不写 disputes[k].claimed**：REFUND 路径走 refundModeCredit 直退，不进入 §6.4.2 settle 块；`disputes[k].claimed` 保持 false 不影响守恒

### 11.9 Mutator first-check 协议

31. **统一 first-check 规则**：所有 mutator function (`challenge(uint64)` / `prove(uint64,bytes)` / `prove(bytes)` / `resolve()` / `claimCredit(address)`) 入口 **第一行 require** 必须是 `status != GameStatus.IN_PROGRESS → revert GameAlreadyResolved` （resolve 用 `ClaimAlreadyResolved` 别名以与 V1 [line 437](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L437) 对齐）。
    - **rationale**：让 Resolved 状态 game 的拒绝信号永远是 `GameAlreadyResolved`，避免内部 `claimData.status` 分支误用其他 error code（如 challenge() 报 `ClaimAlreadyChallenged` 暗示"被其他 challenger 抢"而 SDK 错误重试）
    - **例外**：`claimCredit()` 不受此约束 —— 它**允许 Resolved 后调用**（这才是提款入口）；其内部按 `bondDistributionMode` + `challengers[_recipient].countered` 分支处理
    - **顺序保证**：first-check fail 立即 revert，后续 check 不再执行；Solidity require 按声明顺序短路 evaluation
    - **SDK 设计含义**：收到 `GameAlreadyResolved` → 已 finalize，不应重试；收到内部状态相关 error (如 `AlreadyFullProved` / `ClaimAlreadyChallenged`) → 状态特定，可能可调整参数重试

---

## 十二、Storage / Immutable / Errors / Events 总览

### 12.0 Contract 顶层 declaration

```solidity
/// @title OPSuccinctTzSegmentDisputeGame
/// @notice TradeZone fault-proof dispute game with multi-segment + multi-challenger + variable batch
/// @dev    Inherits OP-stack standard interfaces; V1 ClaimData shape preserved with minimal diff
contract OPSuccinctTzSegmentDisputeGame is Clone, ISemver, IDisputeGame {
    /// @custom:semver 2.0.0-tz-segment
    string public constant version = "2.0.0-tz-segment";
    ...
}
```

- **Inheritance chain**：`Clone` (CWIA, [@solady/utils/Clone.sol](https://github.com/Vectorized/solady/blob/main/src/utils/Clone.sol)) + `ISemver` (OP-stack standard) + `IDisputeGame` (OP-stack standard)
  - 与 V1 [contract OPSuccinctFaultDisputeGame is Clone, ISemver, IDisputeGame](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L46) 一致
- **`version` 常量**：`"2.0.0-tz-segment"` —— 表明本 impl 与 V1 (`"2.0.0"`) 同 major+minor，区分 TZ-multi-segment 变体；与 XLayer `"2.0.0-xlayer"` 命名约定一致
- 不实现 `IFaultDisputeGame`（OP-stack bisection-specific interface）；通过 `IDisputeGame` 标准接口 + 自定义 view (e.g. `intermediateRoot` / `disputes`) 对接

### 12.1 Constants（编译期固定）

```solidity
uint64 constant MAX_NUM_SEGMENTS = 256;
uint64 constant LOWEST_S_NOT_SET = type(uint64).max;
```

### 12.2 Immutable（constructor 注入）

```solidity
IDisputeGameFactory immutable DISPUTE_GAME_FACTORY;
ISP1Verifier        immutable SP1_VERIFIER;
IAnchorStateRegistry immutable ANCHOR_STATE_REGISTRY;
IAccessManager      immutable ACCESS_MANAGER;

GameType            immutable GAME_TYPE;
Duration            immutable MAX_CHALLENGE_DURATION;     // 典型 1 day
Duration            immutable MAX_PROVE_DURATION;         // 典型 1 day

bytes32             immutable AGGREGATION_VKEY;            // SP1 aggregation vkey
bytes32             immutable RANGE_VKEY_COMMITMENT;       // SP1 range vkey commitment
bytes32             immutable ROLLUP_CONFIG_HASH;          // = 0 for TZ
uint256             immutable CREATE_BOND;                 // proposer 押注
uint256             immutable CHALLENGER_BOND;             // challenger 押注
```

> **note**：基础 calldata 大小 `0x7E` 直接在 §6 Phase 0 的 length 校验 inline 使用（与 V1 [line 242-247](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L242) 同），不抽 immutable。

### 12.3 Storage

```solidity
// Lifecycle
Timestamp                   public  createdAt;
Timestamp                   public  resolvedAt;
GameStatus                  public  status;                // OP-stack standard
bool                        public  wasRespectedGameTypeWhenCreated;
bool                        internal initialized;

// ClaimData（单 deadline 字段；prover 与 V1 ClaimData.prover 对齐保留；challengeEnd 是 immutable-derived view，不存 storage）
struct ClaimData {
    address prover;                // §6 Phase 3.5 `prove(bytes)` caller; address(0) = 未 `prove(bytes)`
    Timestamp proveDeadline;       // initialize 一次写入永不更新 (rename 自原合约 ClaimData.deadline)
    uint32 parentIndex;            // 与 prover + proveDeadline 同 slot pack: 20+8+4=32B ✓
    ProposalStatus status;         // 4-value enum, slot 2 alone
    Claim claim;                   // slot 3
}
ClaimData                   public  claimData;

// Bond ledgers
mapping(address => uint256) public  normalModeCredit;
mapping(address => uint256) public  refundModeCredit;
BondDistributionMode        public  bondDistributionMode;  // OP-stack standard, UNDECIDED=0 default

// Parent linking
Proposal                    public  startingOutputRoot;

// Per-game variable params
uint64                      public  batchSize;             // = l2SequenceNumber - startingOutputRoot.l2SequenceNumber
uint64                      public  numSegments;           // = (CWIA extraData length - 0x24) / 0x20 + 1
// SEGMENT_SIZE 不存 storage；调用方按需 `batchSize / numSegments`

// Multi-challenger state
struct ChallengerInfo {
    uint256 bond;
    bool    countered;
    uint64  counteredIndex;
}
mapping(address => ChallengerInfo) public challengers;

struct DisputeEntry {
    address counteredBy;     // 20 B
    bool    proved;          //  1 B
    bool    claimed;         //  1 B  ★ §6.4.2 lazy settle 标记（S-path CHAL_BOND 已 push）
    address provedBy;        // 20 B
}
mapping(uint64 => DisputeEntry) public disputes;

// Counters & lazy compute
uint64                      public  totalCountered;
uint64                      public  totalProved;
uint64                      public  lowestSIndex;          // initialize 时设 LOWEST_S_NOT_SET; CHW + NORMAL 时 lazy compute
bool                        public  createBondPushedAtResolve;  // parent-forced CHW + totalCountered == 0 时设 true

// 注：早 finalize prover address 字段已迁入 ClaimData (`claimData.prover`)，与 V1 ClaimData.prover 对齐
```

#### 12.3.1 Storage Slot 映射表

> **目的**：避免 implementer 在 packing 上歧义；与 V2 blob spec §12.2 风格一致。Solidity 0.8.x 编译器规则：从 declaration 顺序依次填 slot，单 slot 32 bytes，无法跨 slot 拆分单字段；遇到大字段（`bytes32` / `address` / `uint256`）单独占新 slot。

| Slot (起 base N=0) | 字段 | bytes used / 32 | 备注 |
|---|---|---|---|
| 0 | `createdAt` (8B) + `resolvedAt` (8B) + `status` (1B GameStatus) + `initialized` (1B internal) | 18 / 32 ✓ packed | V1 风格 packing |
| 1 | `claimData.parentIndex` (4B) + `claimData.prover` (20B) | 24 / 32 ✓ packed | **ClaimData slot A** — V1 字段顺序（minus counteredBy） |
| 2 | `claimData.claim` (32B Claim) | 32 / 32 ✓ | ClaimData slot B — Claim 32B 必独占新 slot |
| 3 | `claimData.status` (1B ProposalStatus) + `claimData.proveDeadline` (8B Timestamp) | 9 / 32 ✗ unpacked rest | ClaimData slot C — V1 同等 9B / 23B 空余 |
| 4 | `normalModeCredit` mapping head | — | mapping slot 占位 |
| 5 | `refundModeCredit` mapping head | — | mapping slot 占位 |
| 6 | `startingOutputRoot` slot A (Proposal struct first field) | 32 / 32 ✓ | Proposal first field 32B |
| 7 | `startingOutputRoot` slot B (Proposal struct second field) | 32 / 32 ✓ | Proposal second field 32B |
| 8 | `wasRespectedGameTypeWhenCreated` (1B) + `bondDistributionMode` (1B BondDistributionMode) + `createBondPushedAtResolve` (1B) + `lowestSIndex` (8B uint64) | 11 / 32 ✓ packed | **R2-11 优化**：4 个 small fields 集中声明 → 1 slot (节约 vs 原 4 slots) |
| 9 | `batchSize` (8B) + `numSegments` (8B) + `totalCountered` (8B) + `totalProved` (8B) | 32 / 32 ✓ packed | **4 个 uint64 同 slot 紧凑** |
| 10 | `createBond` (32B uint256) | 32 / 32 ✓ | **R2-15 新字段** — `msg.value` 快照（避免 `refundModeCredit[gameCreator()]` 在 creator-as-challenger 时被 +=ed 而 alias 错） |
| 11 | `challengers` mapping head | — | |
| 12 | `disputes` mapping head | — | |

**关键 packing 决策**：
- **ClaimData 3 slots**（与 V1 同等，post-R2 §9 reorder）：
  - slot A = `parentIndex(4B) + prover(20B) = 24B`（8B unused）
  - slot B = `claim(32B)` 满载
  - slot C = `status(1B) + proveDeadline(8B) = 9B`（23B unused）
  - **字段声明顺序按 V1 对齐**（`parentIndex → prover → claim → status → proveDeadline`，minus deleted `counteredBy`）— 优先 V1-diff 可读性而非 slot-1 全 pack。其他排列（如 `prover → proveDeadline → parentIndex → claim → status`）虽然能让 slot A 满载 32B，但破坏与 V1 line 70-77 的 1:1 字段位置对应
- **R2-11 small-fields packing 优化**：`wasRespectedGameTypeWhenCreated + bondDistributionMode + createBondPushedAtResolve + lowestSIndex` 4 字段集中声明 (line 225-244) → Solidity 自动 pack 到 slot 8（11B / 32B）。Gas snapshot 实测净 -1.4%（详见 R2-11 audit trail）
- **per-game 变量**：`batchSize / numSegments / totalCountered / totalProved` 4 个 uint64 (8B × 4 = 32B) 同 slot pack ✓
- **R2-15 `createBond`**: msg.value 快照，独占 slot 10。该字段是 R1 #1 fix (creator-as-challenger bond inflation) 的核心 — 用 `createBond` 而非 `refundModeCredit[gameCreator()]` 作为 CREATE_BOND 数量代理
- **`fullProver` top-level 字段已删除**，迁入 `ClaimData.prover`（V1 对齐，参见 vs-V1 增量）

**vs 原 op-succinct 增量**：
- `ClaimData.deadline` (1 field, rolling) → `ClaimData.proveDeadline` (单字段, 绝对时间) + view function `challengeEnd()`
- 删除 `ClaimData.counteredBy`（multi-challenger 模式无单一 counter；per-segment 由 `disputes[k].counteredBy` 接管）
- **`ClaimData.prover` 保留**（V1 line 73 同名同类型；本 spec `prove(bytes)` 写 msg.sender，per-segment prove 不动）
- 新增：`batchSize / numSegments / totalCountered / totalProved`（uint64 packed 1 slot）、`challengers` / `disputes` mappings、`lowestSIndex / createBondPushedAtResolve`（packed 1 slot 共 9B）

**vs blob 变体（V2）增量**：
- **删除** `blobVersionedHash` (bytes32, V2 占 1 slot)
- **新增** `ClaimData.prover` (与 V1 对齐, V2 blob 变体无此字段)；ClaimData slot 数 2 → 3
- 其余完全一致

### 12.4 Errors

```solidity
// 鉴权 & 重入
error AlreadyInitialized();
error IncorrectDisputeGameFactory();
error BadAuth();
error BadExtraData();              // CWIA 长度错（非 0x7E + 0x20×(N-1) 形态）

// CWIA / per-game params 校验
error InvalidNumSegments(uint64 actual);   // numSegments 不在 [1, 256]
error InvalidBatchSize();                  // batchSize == 0 或 batchSize % numSegments != 0
error UnexpectedRootClaim();               // l2SequenceNumber <= startingOutputRoot.l2SequenceNumber

// Parent integrity
error InvalidParentGame();

// Bond
error IncorrectBondAmount();

// Phase 1 challenge
error ClockTimeExceeded();
error AlreadyCountered();
error ClaimAlreadyChallenged();    // disputes[k].counteredBy != 0
error IndexOutOfRange();

// Phase 2 prove
error IndexNotCountered();
error AlreadyProved();

// Phase 3 resolve
error ParentGameNotResolved();     // parent.status == IN_PROGRESS（与原合约 line 437-439 对齐）
error GameNotOver();
error GameAlreadyResolved();
// `InvalidProposalStatus` (V1-inherited) reused for the resolve() Challenged-else fallthrough.

// Phase 3.5 `prove(bytes)` (early finalize)
error NotUnchallenged();           // `prove(bytes)` 仅在 claimData.status == Unchallenged 时可用
// HasChallengers error: 不声明 — 防御性 `totalCountered == 0` check 被 Invariant 11 蕴含覆盖（impl 故意省略，spec §6 Phase 3.5 已对齐）
error ChallengeWindowEnded();      // `prove(bytes)` 仅在 challenge 窗口内有意义
error AlreadyFullProved();         // `prove(bytes)`: 同 game 重复（claimData.status == UnchallengedAndValidProofProvided）
                                   // 同时被 challenge() 使用：claimData.status == UnchallengedAndValidProofProvided 时禁止 challenger 入场，避免浪费 CHAL_BOND
error ParentAlreadyLost();         // `prove(bytes)`: parent.status == CHALLENGER_WINS 已落定，本 game 必 burn；阻挡 doomed `prove(bytes)` tx 节省 gas

// Phase 4 closeGame / claimCredit (与原合约 [closeGame:531](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L531) / [claimCredit:500](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L500) 对齐)
error InvalidBondDistributionMode();  // closeGame: bondDistributionMode 不在 {UNDECIDED, NORMAL, REFUND} 之一 (sanity)
error GameNotFinalized();             // closeGame: ASR.isGameFinalized(this) 返回 false (finality delay 未过)
error NoCreditToClaim();              // claimCredit: 当前 mode 下 _recipient 的 credit ledger 为 0
error BondTransferFailed();           // claimCredit: 末尾 _recipient.call{value:credit}("") 返回 false
error InvalidProposalStatus();        // resolve: claimData.status 在 4 态 enum 之外（理论不可达，sanity）
```

**vs 原 op-succinct 增量**：
- 删除 `ClaimAlreadyChallenged` 的原义（单 challenger 模式下整 game 被 challenge）→ 本 spec 改为 "该 segment 已被 challenge"
- 新增 `InvalidNumSegments / InvalidBatchSize / AlreadyCountered / IndexNotCountered / AlreadyProved / IndexOutOfRange`（multi-challenger + segment 模式新增）
- 沿用原合约的 `ParentGameNotResolved`（resolve 阶段 parent IN_PROGRESS 时 revert，与原合约 line 437-439 对齐）

**vs blob 变体（V2）增量**：
- **删除** `NoBlobAttached`、`InvalidKZGOpening`（blob / KZG 专用 errors）
- **新增** `NotUnchallenged / ChallengeWindowEnded / AlreadyFullProved`（§6 Phase 3.5 `prove(bytes)` 通道；V2 无 `prove(bytes)`）
- 其余完全一致

### 12.5 Events

```solidity
event Challenged(address indexed challenger, uint64 indexed segment);
event Proved(address indexed prover, uint64 indexed segment);
event UnchallengedAndValidProofProvided(address indexed prover);                              // §6 Phase 3.5 — early finalize 通道
event Resolved(GameStatus status);                                     // OP-stack standard, 继承 IDisputeGame
event GameClosed(BondDistributionMode mode);                            // OP-stack standard
```

**vs 原 op-succinct 增量**：
- `Challenged` / `Proved` 新增 `segment` 参数（multi-challenger 模式必需）

**vs blob 变体（V2）增量**：
- **新增** `UnchallengedAndValidProofProvided(address indexed prover)`（§6 Phase 3.5 early-finalize 通道；V2 无 `prove(bytes)` 则无此 event）
- 其余完全一致（V2 没有 blob-specific event）

### 12.6 External / public function signatures

```solidity
// 生命周期
function initialize() external payable;
function challenge(uint64 k) external payable returns (ProposalStatus);
function prove(uint64 k, bytes calldata proofBytes) external returns (ProposalStatus);  // §6 Phase 2 per-segment prove (新 selector, multi-segment 模式特有)
function prove(bytes calldata proofBytes) external;                                     // §6 Phase 3.5 early finalize overload (selector 与 V1 `prove(bytes)` 完全一致); 验 + 写 claimData.prover + 推 claimData.status=UnchallengedAndValidProofProvided; 不改 GameStatus; 后续 resolve() consume
function resolve() external returns (GameStatus);
function closeGame() public;                                                    // OP-stack standard
function claimCredit(address _recipient) external;                              // OP-stack standard

// IDisputeGame standard getters
function l2SequenceNumber() public pure returns (uint256);
function l2BlockNumber() public pure returns (uint256);    // alias
function parentIndex() public pure returns (uint32);
function startingBlockNumber() external view returns (uint256);
function startingRootHash() external view returns (Hash);
function gameOver() public view returns (bool);
function gameType() public view returns (GameType);
function gameCreator() public pure returns (address);
function rootClaim() public pure returns (Claim);
function l1Head() public pure returns (Hash);
function extraData() public view returns (bytes memory);   // 注：view 不是 pure（读 numSegments storage 决定 extraData 长度）
function gameData() external view returns (GameType, Claim, bytes memory);
function credit(address _recipient) external view returns (uint256);

// Immutable getters
function maxChallengeDuration() external view returns (Duration);
function maxProveDuration() external view returns (Duration);
function maxClockDuration() external view returns (Duration);                   // = MAX_CHALLENGE_DURATION; IFaultDisputeGame interface 兼容（与 V1 [maxClockDuration:651](contracts/src/fp/OPSuccinctFaultDisputeGame.sol#L651) 同实现）
function disputeGameFactory() external view returns (IDisputeGameFactory);
function sp1Verifier() external view returns (ISP1Verifier);
function rollupConfigHash() external view returns (bytes32);
function aggregationVkey() external view returns (bytes32);
function rangeVkeyCommitment() external view returns (bytes32);
function challengerBond() external view returns (uint256);
function anchorStateRegistry() external view returns (IAnchorStateRegistry);
function accessManager() external view returns (IAccessManager);

// Calldata 变体特有 getters
function intermediateRoot(uint64 k) public view returns (bytes32);              // k ∈ [0, numSegments-2] (0-indexed); intermediateRoot(i) = boundary[i+1]; bound check 读 storage 故是 view 不是 pure
function intermediateRoots() public view returns (bytes memory);                // 一次性读全部 (numSegments - 1) 个 intermediate root, bulk getter (N=1 时返回空 bytes)
function segmentSize() external view returns (uint64);                          // = batchSize / numSegments (view derive)
function challengeEnd() public view returns (Timestamp);                        // = createdAt + MAX_CHALLENGE_DURATION (immutable-derived view, 无 storage 字段)
```

#### 12.6.1 `gameOver()` 实现

```solidity
function gameOver() public view returns (bool) {
    ProposalStatus s = claimData.status;
    if (s == ProposalStatus.Resolved) return true;
    if (s == ProposalStatus.UnchallengedAndValidProofProvided) return true;     // ★ `prove(bytes)` 早 finalize 标记态（§6 Phase 3.5）
    if (s == ProposalStatus.Unchallenged) {
        // 未被挑战 + 挑战窗口截止 → game over (Unchallenged 路径)
        return block.timestamp >= Timestamp.unwrap(challengeEnd());
    }
    // s == Challenged: 两种终局触发
    //   (a) Early-finalize: challengeEnd 已过 + 所有已 challenged 段被 prove (totalProved == totalCountered)
    //       challengeEnd guard MANDATORY — 没有它会在 challenge 窗口内被抢跑 resolve，剥夺后到 challenger 权利
    //   (b) 正常 timeout: proveDeadline 到期
    if (block.timestamp >= Timestamp.unwrap(challengeEnd()) && totalProved == totalCountered) {
        return true;
    }
    return block.timestamp >= Timestamp.unwrap(claimData.proveDeadline);
}
```

> **设计要点**：4 态正向枚举——`Resolved` 终态、`UnchallengedAndValidProofProvided` 早证态（V1 `UnchallengedAndValidProofProvided` 的等价物，用枚举值显式标记而非"Unchallenged + sub-flag"隐式编码）、`Unchallenged` 走 challenge clock、`Challenged` 走 prove clock 或早完成。单读 `claimData.status` + 时间 + bond counters 即可判别完整状态机。

> **Challenged 早完成的 challengeEnd guard 为何不可省略**（详见 §6 Phase 3.5 后 SAFETY NOTE）：
> 在 `block.timestamp < challengeEnd()` 期间，`totalProved == totalCountered` 是**瞬态等式**——新 challenger 可在窗口内继续 challenge 新段使 totalCountered 上升。若早完成不加 challengeEnd 守卫，会形成抢跑 resolve + 剥夺后到 challenger 权利的攻击路径。**早完成只在 challenge 窗口关闭后才允许触发。**

#### 12.6.2 `challengeEnd()` 实现

```solidity
function challengeEnd() public view returns (Timestamp) {
    return Timestamp.wrap(uint64(Timestamp.unwrap(createdAt) + Duration.unwrap(MAX_CHALLENGE_DURATION)));
}
```

> **设计要点**：`challengeEnd` 不存 storage（详见 §12.3.1 slot 表），仅作为 immutable-derived view function 暴露给 SDK / 链下 indexer。`createdAt` 一次 SLOAD + `MAX_CHALLENGE_DURATION` immutable 加法运算，调用 site 集中在 `challenge()` 入口检查 + `resolve()` Unchallenged 分支 + 链下查询，频率低于"省 1 个 storage slot"的收益。

#### 12.6.3 `segmentSize()` 实现

```solidity
function segmentSize() external view returns (uint64) {
    return batchSize / numSegments;   // initialize 时已强校验 batchSize % numSegments == 0
}
```

**vs 原 op-succinct 增量**：
- `challenge` 加 `uint64 k` 参数 —— **selector 变更**（原 `challenge()` → 本 spec `challenge(uint64)`），外部 ABI 不兼容。区块浏览器 / etherscan / SDK 必须更新
- **`prove` 改成同名 overload**：
  - 新增 `prove(uint64,bytes)` per-segment 接口（multi-segment 模式特有；新 selector）
  - 保留 `prove(bytes)` selector（与 V1 完全一致），但语义改为"full-batch early-finalize"——V1 N=1 路径等价
- 新增 `intermediateRoot(k) / intermediateRoots() / segmentSize() / challengeEnd() / maxClockDuration()` getter
- 删除 `createBond()` getter（与原合约一致——CREATE_BOND 通过 `factory.initBonds(GAME_TYPE)` 间接查）
- `extraData()` pure → view（因变长 extraData 由 storage `numSegments` 决定长度）
- **ProposalStatus 5 态 → 4 态**：
  - 删除 `ChallengedAndValidProofProvided` (C+VP)：multi-segment 下 `prove(uint64,bytes)` Step 4 即时 push L bond 给 prover，无 game-wide 中间态需求
  - **保留 `UnchallengedAndValidProofProvided` (U+VP)** 同 V1 命名（V1 alignment-first）：含义不变（无 challenge + 整 batch 已验），通道化为独立 `prove(bytes)` overload（不与 per-segment `prove(uint64,bytes)` 复用），独立 revert mapping

**vs blob 变体（V2）增量**：
- 删除 `blobVersionedHash()` getter
- `prove` 从单一 `prove(bytes)` (内部 abi.decode 7 字段 SegmentProof) → 两个 overload：`prove(uint64,bytes)` (per-segment, 直接 2 参数) + `prove(bytes)` (full-batch early-finalize)
- 新增 `intermediateRoot(k) / intermediateRoots()` getter（V2 没有，V2 通过 KZG opening 验证）
- **新增 `prove(bytes)` overload 作为早 finalize 通道**（§6 Phase 3.5；V2 blob 变体无 early-finalize 通道——本 spec 与 V1 兼容性的产物）
- V2 ClaimData 双 deadline 字段 → 本 spec 单字段 + view function `challengeEnd()`

---

## 十三、Off-chain Client Conventions

> **范围**：本章描述 honest challenger / prover 客户端 SDK 行为约定。**链上合约不强制**这些规则；正确性依赖 1-of-N honest 假设（§2.2）+ SDK 实现。
>
> 这些是合约 spec 之外的 social-layer convention：链上接口本身中立，但 honest 参与者必须遵循以下行为才能在 game theory 上稳赢。

### 13.1 Challenger SDK：取 roots 流程

challenger 在调 `challenge(k)` 之前需先获得 intermediate roots、本地 replay、找 first-mismatch index。生产 challenger client 推荐如下 4 步：

1. **获取 game 地址**：通过 factory 的 `DisputeGameCreated` event 拿到新 game 地址。

2. **读取 intermediate roots**：调 game 合约的 `intermediateRoot(k)` getter（view function，CWIA calldata 直读），按 `k = 0, 1, ..., numSegments-2` 顺序读取全部 `numSegments - 1` 个 root；也可调 `intermediateRoots()` bulk getter 一次性拿全部 intermediate roots 字节（推荐，减少 RPC round-trip）。**零外部依赖**：不需要 beacon node / archive EL / blob indexer。

3. **本地 replay + first-mismatch 搜索**：用 sp1-range-program 同款 STF 实现，从 `startingOutputRoot.root` 出发，逐 segment（每 `SEGMENT_SIZE` block）replay，与链上 `intermediateRoot(i)` 比对。找到**第一个**不匹配的 boundary 即 first-mismatch；按 §13.2 端点映射表换算为 dispute index k。

4. **调 `challenge(k)`**：付 CHALLENGER_BOND 提交。

> **关键**：步骤 3 的 first-mismatch 搜索必须**确定性**（按 boundary index 升序），不允许跳过。否则 challenger 可能误选 decoy mismatch 损失 CHAL_BOND（见 §13.2）。

### 13.2 Challenger SDK：选择规则

链上**不强制** challenger 选 first-mismatch，但 honest challenger 行为约定如下。这是 1-of-N honest 假设的一部分。

**规则 1：First-mismatch only**

设 honest L2 state chain 为 `s_0, s_1, ..., s_N`，proposer claim 为 `c_1, ..., c_{N-1}`（来自 `intermediateRoot(0..N-2)`，0-indexed: `c_p = intermediateRoot(p - 1)`），rootClaim 为 `c_N`。"first-mismatch"是最小 boundary index `p` 满足 `c_p ≠ s_p`（对应 dispute index `k = p - 1`）。

**为什么必须选最小**：proposer 恶意链上 deterministic STF **只有一个**真 fork 点（即 first-mismatch p）；在 q > p 上 proposer 可在自己的恶意 chain 上 prove segment[q-1, q] 成功 → 选 q 的 challenger 进 L 集合输 CHAL_BOND。只有选 p 进入 S 集合（proposer 永远 unprove）才稳赢。详细博弈推导见 §十（攻击面与防护）。

**端点 → dispute index 映射**（设 `N = numSegments`）：

> **符号约定**（统一全 spec）：
> - **`p`** = **mismatch boundary index** ∈ `[1, N]` —— honest L2 boundary state 链上第一处与 proposer claim 不匹配的下标
> - **`k`** = **dispute index** ∈ `[0, N-1]` —— `challenge(k)` / `prove(k)` 接口使用的参数；指 segment[k] 的 STF transition（从 boundary `k` 到 boundary `k+1`）
> - **映射关系**：`k = p - 1`

| 第一处 mismatch `p` | dispute index `k = p - 1` | claimPre 来源 (boundary k) | claimPost 来源 (boundary k+1) |
|---|---|---|---|
| `p = 1` | `k = 0`（起点端） | `startingOutputRoot.root`（链上 storage） | `intermediateRoot(0)`（CWIA, 0-indexed = boundary 1） |
| `2 ≤ p ≤ N-1`（中间） | `k = p - 1` | `intermediateRoot(k-1)` (= boundary k) | `intermediateRoot(k)` (= boundary k+1) |
| `p = N`（中间序列全 honest 但累加不等于 rootClaim） | `k = N-1`（终点端） | `intermediateRoot(N-2)` (= boundary N-1) | `rootClaim()`（CWIA arg #2 = boundary N） |

**N=1 退化情形**：只有 segment 0，挑战 `k=0`，`claimPre = startingOutputRoot.root`，`claimPost = rootClaim()`，等价于原 op-succinct single-batch 挑战模式。

**规则 2：Race loss → skip**

如果 `challenge(k)`（`k = p - 1`）因 dedup 被 revert（说明已有其他 challenger select 了同一 segment），challenger 应**放弃 select**（payable call 整笔回滚不付任何 bond），**绝不**选其他 dispute index `k' > k`。

**理由**：无论对手是 honest（已 counter 真 first-mismatch）还是 malicious（proposer 马甲占位 decoy 诱导转选 q），honest challenger 在 race loss 后选 q 都不优——前者拿不到 lowest-S winner reward，后者直接被 trap 输 CHAL_BOND。唯一最优策略：race loss → 放弃 → 等待下一个 game。

> **注意**：链上**不强制**此规则——proposer 仍可恶意构造 decoy 让粗心 challenger 误选 q。这是为什么 challenger SDK 必须实现确定性 first-mismatch 搜索 + race-loss-skip 逻辑。

### 13.3 Full-batch Prover 客户端（`prove(bytes)` 早 finalize 通道）

调 §6 Phase 3.5 `prove(bytes)` 的 caller 通常是 **proposer 自己**（或代付 gas 的第三方）。本节约定 off-chain prover client 行为：

**1. 触发时机判定**：
- **必要前提**：本 game `claimData.status == Unchallenged` 且 `totalCountered == 0`
- **建议监控窗口**：从 `createdAt` 起，直到 `createdAt + MAX_CHALLENGE_DURATION × 0.8`（留 buffer 给链上落块 + race 防护）
- **不应触发**：
  - parent game 仍 IN_PROGRESS 且观察到 parent 有 active challenger / pending resolve 风险 —— 走 §9.4.b burn 风险（虽有 `ParentAlreadyLost` 预检，但 race window 仍存）
  - 任何 challenge(k) 已落块或 mempool 中 —— proveFull 必然 revert，链下 prove 工作白费
  - 下游无 fast finalize 需求（默认 honest case 等 challengeEnd 自然到期最便宜）

**2. 链下 prove 准备**：
- 输入：`startingOutputRoot.root`、`rootClaim()`、`startingOutputRoot.l2SequenceNumber + batchSize`、`rollupConfigHash` (= 0 for TZ)、`RANGE_VKEY_COMMITMENT`、`msg.sender`
- 用 sp1-range-program 跑整 `batchSize` 跨度 STF，生成 SP1 aggregation proof
- **rootClaim 正确性自检**：proof generation 完成前应链下 replay 整 batch 与 game 的 `rootClaim()` 校对，避免 prove 完成才发现 rootClaim 错（SP1 verify 会 revert，链下工作浪费）

**3. tx broadcast**：
- **必须用 private mempool** 防 frontrun-by-challenge DOS（§10.3）
- gas 设置按目标 inclusion delay 调

**4. tx 落块后**：
- 监 `UnchallengedAndValidProofProvided(prover)` event 确认成功
- **立即广播 `resolve()` tx**（任何人都可调；建议 prover 自己付以最快 finalize）
- resolve() 成功后下游 ASR / OptimismPortal 可在 `maxClockDuration` + airgap 后视本 game 为 finalized

**5. 风险接受**：
- proveFull 在 race / parent 翻转 / SP1 公共输入与 rootClaim 不匹配等情况下 **链下成本无补偿**（§9.6.5）
- 协议层不付 reward；动机来自下游应用层（bridge / sequencer 续期 / 时间敏感 governance）

---

## 十四、Open Questions / 后续工作

### 14.1 Range program vkey rotation 兼容性

本 spec 与 blob 变体（V2）共享同一 sp1-range-program vkey —— program 接受动态 block 范围，合约层通过 `claimBlockNum` 公式间接强制单 dispute 为 SEGMENT_SIZE-block。**未来 range program 升级时**，本 spec 与 V2 应保持 vkey 同步 rotation，避免双 spec 部署版本漂移。

### 14.2 部署 calldata cost 实测

`MAX_NUM_SEGMENTS = 256` 上限对应 ~8.2 KB extraData，按当前 mainnet gas 价格估算 ~$2-10 per propose。**实际部署前需在目标链测量**：
- 普通 calldata 16 gas/byte 是 baseline
- L2 上 calldata 成本通常更低（不同 L2 对 calldata 计价规则差异）
- 频繁 propose 累计成本应纳入 proposer 经济模型

### 14.3 SEGMENT_SIZE 上限的 social-layer 约束

合约层不约束 `SEGMENT_SIZE` 上限（仅 `1 ≤ numSegments ≤ 256` 和 `batchSize % numSegments == 0`）。proposer 理论上可选 `numSegments = 1, batchSize = ∞` → SEGMENT_SIZE 极大 → 任何挑战的 prove 都不可能在 `MAX_PROVE_DURATION` 内完成。

**Game theory 自然约束**：
- 若 proposer 选 SEGMENT_SIZE 过大，被 honest challenger 挑战时无法在窗口内 prove → CHW，proposer 失 CREATE_BOND
- → proposer 自利约束 SEGMENT_SIZE 在 "可 prove" 范围内

**但仍有 social-layer 风险**：
- 恶意 proposer 故意选超大 SEGMENT_SIZE 以增加 honest challenger 的本地 replay 负担（DoS challenger）
- challenger 在合理时间内 replay 不完 → 错过 challenge window → 错误 game 通过

**缓解**：challenger SDK 实现"超大 SEGMENT_SIZE 拒绝处理"的 sanity check；governance 监控 + emergency blacklist。

### 14.4 N=1 退化模式的取舍

N=1 时合约退化为原 op-succinct 单 batch dispute 模式，prove cost = `O(batchSize)`。在生产部署中，N=1 通常**不被选用**——除非：
- 极短 batch（如 < 100 blocks）— 实操中 propose 频率太高
- 测试 / 兼容性场景 — N=1 与原合约字节级兼容，便于灰度切换

**是否在 governance / off-chain enforcement 层禁止 N=1**？建议 N=1 保留为合约层合法路径但 social-layer 约定 N ≥ 4 或类似下限。

### 14.5 EVM 版本要求

本 spec 不依赖 EIP-4844 的 `BLOBHASH` (`0x49`) 与 point evaluation precompile (`0x0A`)，**编译目标可设为 London 及以上**（无 Cancun 强约束）。这与 blob 变体的关键差异——blob 变体强制 Cancun fork。

### 14.6 与 OP-stack 合约升级兼容性

本 spec 复用 OP-stack 标准 `ASR / DisputeGameFactory / DelayedWETH` 接口，跨 OP-stack 版本升级时只需保持接口稳定即可不动 dispute 实现。**未来 OP-stack 引入新的 dispute game 治理路径（如 emergency veto）时**，本 spec 需追加对应分支。

### 14.7 ZK proof aggregation 优化

本 spec 单 prove tx 验证 1 个 segment 的 STF。若 multi-challenger 同时挑战多个 segment，需多笔 prove tx。**未来可优化**：单笔 tx aggregate 多 segment proof（需要 SP1 program 端配合）。当前 spec 保留为 §14 future work。
