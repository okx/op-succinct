# op-succinct — Withdraw/ForceTx Root 贯穿与独立 Defender 设计

- **Jira**: [TRDZN-1339](https://okcoin.atlassian.net/browse/TRDZN-1339) — `[op-succinct] 实现 Withdraw/ForceTx Root 贯穿与独立 Defender`
- **仓库 / 分支**: `github/op-succinct` @ `xl/tz-challenger-v2`（既是开发基线也是 MR 目标分支）
- **设计日期**: 2026-09-03
- **Lark Review Document**: <https://okg-block.sg.larksuite.com/docx/EpBwdZvH8oiXq6x0V0JlgQaXgxb>（记录见 `docs/superpowers/lark-review-doc.md`）
- **状态**: 待创作者审批（Approve design / Request design changes）

> **一句话结论**：在 op-succinct 中保留现有 Proposer / L1 Challenger / Range Guest / aggregation / Game 主流程不变，只让 `withdrawalRoot` 和 `forceRoot` 两个新 root 与既有 `blockHash`/`appHash` 一起，形成完整四字段 `claimRoot`，从 Witness Builder 的 CheckpointV2 与 boundary witness 贯穿到 SP1 证明、L1 Game 和 L1 Challenger；并新增一个**独立的 Defender 服务**，用 RootManager 权威 root + Witness Builder 历史 inclusion proof 响应 X Layer 上的 Withdraw challenge。所有 leaf 提取、Merkle 追加、root 与 proof 计算**唯一**来自 TradeZone 的 `tz-witness` crate（extractor 在 `tz-block-processor`）——op-succinct 内**绝不**再实现第二套树/root/proof 算法。

---

## 0. 权威来源与优先级

本设计的字段、编码、哈希、接口语义**不自行更改**，全部以下列 Lark 文档为准（冲突时以 Protocol 正文 + 冻结 `claim-tree-v1.json` fixture 为最终裁决）：

1. **Protocol and Interfaces（唯一协议权威）** — <https://okg-block.sg.larksuite.com/docx/QmrBdy5Yzo4BnAxefTvlCafAgVq>
2. **op-succinct Spec（本 Task 的直接实现设计）** — <https://okg-block.sg.larksuite.com/docx/X1QXdiXpyo3rAUxXFh1l5wnyg9c>
3. **Witness Builder Spec（上游数据与 RPC 行为）** — <https://okg-block.sg.larksuite.com/docx/WFI7dNfASom6pXxn3W4lCgaJg9e>
4. **Withdrawal/Force Tree 复用设计** — <https://okg-block.sg.larksuite.com/docx/YWBkdLIo2o7CwXxDfNLlIVgGgKc>

> 校验硬规则（proof）：`count > 0`、`leafIndex < count`、`siblings` 数量必须为 32。

---

## 1. Additional Context（用户提供的补充上下文）

### 1.1 原始补充内容（原文）

> 这里的开发对应的 witness builder 的实现是在这里：
> <https://gitlab.okg.com/xlayer-dex/tradezone/-/tree/feature/witness-builder-withdraw-v1>
> 对应的合约在：
> <https://gitlab.okg.com/github/op-succinct/-/tree/xl/tz-challenger-v2/contracts/src/fp?ref_type=heads>

创作者在澄清时进一步补充（决策 D2）：

> 不用 x2，x2 是 tz 在 github 上的镜像，这里不对，你可以把 x2 换成 tz 的我开发好的分支：
> <https://gitlab.okg.com/xlayer-dex/tradezone/-/tree/feature/witness-builder-withdraw-v1>

### 1.2 逐条分类与已解决的设计含义

| # | 原始陈述 | 分类 | 设计含义（已解决，可适用） |
|---|---|---|---|
| AC-1 | Witness Builder / tz-witness / extractor 的上游实现在 tradezone 分支 `feature/witness-builder-withdraw-v1` | 参考 / 操作说明 | op-succinct 依赖的 `tz-witness`（append/root）与 `extract_withdrawals`（在 `tz-block-processor`）必须来自这个分支。见 §8 依赖方案。与 op-succinct Spec §8.4 一致。 |
| AC-2 | 对应合约在 op-succinct `xl/tz-challenger-v2` 的 `contracts/src/fp` | 参考 / 范围说明 | 最终 ABI 以该目录为准。已核验：`OPSuccinctFaultDisputeGame.sol`（四字段 extraData + rootClaim 校验）、`TZRootManager.sol`/`ITZRootManager`、`ITZClaimGame` 已存在；Withdraw challenge 合约不在本仓库，属 X Layer 外部 ABI（合约组提供，见 §7.4）。**非目标**：不实现/重构合约本体。 |
| AC-3（澄清） | 依赖来源不要用 x2（github 镜像），改用 tradezone GitLab 的开发分支 | 约束（修正） | 把当前 `ssh://git@github.com/okx/x2.git` 的 tz-* 依赖来源，全部改为 tradezone GitLab 仓库 `gitlab.okg.com/xlayer-dex/tradezone`，分支 `feature/witness-builder-withdraw-v1`，固定 rev。见 §8。 |

**与 Jira/PRD/仓库事实无冲突**：三条均为对 Jira 与四份 Spec 的强化说明；AC-3 与 op-succinct Spec §8.4「注意 x2 是 TradeZone 的镜像、当前 pin 的 rev b3e2cf98 为 master 旧快照、开发期应从 feature 分支引入」完全一致，无需额外冲突裁决。

---

## 2. 协议基线（冻结常量与公式，摘录自 Protocol）

- **CheckpointV2**（纯计算结构，**不含 chainId**）：`schemaVersion=2, blockHeight:u64, blockHash:bytes32, appHash:bytes32, withdrawalRoot:bytes32, forceRoot:bytes32, claimRoot:bytes32`。
- `claimRoot = keccak256(abi.encodePacked(blockHash, appHash, withdrawalRoot, forceRoot))` — 原像固定 **128 字节**，`blockHeight` 不进入 claimRoot。
- `withdrawalRoot = keccak256(abi.encodePacked(withdrawalInnerRoot, uint256(withdrawalCount), 0x02))` — 原像固定 **65 字节**。
- `forceRoot = keccak256(abi.encodePacked(forceInnerRoot, uint256(forceCount), 0x01))` — 原像固定 **65 字节**。
- **chainId**：不进入 CheckpointV2；由 checkpoint RPC 响应**顶层** `SnapshotQueryResponse.chain_id`（裸 `u64`，非 0）返回，仅用于 host 侧交叉校验数据属于正确 TZ 链。
- **增量树**：`TREE_DEPTH=32`；状态 `branch[32] + count`（`count`/`leafIndex` 均 `u32`）；空 leaf `bytes32(0)`；`z[h+1]=keccak256(z[h]‖z[h])`；父节点 `keccak256(left‖right)`（不排序）；inclusion proof = `leafIndex + count + siblings[32]`。
- **固定空树向量**（Rust/Solidity/部署脚本各自计算断言，不互相复制）：
  - `emptyInnerRoot      = 0x27ae5ba08d7291c96c8cbddcc148bf48a6d68c7974b94356f53754ef6171d757`
  - `EMPTY_FORCE_ROOT     = 0x2ce29f3bbe826db4f8ba37a99421dec3b9b590d06fd6b77b706c8a8606de2a56`
  - `EMPTY_WITHDRAWAL_ROOT = 0x6b7dbdc90c57dd6d1cc0ce495b921b274ffccbba3813e018b7cc843f4f6876d7`
- **ForceTx 无叶子时** `forceRoot = EMPTY_FORCE_ROOT`（非零，含义「树已存在、count=0」），不因此返回 NotReady。
- **Boundary witness wire**：`count==0` 时 `activeBranches=[]`；否则只含 count 二进制置位层级的 branch，长度 `== popcount(count)`，按 level 低→高排列，每项定长 `bytes32`，无 level 字段、无 zero-hash 占位；解码方必须校验长度并重建声明 root，不匹配即拒绝。

---

## 3. 当前代码基线（已核验，branch `xl/tz-challenger-v2` @ 671e055）

> 通过 codegraph（3,631 files / 81,570 nodes / 247,136 edges）+ 全文件阅读核验。这是「改哪里」的事实依据。

**合约（已完成，非目标）**
- `contracts/src/fp/OPSuccinctFaultDisputeGame.sol`：已有四字段 extraData getter（`blockHash()@0x78`、`appHash()@0x98`、`withdrawalRoot()@0xB8`、`forceRoot()@0xD8`），并在 `_verifyRootClaimPreimage` 强制 `rootClaim == keccak256(abi.encodePacked(blockHash, appHash, withdrawalRoot, forceRoot))`；extraData 总长 164 字节（`l2BlockNumber(32)+parentIndex(4)+4×bytes32`）。
- `contracts/src/fp/TZRootManager.sol` + `interfaces/ITZRootManager.sol`：`record(withdrawalRoot, forceTxRoot, checkpointBlockHeight)` / `getRoots(height)` / `getLatestRoots()`，height 严格递增、未命中返双零。
- `interfaces/ITZClaimGame.sol`：forwarder 读视图 `withdrawalRoot()` / `forceRoot()`。
- **不在本仓库**：Withdraw/ForceTx **challenge 合约**（`ChallengeOpened` / `getChallenge` / `proveChallenge`）与 `ClaimTreeVerifier.sol` — 属 X Layer 外部 ABI，由合约组提供（Protocol §5.3）。

**Rust（`op-succinct-fp` / `fault-proof` crate，`tz` feature 后）**
- Bins：`proposer` / `challenger` / `tz-proposer` / `tz-challenger`（**无 defender**）。
- `src/tz/l2_provider.rs`：`compute_tz_root_claim(block_hash, state_hash) = keccak256(blockHash‖stateHash)` — **两字段** rootClaim；`compute_output_root_at_block` 只用缓存 `TzBlockInfo{block_hash, state_hash}`。
- `programs/tz/range/src/main.rs`（SP1 range guest）：`l2PreRoot/l2PostRoot = keccak256(blockHash‖appHash)` — **两字段**；只 import `tz_block_processor::{Block, compute_app_hash, process_block, verify_next_block}` + `tz_dex`；**无 tz-witness、无 boundary 输入**。
- `src/tz/proposer.rs`：把 Game 区间切成 N 个 sub-range 并发证明（`compute_chunks`），`range_stdin = snapshot + chunk_count + block chunks`（**无 boundary witness**）；`create_game` 的 `extra_data = (l2BlockNumber, parentIndex).abi_encode_packed()`（**旧两字段短格式**，尚未产出 164 字节四字段 extraData）。
- `src/tz/chain_client.rs`：`confirmed_block_info` / `dex_state_snapshot`(异步 replay) / `blocks_range`。**无** CheckpointV2(schemaVersion=2)、boundary、record、proof endpoint；**无** chainId 解析；**无**稳定错误分类。
- `src/tz/game_validator.rs`（L1 Challenger）：`TzRootClient` 查 `chain/dex_state_snapshot?height&format=root`（**未带 schemaVersion=2**）；`RootResponse.components` 可选 `{blockHash,appHash,withdrawalRoot,forceRoot}`，若有则重算 128 字节 claimRoot 并比对；最终**只**把单个 `claimRoot` 与 Game `output_root` 比对；`NotReady/Running/DataUnavailable → Unavailable`（可重试）。**缺**：schemaVersion=2、顶层 chainId 解析+守卫、逐字段比较。
- `src/tz/config.rs`：`TzConfig{rpc_urls, game_type}` — **无** TZ chainId、无 WB endpoint 字段、无 Defender 配置。

**依赖（root `Cargo.toml`）**：`tz-block-processor` / `tz-dex` / `tz-primitives` 均 `ssh://git@github.com/okx/x2.git` rev `b3e2cf98`（旧 master，**无** Claim Tree Core / `extract_withdrawals`）；**无 tz-witness**。

---

## 4. 目标架构与工程边界

```
 Witness Builder RPC ── CheckpointV2 / boundary / record / proof
        │                         │
        ▼                         ▼
 ┌─────────────── 共享 library（src/tz/ 下新增 protocol/ + client 扩展）───────────────┐
 │ Protocol/ABI 类型：CheckpointV2, TreeBoundaryWitness, WithdrawRecord(镜像), proof,   │
 │                     Game extraData, 稳定错误枚举                                     │
 │ WB client：4 个只读 endpoint + 稳定错误解析（NotReady/transient 可重试）             │
 │ 四字段 claimRoot 编解码；tz-witness 薄 adapter（Guest 转换 + Defender 本地验证）     │
 └──────────────────────────────────────────────────────────────────────────────────┘
        │                    │                    │
        ▼                    ▼                    ▼
   Proposer bin        L1 Challenger bin      L2 Defender bin（新增）
   (tz-proposer)       (tz-challenger)        (tz-defender)
        │                    │                    │
        ▼                    ▼                    ▼
     L1 Game            L1 Game 校验         X Layer Challenge / RootManager
```

**唯一计算源**：`tz-witness` crate（`crates/witness/`，纯计算，只依赖 `tz-primitives` + `thiserror`，绝不 `use tz_block_processor`）提供 `calculate_inner_root` / `business_root` / `verify_proof` / 增量 append；extractor（`extract_withdrawals` / `normalize_withdraw`）在 `tz-block-processor`。依赖方向单向：`tz-block-processor → tz-witness → tz-primitives`。

**三程序隔离**：Proposer / L1 Challenger / L2 Defender 各自独立 main loop、配置、signer、运行状态、部署生命周期；Defender **不与 Relayer 合并**、**不读** Proposer/Relayer 本地缓存作为权威来源。

**共享 vs 隔离**：共享只到「纯类型 / 编解码 / WB client / tz-witness adapter」层；三个 bin 的运行时（signer、main loop、配置装载）互不耦合。

---

## 5. 逐区域设计

### 5.1 区域一 — 共享协议类型 + WB Client

在 `fault-proof/src/tz/` 下新增 `protocol/`（类型与编解码）并扩展 WB client：

- **类型**：`CheckpointV2`（7 字段，不含 chainId）、`SnapshotQueryResponse{ checkpoint: CheckpointV2, chain_id: u64 }`、`TreeBoundaryWitness{ schemaVersion, blockHeight, blockHash, withdrawalCount:u32, withdrawalActiveBranches:Vec<B256>, forceCount:u32, forceActiveBranches:Vec<B256> }`、`CanonicalRecord{ protocolVersion, recordHash, canonicalBlockHeight, leafIndex, record }`、`HistoricalInclusionProof{ record, recordHash, leafHash, canonicalBlockHeight, checkpointHeight, withdrawalRoot, leafIndex:u32, count:u32, siblings:[B256;32] }`、Game extraData 四字段原像类型。`WithdrawRecord` 结构**镜像** `tz-witness` 暴露的类型，不另写 leaf 编码。
- **claimRoot 编解码**：唯一实现 `compute_claim_root(blockHash, appHash, withdrawalRoot, forceRoot) = keccak256(128B)`（替换现有两字段 `compute_tz_root_claim`；两字段路径按 wire v1 兼容保留）。
- **WB client 扩展**（在 `chain_client.rs` 或新 `witness_client.rs`）：
  1. Publishable CheckpointV2：`GET /chain/dex_state_snapshot?height={H}&format=root&schemaVersion=2` → 扁平 `SnapshotQueryResponse`（v2 四字段 + 顶层 `chainId`）；**不传 schemaVersion 默认 v1**（保持既有两字段）。
  2. 任意已处理 canonical 高度的 boundary witness（接口名由实现定，语义按 Protocol §4.2）。
  3. Canonical record：`GET /chain/witness/withdrawals/{recordHash}`。
  4. Historical inclusion proof：`GET /chain/witness/withdrawal-proof?recordHash&checkpointHeight&withdrawalRoot`。
- **稳定错误枚举**：`InvalidRequest / UnsupportedVersion / CheckpointNotFound / WithdrawalNotFound / RecordNotInCheckpoint / NotReady / RootMismatch / WitnessStoreCorrupt`。`NotReady` 与临时 RPC 错误 → 可重试（退避）；其余按语义分流。U256 JSON 用十进制字符串，hash/address 用定长 `0x` hex。

### 5.2 区域二 — Proposer / Range Host / SP1 Range Guest

**主流程不变**：checkpoint cadence、range 切分（`compute_chunks`）、并发证明、aggregation、Game create/prove/resolve、交易管理、监控全部保留。

**SP1 Range Guest（`programs/tz/range/src/main.rs`）核心升级**：
1. 新增私有输入：每个 sub-range 起点两组 `(count, activeBranches)`（Withdrawal + Force）。
2. 用 `tz-witness` 从 boundary 重建 pre `withdrawalInnerRoot`/`forceInnerRoot` → pre `withdrawalRoot`/`forceRoot`；与既有 pre `appHash`、`blockHash` 组成 **pre `claimRoot`（128B）**。
3. 重放 `(S,E]`：`process_block` 后调用 `tz-block-processor::extract_withdrawals` 从 canonical `BlockResult` 提取记录，交 `tz-witness` 计算 leaves/frontier/count/**post root**；Guest **不信任** Host 提供的 leaf 列表或 post root。
4. 输出：`l2PreRoot = pre claimRoot`、`l2PostRoot = post claimRoot`（沿用 `BootInfoStruct` 现有槽位，仅升级语义为四字段）。
5. ForceTx 空树用 `EMPTY_FORCE_ROOT`。

**Range Host / Proposer（`src/tz/proposer.rs` + `l2_provider.rs`）**：
1. 每个 sub-range 起点：除 DexState snapshot 外，从 WB 取两棵树 boundary witness，写入 `range_stdin`。
2. Host 交叉校验：boundary/snapshot/canonical block 的 `blockHeight`/`blockHash` 一致；**chainId 从 checkpoint 响应顶层校验**（boundary 不返回 chainId）。
3. Proposer 侧 rootClaim（`compute_output_root_at_block`）升级为四字段 `claimRoot`（需在 anchor 高度取 CheckpointV2 的 withdrawal/force root）。
4. Game 创建：`extra_data` 升级为 164 字节四字段格式（`l2BlockNumber + parentIndex + blockHash + appHash + withdrawalRoot + forceRoot`），与合约 getter 布局一致；**创建交易前本地重算 claimRoot 并校验 extraData 解码后的四字段原像**。
5. Aggregation：继续用相邻 `postRoot == preRoot` 链接，从而同时绑定 appHash + Withdrawal Tree + ForceTx Tree。

> ⚠️ Guest 程序变化 → SP1 range ELF 与 `rangeVkeyCommitment` 会变，需要重建 ELF 并更新 fdg-config 的 vkey commitment（属实现/交付项，非本 Spec 决策项）。

### 5.3 区域三 — L1 Challenger（`src/tz/game_validator.rs`）

保留现有 Game 扫描与挑战状态机，仅增强 `TzRootClient` / `validate`：
1. checkpoint 查询改带 `schemaVersion=2`，解析完整 CheckpointV2 + **顶层 chainId**。
2. **chainId 守卫**：`SnapshotQueryResponse.chain_id == 本地配置 TZ chainId`，否则视为数据来源错误（不推进）。
3. 从 Game/extraData 读 `withdrawalRoot`/`forceRoot`，按 Game checkpoint height 查 CheckpointV2，**逐字段比较**：`blockHash / appHash / withdrawalRoot / forceRoot` 及 `rootClaim == claimRoot`；任一不一致 → 现有 challenge 流程。
4. `NotReady`/临时 RPC 失败 → 保留待验证 Game 并退避重试，**不因单次 cache miss/RPC 失败永久漏检**（复用现有 `Unavailable` 重试语义）。

> 说明：合约已强制 `rootClaim == keccak256(4 fields)`，逐字段比较与单 claimRoot 比较在密码学上等价；本设计按 Spec §4 显式做逐字段比较 + chainId 守卫，以满足验收（篡改任一字段必挑战）并防跨链数据。

### 5.4 区域四 — 独立 Defender 服务（新增）

**打包（决策 D1）**：`op-succinct-fp` 内新增 `bin/tz_defender.rs` + `src/tz/defender/` 模块；独立 main loop / 配置 / signer / 部署，复用共享 tz 协议类型与 WB client。

**组件**：Challenge watcher（扫 `ChallengeOpened`，等 L2 finality，支持启动 lookback 重扫）、Challenge handler（每个可响应 challenge 一个轻量任务）、WB client（record + proof）、RootManager client（latest/finalized covering root）、Local verifier（复用 `tz-witness::verify_proof`，固定 tag `0x02`）、Proof memory cache（LRU，key `(leafHash, withdrawalRoot)`）、L2 transaction sender（复用现有 nonce/replacement/receipt 能力）、Metrics/alert。

**处理流程**（Protocol §6.2 / op-succinct Spec §5.3）：
`ChallengeOpened` → 等 L2 finality → `getChallenge(leafHash)`（仅处理仍可响应且未过 deadline）→ 按精确 `leafHash/recordHash` 查 WB record（`WithdrawalNotFound`/`NotReady` 在 deadline 前退避重试）→ 取 canonical `recordHeight` → 等 latest finalized RootManager `checkpointHeight >= recordHeight` → 固定 `checkpointHeight + withdrawalRoot` → 查 cache，未命中则查 WB 历史 proof → **本地验证**（`leafHash 一致`、`count>0`、`leafIndex<count`、`siblings[32]`、重建 innerRoot、`keccak256(innerRoot‖uint256(count)‖0x02) == 绑定的 RootManager withdrawalRoot`）→ 仅验证成功才入 cache → 发送前**再次** `getChallenge` 检查状态+deadline → `proveChallenge` 上链 → 等 canonical receipt 并复查最终状态。

**恢复与竞态**：事件用 `(chain, contract, transactionHash, logIndex)` 标识，**不**把 leafHash 当永久事件 ID；同一 leaf 多次 challenge 可复用同 root 下 proof，但每次提交前重查链上状态+deadline；重启靠事件重扫恢复（proof cache 不持久化）；只有达配置 finality 的事件/root 才驱动发送；他人已响应 / challenge 已结束 / L2 reorg / deadline 已过时**不误提交**；deadline 前无 record/covering root/有效 proof 时**只停止响应并告警**——**不主动认输、不发失败交易、不做 timeout settlement**。

### 5.5 区域五 — 配置、可观测性与安全边界

- Proposer / L1 Challenger / Defender **各自独立 signer 与配置**。
- L1 Challenger 配置新增 **TZ chainId**（chainId 守卫用）与 WB endpoint。
- Defender 配置至少覆盖：challenge contract、RootManager、WB endpoint、chain ID、finality、lookback、重试/退避、deadline safety margin、cache capacity、transaction sender 参数。
- Metrics/log/alert 覆盖：等待 record、等待 covering root、proof 校验失败、RPC 错误、交易状态、接近 deadline、事件重扫。

---

## 6. 数据流与不变量

- 四字段 `claimRoot` 从 WB CheckpointV2 → Rust 类型 → SP1 public values → Game extraData **不丢失、不换序**（顺序严格 `blockHash, appHash, withdrawalRoot, forceRoot`）。
- Guest 只依赖起点 boundary + canonical replay 结果，post root 由 `tz-witness` 自算，**不信任 Host**。
- 两棵树独立 namespace/frontier/count；固定 checkpoint 刻意用 Withdraw count=5、ForceTx count=3，交换 root 或复用 count 必失败。
- WB Sidecar 与 Range Guest 对同一区块/ boundary 得**逐字节相同**的 records/leaf 顺序/count/roots（同源 `tz-witness`）。
- chainId 只在 host/challenger 侧从 checkpoint 顶层交叉校验，不进 claimRoot、不进 boundary。

---

## 7. 外部依赖与接口契约

1. **合约组**提供最终 L1 Game、RootManager、Withdraw challenge 的 ABI 与状态枚举；op-succinct 只按最终 ABI 集成，客户端**不新增自定义状态名**。
2. **Witness Builder** 实现 Protocol 的 v2 checkpoint、boundary、record、proof RPC。
3. **Withdraw challenge 合约（X Layer）** 不在本仓库；Defender 依 Protocol §5.3 ABI（`ChallengeOpened(leafHash, responseDeadline)` / `getChallenge(leafHash)->(resolutionStatus:u8, responseDeadline:u64)` / `proveChallenge(leafHash, checkpointBlockHeight:u64, leafIndex:u32, count:u32, siblings:bytes32[32])`；tag `0x02` 合约内固定、不由调用方传）生成绑定。
4. 实施前**重新核验**目标分支、Guest ABI、Game 合约最新实现，不依赖设计文档中的历史 commit 快照。

---

## 8. 依赖方案（决策 D2 + op-succinct Spec §8.4/§8.5）

- **来源修正**：把 `tz-block-processor` / `tz-dex` / `tz-primitives` 的来源从 `ssh://git@github.com/okx/x2.git`（github 镜像，rev `b3e2cf98` 为旧 master，缺 Claim Tree Core / `extract_withdrawals`）**改为** TradeZone GitLab 仓库 `gitlab.okg.com/xlayer-dex/tradezone`，分支 `feature/witness-builder-withdraw-v1`；并**新增 `tz-witness`** 同源。
- **固定 rev**：用固定 `rev=<commit>`（**非** `branch=`），避免编译随分支推进漂移；确切 commit 在实现阶段解析该分支 HEAD 后写回本 Spec 与 `Cargo.toml`（op-succinct Spec §8.4 给出参考示例 `a3f3079b7`）。WB feature 合入 tradezone master 后再切回镜像依赖。
- **依赖方向**：`tz-block-processor → tz-witness → tz-primitives`（单向；`tz-witness` 内禁止 `use tz_block_processor`）。Guest 依赖 `tz-block-processor`（`process_block` + `extract_withdrawals`）+ `tz-witness`（append/root）。
- **编译门槛（硬性）**：实现阶段必须在 **SP1 guest target** 实测 `cargo check` 通过：`rayon` 在 zkvm/tee feature 下被裁掉、`verify_pool` 传 `None` 能过、`tz-primitives`（chrono / serde_json / base64 / rust_decimal）在 guest 下能编译。不能只停留纸面。

---

## 9. 备选方案与被否决的选择

| 决策点 | 采用 | 否决 | 理由 |
|---|---|---|---|
| 树/root/proof 算法归属 | 唯一复用 `tz-witness`（extractor 在 `tz-block-processor`） | 在 op-succinct 内实现第二套 Merkle/root/proof | 明确非目标；跨语言一致性只以 `tz-witness`↔Solidity `claim-tree-v1.json` 对照为 gate；避免双实现漂移。 |
| Defender 打包 | `op-succinct-fp` 内新 bin `tz-defender` + `src/tz/defender/`（D1） | 单独新 crate | 同样满足独立 main/config/signer/部署，且复用共享类型、与现有 4 个 bin 模式一致、脚手架成本低。 |
| tz-* 依赖来源 | tradezone GitLab feature 分支固定 rev（D2） | 继续用 x2 `b3e2cf98`；或只加 tz-witness 不动其余 | x2 是镜像且旧 master 缺 extractor/Claim Tree Core，guest 无法编译；必须整体改源并固定 rev。 |
| Challenger 比较方式 | schemaVersion=2 + 顶层 chainId 守卫 + 逐字段比较 | 只比单 claimRoot（合约已绑定，密码学等价） | 满足 Spec §4 与验收（篡改任一字段必挑战）并显式防跨链数据；保留 NotReady 重试防漏检。 |
| Guest 结束 root 来源 | Guest 自算 post root | 信任 Host 提供的 leaf/post root | 安全性要求：Host 只能给起点 boundary，结束 root 必须 zkVM 内推导。 |

---

## 10. 测试与验收映射

- **贯穿不丢**：两个新 root 从 WB RPC → Rust 类型 → SP1 public values → Game extraData 不丢失、不换序。
- **篡改必败**：篡改 `blockHash/appHash/withdrawalRoot/forceRoot` 任一 → Guest / aggregation / Game 校验 / Challenger 必失败。
- **多 sub-range**：完整四字段 pre/post claimRoot 连续连接。
- **boundary 还原**：count 0/1/2/3/5 的 activeBranches 可还原相同 pre root，追加后得相同 post root。
- **双树独立**：固定 checkpoint Withdraw count=5 / ForceTx count=3，namespace/frontier/count 独立；交换 root 或复用 count 必失败。
- **WB↔Guest 一致**：固定区块与 boundary 下，逐字节相同 records/leaf 顺序/count/roots。
- **Challenger**：任一字段不一致挑战；chainId 不匹配不推进；`NotReady`/临时错误重试且不漏检。
- **Defender**：合法 proof 本地验证并成功上链；错误 leaf/index/count/tag/sibling/root 不发交易；`leafIndex==count`、`count==0`、siblings 长度错必拒；同 `(leafHash, withdrawalRoot)` 重复 challenge 命中缓存、root 变化 cache miss、命中仍检查状态+deadline；WB 延迟收录、RootManager 延迟覆盖、到期无 proof（只告警不发失败交易）、事件重复、进程重启、他人抢先、L2 reorg 均不误提交。
- **跨语言**：Solidity harness 与 Defender Rust verifier 对同一 fixture 结论一致（至少 ERC20、ERC1155 batch、空树拒绝、错误 tag、`leafIndex==count`）。
- **回归**：原有 proposal/prove/resolve/challenge 回归测试继续通过。
- **fixture 使用规则**：`tz-witness` 与 Solidity 以冻结 `claim-tree-v1.json` 做跨语言对照（Solidity 以它为 gate）；SP1 与 Defender 复用 `tz-witness`、与 WB 同源，不单独以 golden vector 为 gate，也**不**在测试期调用 generator 生成期望值或各自维护手写常量。

---

## 11. 非目标

- 不实现/重构 L1/L2 合约本体；仅按最终 ABI 集成。
- 不在 op-succinct 内实现第二套 Claim/Merkle Tree 算法。
- 不提交 Relayer 快路径记录；不合并 Relayer 与 Defender。
- 不生成或伪装 non-inclusion proof。
- Defender 不创建 L1 Game、不生成 Withdrawal Root、不执行 timeout settlement。
- 不改变现有 appHash 执行语义与 checkpoint cadence。

---

## 12. 约束与风险

- **单向依赖 & guest 编译**：见 §8 编译门槛，最大落地风险；实现阶段先 `cargo check` 再展开。
- **ELF/vkey 变更**：guest 变化导致 range ELF/`rangeVkeyCommitment` 更新，属交付协调项。
- **固定 rev 记录**：确切 tz-* commit 必须写回 Spec 与 Cargo.toml，避免 branch 漂移。
- **合约组 ABI 未冻结项**：Withdraw challenge 合约/状态枚举以合约组最终交付为准；接口名以实现为准（字段/编码/语义不变）。
- **单分支单 MR**：全流程维持一个 feature 分支、一个开放 MR；提交与 MR 标题以 `[Oli] ` 开头；不合并/部署/发布/force-push/直推目标分支。

---

## 13. 交付物（本设计范围内的改动面）

- `Cargo.toml`：tz-* 依赖改源 + 新增 `tz-witness`（固定 rev）。
- `fault-proof/src/tz/`：新增 `protocol/`（类型/编解码）、扩展 `chain_client.rs`（4 endpoint + 错误枚举）、`l2_provider.rs`（四字段 claimRoot）、`proposer.rs`（boundary plumbing + 164B extraData + 本地校验）、`game_validator.rs`（schemaVersion=2 + chainId 守卫 + 逐字段比较）、`config.rs`（chainId + Defender 配置）、新增 `defender/` 模块。
- `fault-proof/bin/tz_defender.rs`：新 bin。
- `programs/tz/range/src/main.rs`：四字段 claimRoot + boundary + tz-witness append/root。
- 测试：单元/集成/回归 + 跨语言对照（§10）。
- `docs/superpowers/`：本 Spec、后续 plan、`lark-review-doc.md`（随 CoW 与 stage-5 tar 前进）。
