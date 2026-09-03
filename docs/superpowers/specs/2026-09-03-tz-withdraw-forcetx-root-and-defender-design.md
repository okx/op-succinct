# op-succinct — Withdraw/ForceTx Root 贯穿与独立 Defender 设计

- **Jira**: [TRDZN-1339](https://okcoin.atlassian.net/browse/TRDZN-1339) — `[op-succinct] 实现 Withdraw/ForceTx Root 贯穿与独立 Defender`
- **Repository**: op-succinct (`https://gitlab.okg.com/github/op-succinct.git`)
- **Selected branch (dev base + MR target)**: `xl/tz-challenger-v2`
- **Date**: 2026-09-03
- **Status**: APPROVED by creator on 2026-09-03 (via Oli AskUserQuestion, round 1)
- **Lark Review Document**: https://okg-block.sg.larksuite.com/docx/YyUBdnoNwoigFIxMNRulItKDgCb （记录见 `docs/superpowers/lark-review-doc.md`）

> **权威来源**：本 Spec 是 op-succinct 侧的实现设计。字段/编码/哈希/调用语义的唯一权威是
> Jira 引用的 Protocol 文档与冻结的 `claim-tree-v1.json` fixture；文档间冲突以 Protocol 正文
> 与 fixture 为准。本 Spec 不改变任何协议常量，只描述如何在 op-succinct 现有代码上落地。

---

## 0. 概述 / Executive Summary（中文）

**目标**：把「四字段 checkpoint claim」——`claimRoot = keccak256(blockHash ‖ appHash ‖ withdrawalRoot ‖ forceRoot)`
——从 Witness Builder(WB) 一路贯穿到 SP1 Range Host+Guest、L1 Game、L1 Challenger；并新增一个
**独立 Defender 服务**,用历史 inclusion proof 响应 X Layer 上的 Withdraw challenge。Withdrawal/ForceTx
两棵树的计算**不在 op-succinct 重写**,统一复用 TradeZone Claim Tree Core。

**已就绪(直接对接,不重复实现)**:
- **合约层**:`contracts/src/fp/OPSuccinctFaultDisputeGame.sol` 已是「四原像」游戏——extraData 已含
  `withdrawalRoot`/`forceRoot`,并在链上强制 `rootClaim == keccak256(abi.encodePacked(blockHash, appHash, withdrawalRoot, forceRoot))`;
  `TZRootManager.sol` 已实现 `record/getRoots/getLatestRoots` + `RootsRecorded` 事件;`PostAnchor.sol` 已从 Game 读 root 入队。
- **Witness Builder**:tradezone `feature/witness-builder-withdraw-v1` 已实现;root-format 已返回四字段
  `components`;boundary / canonical record / historical inclusion proof 接口按 WB Spec 提供。

**本 Task 要补齐的 op-succinct 侧缺口**:
1. **共享库**(`fault-proof/src/tz/withdraw/`):协议/ABI 类型、WB 客户端新方法 + 稳定错误枚举、claimRoot 编解码、给 Defender 用的树校验 adapter。
2. **Proposer / Range Host / SP1 Range Guest**:每个 sub-range 起点向 WB 取两棵树 `count + activeBranches` boundary;Guest 由 boundary 重建 pre roots、重放 canonical blocks、把 `BlockResult` 交给 Claim Tree Core 自算 post roots;把 `l2PreRoot/l2PostRoot` 语义升级为完整四字段 claimRoot;建 Game 前本地重算并校验四字段原像。
3. **L1 Challenger**:从 Game extraData 读 `withdrawalRoot/forceRoot`,按 checkpoint 高度查 WB CheckpointV2,校验 `chainId`,逐字段比较 `blockHash/appHash/withdrawalRoot/forceRoot/claimRoot`;`NotReady`/临时错误退避重试不漏检。
4. **独立 Defender**:新 binary,独立 main loop/config/signer;监听 `ChallengeOpened` → 查 WB record → 等 RootManager 覆盖高度 → 取历史 proof → 本地校验 → LRU 缓存 → `proveChallenge` → 复查回执。
5. **配置 / 可观测 / 安全边界**:三服务独立 signer 与配置;Defender 丰富配置 + 指标/日志/告警;复用现有 transaction sender。

**关键决策(经 creator 确认)**:
- **决策 1 — 范围**:op-succinct 侧全实现,以冻结 `claim-tree-v1.json` fixture 验证;WB 与合约已实现,以真实代码为准对接;**唯一未就绪的「L2 树挑战/证明接口」先写一个简单 mock 框架**,Defender 逻辑对 mock + fixture 完整可测。
- **决策 2 — 代码结构**:全部放在现有 `fault-proof` crate 内。共享码 → `fault-proof/src/tz/withdraw/`;Defender → 新 binary `fault-proof/bin/tz_defender.rs` + 模块 `fault-proof/src/tz/defender/`,复用现有 transaction sender / signer / prometheus,但**独立 main loop、config 结构与 signer 实例**。SP1 guest 的树计算直接依赖外部 TradeZone Claim Tree Core。
- **决策 3(设计推论,非新问题)— claimRoot 硬切换**:补齐 proposer/guest 侧的 2→4 字段切换。这会改变 range/agg vkey,**需要 `just build-tz-elfs` + `just tz-vkeys` + 更新 `opsuccinctfdgconfig.json` + 重新部署**。不做双模式(协议禁止 wire 混用)。

---

## 1. Additional Context

本 Task 的 native 输入中**没有 Additional Context**(初始运行,无 rework)。因此没有需要归类为
requirement/constraint/preference/scope-note/operational-note/ambiguity 的补充条目,也没有与
Jira/PRD/仓库事实冲突需要通过 AskUserQuestion 解决的项。若后续 rework 轮次带来新的 creator 反馈,
将在本节追加原文与其设计影响。

---

## 2. Background & Goal

TradeZone(TZ) 是一条非 OP-Stack L2。op-succinct 已在 `xl/tz-challenger-v2` 分支上通过 `--features tz`
支持 TZ:checkpoint 走 REST(`GET /chain/...`)而非 `eth_getBlockByNumber`,证明由 SP1 range+aggregation 生成,
在 L1 上用 `OPSuccinctFaultDisputeGame` 创建/推进/resolve。

TradeZone Withdraw 协议要求把 checkpoint 的 claim 从「两字段」`keccak256(blockHash ‖ stateHash)` 升级为
「四字段」`claimRoot = keccak256(blockHash ‖ appHash ‖ withdrawalRoot ‖ forceRoot)`,其中 `withdrawalRoot`/`forceRoot`
来自两棵深度 32 的增量 Merkle 树(Withdrawal tag `0x02` / ForceTx tag `0x01`)。同时新增独立 Defender,
在 X Layer challenge 打开时用历史 inclusion proof 响应。

目标是让完整四字段 claim 从 WB → SP1 → L1 Game → L1 Challenger 全链贯穿、逐字段可校验,并让 Defender
作为与 Proposer/L1 Challenger 完全分离的服务安全地响应挑战。

---

## 3. Current Baseline（已核验 · grounded）

> 通过 codegraph(81,570 nodes / 247,136 edges)+ 直接读源码 + 本仓库 `context-kg/technical/` 核验。

### 3.1 已存在
| 位置 | 现状 |
|---|---|
| `contracts/src/fp/OPSuccinctFaultDisputeGame.sol` | 「四原像」游戏。CWIA immutable-args 布局:`0x14 rootClaim`、`0x34 l1Head`、`0x54 l2BlockNumber(u256)`、`0x74 parentIndex(u32)`、`0x78 blockHash`、`0x98 appHash`、`0xB8 withdrawalRoot`、`0xD8 forceRoot`。`extraData()` = `0x54..end`(四原像模式 **164 字节**,legacy 36 字节,由 `HAS_ROOT_CLAIM_PREIMAGE` 门控)。`_checkRootClaimCommitment()`(L695)链上强制 `rootClaim == keccak256(abi.encodePacked(blockHash, appHash, withdrawalRoot, forceRoot))`。getter `withdrawalRoot()/forceRoot()/blockHash()/appHash()` 均已提供。 |
| `contracts/src/fp/TZRootManager.sol` + `interfaces/ITZRootManager.sol` | `record(bytes32 withdrawalRoot, bytes32 forceTxRoot, uint256 checkpointBlockHeight)`;`getRoots(height) → (w,f)`(未命中返双零);`getLatestRoots() → (height,w,f)`;`event RootsRecorded(w,f,height)`。 |
| `contracts/src/fp/PostAnchor.sol` + `interfaces/ITZClaimGame.sol` | Anchor 后从 Game 读 `withdrawalRoot()/forceRoot()` 并 `RootsEnqueued`。 |
| `fault-proof/src/tz/game_validator.rs` | `TzGameValidator` + `TzRootClient`。`compute_v3_claim_root` 已算 128 字节四字段 claimRoot;`TzRootClient` 已查 `/chain/dex_state_snapshot?height=H&format=root`,解析 `RootResponse{status, canonicalBlockHash, claimRoot, components{blockHash,appHash,withdrawalRoot,forceRoot}, localTip, detail}`,当 `components` 存在时重算并核对 claimRoot;把 Game `output_root` 与 WB `claim_root` 比较,`running/above_local_tip/*_unavailable` 走重试。 |
| `fault-proof/src/tz/chain_client.rs` | `TzChainClient`:DexState snapshot 异步 replay(4 端点状态机)+ `/chain/blocks`(区块范围)。多 endpoint failover;同步 `Mutex<HashMap<u64,TzBlockInfo>>` checkpoint 缓存 + `evict_below(anchor)`。 |
| `fault-proof/src/tz/l2_provider.rs` | `TzL2Provider`(`L2ProviderTrait`)。`compute_tz_root_claim(block_hash, state_hash) = keccak256(blockHash ++ stateHash)` — **仍是两字段**;`get_next_proposal_block` interval gate。 |
| `fault-proof/src/tz/proposer.rs` | tz `#[path]` 覆盖 `prove_game`;multi-range `tz_prove`(1–16 段,并发,按 idx 重排);`BootInfoStruct::abi_decode`(160 字节 Solidity-ABI,非 bincode)。 |
| `programs/tz/range/src/main.rs` | Range guest:`commit_slice(&SolValue::abi_encode(&boot_info))`。 |
| `programs/tz/aggregation/{commit,link_check,verify}.rs` | Agg guest:`link_check` 对 `boot_infos.windows(2)` 断言 `prev.l2PostRoot == curr.l2PreRoot`;`verify` 用 `Sha256::digest(boot_info.abi_encode())` 算 pv_digest。 |
| `fault-proof/src/tz/config.rs` | `TzConfig { rpc_urls, game_type=1961 }`(仅此两项)。 |

### 3.2 缺口(= 本 Task)
- Proposer/Host/Guest 仍产出两字段 claim(`compute_tz_root_claim`);未取 boundary witness;Guest 不算树根。
- 无 TreeBoundaryWitness / canonical record / historical inclusion proof 客户端方法。
- L1 Challenger 未从 Game extraData 读 `withdrawalRoot/forceRoot` 做逐字段比较;未校验 `chainId`;WB 客户端 wire 与协议 `CheckpointV2`(含 `schemaVersion/chainId/blockHeight`)及稳定错误枚举未对齐。
- 无 Defender 服务。
- `TzConfig` 过于精简,Defender 需要独立丰富配置。

---

## 4. 权威协议不变量（本设计据以落地，不得改动）

- `claimRoot = keccak256(blockHash ‖ appHash ‖ withdrawalRoot ‖ forceRoot)`,原像 **128 字节**;`chainId`/`blockHeight` 不进 claimRoot。`chainId` 仅用于 host 侧确认数据属正确 TZ 链,非 0。
- `withdrawalRoot = keccak256(innerRoot ‖ uint256(count) ‖ 0x02)`;`forceRoot = keccak256(innerRoot ‖ uint256(count) ‖ 0x01)`;外层 preimage 固定 **65 字节**,`count` 为大端右对齐 `uint256`。
- 固定空树向量(非零,必须各自计算而非互抄):`emptyInnerRoot=0x27ae5ba0…d757`;`EMPTY_FORCE_ROOT=0x2ce29f3b…2a56`;`EMPTY_WITHDRAWAL_ROOT=0x6b7dbdc9…76d7`。
- 增量树:`TREE_DEPTH=32`;frontier=`branch[32]+count`(`count`/`leafIndex` 为 `u32`);父 `keccak256(left‖right)` 不排序;空叶 `bytes32(0)`,空子树 `z[h+1]=keccak256(z[h]‖z[h])`。
- inclusion proof = `leafIndex + count + siblings[32]`;验证前必须检查 `count > 0`、`leafIndex < count`、`siblings.len()==32`。
- Boundary witness wire:`count==0 ⇒ activeBranches=[]`;否则只含 `count` 二进制置位层级的 branch,`len==popcount(count)`,按 level 低→高,元素为裸 `bytes32`,无 level 字段/无 zero 占位;解码方必须校验长度并重建声明 root,不符即拒。
- Withdraw leaf = `keccak256(abi.encode(version, chainId, transactionHash, tokenType, tokenAddress, tokenIds, amounts, from, to))`(Solidity `abi.encode` 语义,非 packed);V1 `recordHash == leafHash`。
- ForceTx 当前无叶子 ⇒ `forceRoot = EMPTY_FORCE_ROOT`(count=0),**不因未启用而返回 NotReady**。
- 树/leaf/root/proof 算法唯一来源为 TradeZone Claim Tree Core(agglayer `unified-bridge 0.18.0` LocalExitTree 谱系);op-succinct 只加最外层 `count+tag` 包装的对照与集成,不复制内层算法。

---

## 5. 范围与外部依赖策略（决策 1）

**策略:fixture-first,seam 后集成。**

| 外部输入 | 就绪状态 | 本 Task 如何处理 |
|---|---|---|
| 合约(Game/RootManager/PostAnchor) | **已实现**(本仓库 `contracts/src/fp`) | 直接对接真实 ABI/getter/extraData 布局;不改合约本体(非目标)。 |
| Witness Builder v2 RPC | **已实现**(tradezone `feature/witness-builder-withdraw-v1`) | 客户端对接真实端点;wire 与协议 `CheckpointV2` + 稳定错误枚举对齐;以真实 route 为准核验。 |
| TradeZone Claim Tree Core | 上游提供 | 以 git 依赖引入;SP1 guest 与 Defender verifier 复用;若因 crate/target 边界需薄 adapter,其行为必须逐字节等价于 Protocol 3.3.2 Rust 对照实现。 |
| **L2 树挑战/证明接口**(X Layer `ChallengeOpened/getChallenge/proveChallenge`) | **未就绪** | **先写一个简单 mock 框架**(trait + 内存 mock 合约 + 事件注入),Defender 状态机对 mock + 冻结 fixture 完整可测;真实 ABI 就绪后替换 binding,状态机不变。 |
| 冻结 `claim-tree-v1.json` + `tradezone-claim-tree-reference-v1.zip` | 提供 | 复制/以测试资源引入 `fault-proof` 测试;所有 Rust/SP1/Defender 测试只读冻结文件,不在测试时调用 generator。 |

**产出**:一个能**编译、能过测试**的 MR(build- & test-green)。真实上线端点的端到端联调留待运行期
(stage 4 之后 / 运维);L2 挑战接口以 mock 承载,不阻塞 MR。凡缺少外部 crate 无法编译处,以 `tz` feature 门控 + trait/mock 顶上。

---

## 6. 架构与代码结构（决策 2 — 全部在 `fault-proof` crate 内）

```
fault-proof/
  src/
    tz/
      withdraw/                 # 新增:三 binary 共享库(host 侧)
        mod.rs
        types.rs                # CheckpointV2 / TreeBoundaryWitness / WithdrawRecord /
                                #   HistoricalInclusionProof / GameCheckpointPreimage 等
        claim.rs                # 四字段 claimRoot 128B 编解码 + 校验
        wb_client.rs            # WB v2 客户端新方法 + 稳定错误枚举(WbError)
        tree_adapter.rs         # Claim Tree Core 薄 adapter:inner_root/business_root/verify_proof
        error.rs                # WbError 分类(可重试 vs 永久)
      defender/                 # 新增:Defender 服务实现(独立 main loop 逻辑)
        mod.rs
        watcher.rs              # ChallengeOpened 扫描 + finality + 启动重扫
        handler.rs              # 单 challenge 轻量任务状态机
        rootmanager_client.rs   # RootManager latest/finalized covering root
        verifier.rs             # 本地 proof 校验(复用 tree_adapter)
        cache.rs                # (leafHash, withdrawalRoot) → proof 的 LRU
        config.rs               # DefenderConfig(独立配置)
        challenge_contract.rs   # L2 挑战合约接口 trait + mock 框架(决策 1)
      chain_client.rs           # 现有(snapshot/blocks) — 保留
      l2_provider.rs            # 改:compute_tz_root_claim → 四字段;boundary 拉取入口
      proposer.rs / challenger.rs / config.rs   # 增量改造
  bin/
    tz_proposer.rs   tz_challenger.rs           # 现有
    tz_defender.rs                              # 新增(required-features=["tz"])
programs/tz/range/                              # guest:依赖外部 Claim Tree Core,重放算 post roots
programs/tz/aggregation/                        # 保持 windows(2) 链接;root 语义为四字段 claimRoot
```

**隔离保证**:Proposer / L1 Challenger / Defender 三个 binary 各自 `main()`、各自 config、各自 signer 实例。
Defender 复用 `fault-proof` 已有的 transaction sender(nonce/replacement/receipt)与 prometheus 基座,
但不读取 Proposer/Relayer 本地缓存作为权威数据,也不与 Relayer 合并。

---

## 7. 组件设计

### 7.1 共享库 `fault-proof/src/tz/withdraw/`

- **类型(`types.rs`)**:与协议逐字段对应。`CheckpointV2 { schema_version, chain_id:u64, block_height:u64, block_hash:B256, app_hash:B256, withdrawal_root:B256, force_root:B256, claim_root:B256 }`;`TreeBoundaryWitness { schema_version, chain_id, block_height, withdrawal_count:u32, withdrawal_active_branches:Vec<B256>, force_count:u32, force_active_branches:Vec<B256> }`;`WithdrawRecord`(V1 九字段);`HistoricalInclusionProof { record, record_hash, leaf_hash, canonical_block_height, checkpoint_height, withdrawal_root, leaf_index:u32, count:u32, siblings:[B256;32] }`;`GameCheckpointPreimage { checkpoint_block_height:u64, parent_index:u32, block_hash, app_hash, withdrawal_root, force_root }`。
- **claimRoot 编解码(`claim.rs`)**:`claim_root(block_hash, app_hash, withdrawal_root, force_root) -> B256`(128B `abi.encodePacked` 语义,与合约 L695 及 `compute_v3_claim_root` 逐字节一致)。提供 Game extraData(164B)解码:`decode_four_preimage_extra_data(&[u8]) -> GameCheckpointPreimage`,`u64` 高度从 `uint256` 解码时拒绝 `> u64::MAX`。
- **WB 客户端(`wb_client.rs`)**:统一 host 侧 WB 访问,收敛现有 `TzRootClient`(root-format)+ 新方法:
  - `get_checkpoint_v2(height) -> Result<CheckpointV2, WbError>`(root-format v2,含 `chainId` 与四字段;以响应 `schemaVersion` 区分 v1/v2)。
  - `get_tree_boundary_witness(height) -> Result<TreeBoundaryWitness, WbError>`(任意已处理 canonical 高度)。
  - `get_canonical_record(record_hash) -> Result<CanonicalRecord, WbError>`。
  - `get_historical_inclusion_proof(record_hash, checkpoint_height, withdrawal_root) -> Result<HistoricalInclusionProof, WbError>`。
  解码 boundary 时按 §4 校验 `len==popcount(count)` 并重建声明 root,不符即 `WbError::WitnessStoreCorrupt`/拒绝。
- **稳定错误枚举(`error.rs`)**:`WbError::{ InvalidRequest, UnsupportedVersion, CheckpointNotFound, WithdrawalNotFound, RecordNotInCheckpoint, NotReady, RootMismatch, WitnessStoreCorrupt, Transport(..) }`,并暴露 `is_retryable()`——`NotReady` 与临时 transport/5xx 可重试,其余永久。调用方据此重试或告警。
- **树 adapter(`tree_adapter.rs`)**:薄封装 TradeZone Claim Tree Core,暴露 `calculate_inner_root(leaf, leaf_index, &siblings)`、`business_root(inner_root, count, tag)`、`verify_proof(leaf, leaf_index, count, &siblings, expected_root, tag)`,行为逐字节等价于 Protocol 3.3.2。**不复制内层算法**。

### 7.2 Proposer / Range Host / SP1 Range Guest

- **Range Host**(每个 sub-range 起点 `S`):除现有 `fetch_dex_state_snapshot(S)` 外,新增 `wb_client.get_tree_boundary_witness(S)`,得两棵树 `count + activeBranches`,作为 Guest 私有输入(追加进 `SP1Stdin`,新增字段 → 改 range vkey,host+guest 同步改)。Host 交叉校验:boundary 的 `blockHash`/`chainId` 与同高度 DexState snapshot、CheckpointV2、canonical block 一致;不一致则该 sub-range 失败并告警。
- **SP1 Range Guest**(`programs/tz/range`):
  1. 由 DexState snapshot 重算 pre `appHash`(现有语义)。
  2. 由两组 `count/activeBranches` + 固定 zero hashes 经 Claim Tree Core 重建两个 pre `innerRoot`,包 `count+tag` 得 pre `withdrawalRoot/forceRoot`;三者组成完整 **pre claimRoot**。
  3. 重放 `(S,E]` canonical blocks,把 `process_block` 返回的 `BlockResult` 交给 Claim Tree Core **自行**提取 records/leaves、追加 frontier、算 count 与 post `innerRoot/businessRoot`。**Guest 不信任 Host 提供的 leaf 列表或 post root**。
  4. 输出完整 **post claimRoot**。`BootInfoStruct` 的 `l2PreRoot/l2PostRoot` 语义升级为四字段 claimRoot(ABI 形状不变,仍 160B Solidity-ABI)。ForceTx 无叶 ⇒ 空树根(count=0)。
- **Aggregation**:保持相邻 `postRoot == preRoot` 链接(`link_check.rs windows(2)`)。因 root 语义升级为四字段,聚合天然同时绑定 appHash + Withdrawal + ForceTx 三者。
- **建 Game 前**:Proposer 本地用 `claim.rs` 重算 `claimRoot`,并校验将写入 extraData 的四字段原像(164B 布局:`l2BlockNumber(32)+parentIndex(4)+blockHash(32)+appHash(32)+withdrawalRoot(32)+forceRoot(32)`)自洽,再创建/推进 Game。`compute_tz_root_claim` 由两字段改为调用 `claim.rs` 的四字段实现。

### 7.3 L1 Challenger

保持现有 Game 扫描与挑战状态机,`TzGameValidator` 增量增强:
1. 从 Game 读四原像(`extraData()`/getter `withdrawalRoot()/forceRoot()/blockHash()/appHash()`)。
2. 按 Game 的 checkpoint 高度调 `wb_client.get_checkpoint_v2(height)`。
3. 校验 `checkpoint.chain_id == 本地配置 TZ chain ID`(防查错链)。
4. 逐字段比较:`game.blockHash == cp.block_hash`、`game.appHash == cp.app_hash`、`game.withdrawalRoot == cp.withdrawal_root`、`game.forceRoot == cp.force_root`、`game.rootClaim == cp.claim_root`。任一不一致 → 走现有 challenge 流程。
5. `WbError::NotReady` 或临时错误 → 保留待验证 Game 并按现有 `above_local_tip`/retry 语义退避重试;**不得因单次 cache miss/RPC 失败推进后永久漏检**。
无需新增第二套 proof/Game/状态机。

### 7.4 独立 Defender 服务(`bin/tz_defender.rs` + `src/tz/defender/`)

**目标**:监听 X Layer challenge 合约,用历史 inclusion proof 在 deadline 前 `proveChallenge`。
**非目标**:不提交 Relayer 快路径记录;不生成 Withdrawal Root;不创建 L1 Game;不生成 non-inclusion proof;
无法证明时不发送主动失败/认输/超时结算交易(超时结算由 Challenger 触发)。

**组件**:`watcher`(扫 `ChallengeOpened`,等配置 L2 finality,支持启动 lookback/安全高度重扫)、
`handler`(每个仍可响应的 challenge 一个轻量任务)、`wb_client`(复用共享库)、`rootmanager_client`(读 latest/finalized covering root)、
`verifier`(复用 `tree_adapter` 本地校验)、`cache`(LRU)、`l2 transaction sender`(复用现有,提交并等回执)、`metrics/alert`。

**状态机**(严格按 Protocol §6.2 / op-succinct Spec §5.3):
```
发现 ChallengeOpened(按 chain+contract+txHash+logIndex 标识)
  → 等 L2 finality
  → getChallenge(leafHash);已结束/不可响应 ⇒ 结束
  → 按精确 leafHash/recordHash 查 WB canonical record
       WithdrawalNotFound/NotReady 且未到 deadline ⇒ 退避重试;到 deadline 仍无 ⇒ 停止响应+告警
  → 取 canonical recordHeight(来自 WB,不信任调用方附带高度)
  → 等最新 finalized RootManager checkpointHeight >= recordHeight
  → 固定 (checkpointHeight, withdrawalRoot)
  → 查内存 LRU cache(leafHash, withdrawalRoot)
       命中 ⇒ 用缓存 proof;未命中 ⇒ 向 WB 取该精确 root 下的历史 proof
  → 本地校验:leafHash 相符;count>0;leafIndex<count;siblings.len()==32;
       按 leafIndex 位序重建 innerRoot;keccak256(innerRoot‖uint256(count)‖0x02) == 已绑定 withdrawalRoot
       任一失败 ⇒ 不发交易 + 告警(WB/协议不一致)
  → 校验通过的 proof 写入 LRU(key=(leafHash, withdrawalRoot))
  → 再次 getChallenge 读状态+deadline;仍可响应 ⇒ proveChallenge 上链
  → 等 canonical receipt 并复查最终状态
```
**恢复与竞态**:事件用 `chain/contract/txHash/logIndex` 标识,不把 leafHash 当永久唯一 ID;重启靠事件重扫恢复
(不持久化 proof cache);只有达到 finality 的事件/root 才驱动发送;其他 Defender 已响应、challenge 已结束、
L2 reorg、deadline 已过时不得错误提交;缓存命中仍必须复查链上状态与 deadline。

**L2 挑战接口 mock 框架(决策 1)**:`challenge_contract.rs` 定义 trait
`ChallengeContract { watch_opened(); get_challenge(leaf_hash) -> (status, deadline); prove_challenge(leaf_hash, checkpoint_height, leaf_index, count, siblings); }`,
Defender 只依赖 trait。提供内存 `MockChallengeContract`(可注入 `ChallengeOpened`、可编排 status/deadline、记录 `proveChallenge` calldata)供单测/集成测试。真实 ABI 就绪后新增真实实现替换 mock,状态机与校验逻辑不变。合约内部固定 Withdraw tag `0x02`,不由 calldata 传入。

### 7.5 配置、可观测性与安全边界

- Proposer / L1 Challenger / Defender 各用独立 signer 与配置。现有 `TzConfig` 保持不动;Defender 新增 `DefenderConfig`,至少覆盖:challenge contract 地址、RootManager 地址、WB endpoint、chain ID、finality、lookback、重试/退避、deadline safety margin、cache capacity、transaction sender 参数。
- 新增指标/日志/告警:等待 record、等待 covering root、proof 校验失败、RPC 错误、交易状态、接近 deadline、事件重扫。
- 复用现有 transaction sender 的 nonce/replacement/receipt 处理。
- 安全:Defender 不读 Proposer/Relayer 本地缓存作权威;不与 Relayer 合并;所有等待/重试受链上 `responseDeadline` 约束。

---

## 8. claimRoot 硬切换与影响面（blast radius）

`compute_tz_root_claim` 从两字段升级为四字段,并让 range/agg guest 输出四字段 claimRoot。影响面:
- **改变 range vkey 与 agg vkey** ⇒ 必须 `just build-tz-elfs` + `just tz-vkeys` + 更新 `contracts/config/tz/opsuccinctfdgconfig.json`(`rangeVkeyCommitment`/`aggregationVkey`)+ 重新部署(deploy-tz)。
- host+guest 的 `SP1Stdin` 布局新增 boundary 字段,必须两侧同步。
- `link_check` 在 N≥2 时才会暴露跨进程字节漂移;测试需覆盖 N≥2。
- 不做双模式(2/4 字段并存)——协议禁止 wire 混用,且会 double 化 guest/agg/challenger 路径。既有 WB root-format v1 语义仅在协议兼容规则要求处保留(以响应 `schemaVersion` 区分)。

---

## 9. 测试策略（fixture-driven）

所有 Rust/SP1/Defender/Solidity 集成测试**共同读取冻结 `test/fixtures/claim-tree-v1.json`**,测试期间不调用 generator、不各自维护手写常量。至少覆盖:
1. 两个新增 root 从 WB RPC → Rust 类型 → SP1 public values → Game extraData 不丢失、不换序。
2. 篡改 `blockHash/appHash/withdrawalRoot/forceRoot` 任一字段:Guest、aggregation、Game 校验或 Challenger 必须失败。
3. 多 sub-range pre/post 完整 claimRoot 连续连接(N≥2)。
4. boundary `count = 0/1/2/3/5` 的 activeBranches 可恢复相同 pre root,追加后得相同 post root。
5. 固定 checkpoint:Withdraw count=5、ForceTx count=3 两棵树 namespace/frontier/count 独立;交换 root 或复用 count 必须失败;最终 claimRoot == fixture。
6. WB Sidecar 与 Range Guest 对固定区块+boundary 得逐字节相同 records/leaf 顺序/count/roots。
7. L1 Challenger:任一字段不一致时挑战;`NotReady`/临时错误重试且不漏检;chainId 不符拒绝。
8. Defender:合法 proof 本地校验并成功 `proveChallenge`;错误 leaf/index/count/tag/sibling/root 不发交易;`leafIndex==count`、`count==0`、siblings 长度错误必须拒绝。
9. 相同 `(leafHash, withdrawalRoot)` 重复 challenge 命中缓存;root 变化后 cache miss;缓存命中仍复查状态+deadline。
10. WB 延迟收录、RootManager 延迟覆盖、到期无 proof、事件重复、进程重启、其他 Defender 抢先、L2 reorg(用 mock 合约 + fixture 编排)。
11. 空树固定向量(`emptyInnerRoot`/`EMPTY_FORCE_ROOT`/`EMPTY_WITHDRAWAL_ROOT`)由 Rust 独立计算并断言,不互抄。
12. 原有 proposal/prove/resolve/challenge 回归测试继续通过。

---

## 10. 非目标（Non-Goals）

- 不实现或重构 L1/L2 合约本体(合约已就绪,仅按最终 ABI 集成)。
- 不在 op-succinct 实现第二套 Claim Tree / Merkle Tree 算法。
- 不提交 Relayer 快路径记录;不合并 Relayer 与 Defender。
- 不生成或伪装 non-inclusion proof。
- Defender 不创建 L1 Game、不生成 Withdrawal Root、不执行 timeout settlement。
- 不改变现有 appHash 执行语义与 checkpoint cadence。

---

## 11. Alternatives Considered & Rejected

### 11.1 范围策略(决策 1)
- **[采纳] fixture-first,seam 后集成**:全实现 op-succinct 侧 + 冻结 fixture 验证;L2 挑战接口先 mock。既满足单 MR 可编译可测,又落地最关键的安全校验逻辑。
- [拒绝] 等全部外部就绪再端到端:整 MR 被别的团队卡死,阻塞 flow。
- [拒绝] 只搭骨架、推迟树/证明校验:把最关键、最需保证安全的 verify 逻辑推后且不验证,风险最高。

### 11.2 代码结构(决策 2)
- **[采纳] 全放 `fault-proof` crate**:共享码 `src/tz/withdraw/`,Defender 为新 binary。改动最小、贴合现状(tz 本就在 `fault-proof/src/tz/`),直接满足「复用现有 tx sender」。
- [拒绝] 共享库/Defender 各自独立 crate:隔离最强但接线最多,且 Defender 要重接 tx sender/signer,与「复用现有 tx sender」摩擦。
- [拒绝] 折中(纯类型小 crate + fault-proof 接线):多一个 crate 维护成本,收益有限(guest 树计算本就直接依赖外部 Claim Tree Core,无需 op-succinct 中间 crate)。

### 11.3 claimRoot 迁移
- **[采纳] 硬切换到四字段**(协议要求;合约与 challenger 已就绪四字段),接受 vkey/ELF/redeploy 影响面。
- [拒绝] 双模式并存:协议禁止 wire 混用,复杂度翻倍。

---

## 12. 约束与运维注记（Constraints / Operational Notes）

- 本 Task 完成后必须重建 ELF + vkey 并重新部署 tz Game 合约配置(见 §8),否则链上 `prove` 会因 vkey 不匹配 revert。
- 跨进程版本:op-succinct 编译 ELF 用的 tradezone(x2)git rev 与 Claim Tree Core 版本必须与 WB 端一致;bump 后需重 build ELF + 重 deploy。
- Guest 是 no-std zkVM 目标:Claim Tree Core 依赖必须 no-std 兼容;host 侧共享库(网络/tx)不进 guest。
- 单 Task 单 branch 单 MR;每个新 commit 与 MR 标题以 `[Oli] ` 开头;不 merge/deploy/release/force-push,不直接推 target 分支。
- `docs/superpowers/` 的 Git 处理遵循仓库规则与开发者选择(本 Flow 不强制策略);本 Spec 与 lark-review-doc.md 随 CoW 前向传递。

---

## 13. 外部依赖 / Open Items（跟踪,非本 Task 交付物）

1. TradeZone Claim Tree Core 在 tradezone `feature/witness-builder-withdraw-v1` 的可依赖 crate 形态(no-std 兼容)。
2. WB v2 端点真实 route 名与 wire(以真实代码核验并对齐客户端)。
3. X Layer Withdraw 挑战合约最终 ABI 与状态枚举(替换 mock)。
4. 冻结 `claim-tree-v1.json` + `tradezone-claim-tree-reference-v1.zip` 引入 `fault-proof` 测试资源。

---

## 14. 验收标准（Success Criteria）

1. Proposer 基于 WB CheckpointV2 + boundary witness 生成完整四字段 claim proof,并按协议创建/推进 L1 Game。
2. SP1 Guest 只依赖起点 boundary 与 canonical replay,经 TradeZone Claim Tree Core 自算 post roots。
3. L1 Challenger 逐字段验证 canonical checkpoint(含 chainId),临时 WB 故障不造成永久漏检。
4. Defender 作为独立服务,在 response deadline 内选 covering finalized root、取得并本地验证历史 proof、提交 `proveChallenge`,并正确处理重启、重复事件与竞态(对 mock 合约 + 冻结 fixture 验证)。
5. op-succinct 内不存在重复的 leaf/tree/root 算法实现;核心计算来自 TradeZone Claim Tree Core。
6. 冻结 fixture 与全部新增/回归测试通过;代码具备明确配置、metrics、日志与告警。
7. MR 可编译、可过测试(fixture + mock);ELF/vkey/部署影响面在 §8 明确记录并交由后续阶段/运维执行。
