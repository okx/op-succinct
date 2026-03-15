# OP Succinct Proposer 工作流程详解

本文档详细解释 OP Succinct Proposer 的完整工作流程，从顶层循环到最底层的接口调用。

## 目录

1. [顶层架构](#顶层架构)
2. [主循环流程](#主循环流程)
3. [状态同步 (sync_state)](#状态同步-sync_state)
   - [1. sync_games() - 同步游戏列表](#1-sync_games---同步游戏列表)
   - [2. sync_anchor_game() - 同步锚点游戏](#2-sync_anchor_game---同步锚点游戏)
   - [3. compute_canonical_head() - 计算规范头](#3-compute_canonical_head---计算规范头)
4. [handle_completed_tasks() - 处理已完成任务](#4-handle_completed_tasks---处理已完成任务)
5. [spawn_pending_operations() - 生成待处理操作](#5-spawn_pending_operations---生成待处理操作)
6. [游戏创建流程](#6-游戏创建流程)
7. [游戏证明流程](#7-游戏证明流程)
8. [Host 和 Kona 调用流程](#8-host-和-kona-调用流程)
9. [游戏解析流程](#9-游戏解析流程)
10. [底层接口调用](#10-底层接口调用)

---

## 顶层架构

### 主入口

```rust
// fault-proof/bin/proposer.rs
pub async fn main() -> Result<()> {
    // 1. 初始化配置
    let proposer_config = ProposerConfig::from_env()?;
    let proposer_signer = SignerLock::from_env().await?;
    
    // 2. 创建 L1/L2 Provider
    let l1_provider = ProviderBuilder::new().connect_http(L1_RPC);
    let factory = DisputeGameFactory::new(FACTORY_ADDRESS, l1_provider);
    
    // 3. 创建数据获取器 (Fetcher)
    let fetcher = OPSuccinctDataFetcher::new_with_rollup_config().await?;
    
    // 4. 初始化 Host (封装 Kona)
    let host = initialize_host(Arc::new(fetcher.clone()));
    
    // 5. 创建 Proposer 实例
    let proposer = Arc::new(
        OPSuccinctProposer::new(proposer_config, proposer_signer, factory, fetcher, host)
            .await?
    );
    
    // 6. 启动主循环
    proposer.run().await?;
}
```

### 核心组件

- **ProposerConfig**: 配置信息（RPC地址、证明策略等）
- **SignerLock**: 签名器（用于发送交易）
- **DisputeGameFactory**: L1合约接口（创建和管理游戏）
- **OPSuccinctDataFetcher**: 数据获取器（从L1/L2获取数据）
- **OPSuccinctHost**: Host封装（封装Kona的调用）
- **SP1Prover**: SP1证明生成器（网络或本地）

---

## 主循环流程

### run() 方法

```rust
// fault-proof/src/proposer.rs:296-325
pub async fn run(self: Arc<Self>) -> Result<()> {
    tracing::info!("OP Succinct Proposer running...");
    let mut interval = time::interval(Duration::from_secs(self.config.fetch_interval));

    // 启动指标收集任务
    self.spawn_metrics_collector();

    loop {
        interval.tick().await;  // 等待配置的间隔时间（默认30秒）

        // 步骤1: 同步状态
        if let Err(e) = self.sync_state().await {
            tracing::warn!("Failed to sync proposer state: {:?}", e);
            continue
        }

        // 步骤2: 处理已完成的任务
        if let Err(e) = self.handle_completed_tasks().await {
            tracing::warn!("Failed to handle completed tasks: {:?}", e);
        }

        // 步骤3: 生成新的待处理操作
        if let Err(e) = self.spawn_pending_operations().await {
            tracing::warn!("Failed to spawn pending operations: {:?}", e);
        }

        // 步骤4: 记录任务统计
        self.log_task_stats().await;
    }
}
```

### 循环步骤说明

1. **sync_state()**: 同步链上状态，更新本地缓存
2. **handle_completed_tasks()**: 清理已完成的任务
3. **spawn_pending_operations()**: 生成新的任务（创建游戏、证明游戏等）
4. **log_task_stats()**: 记录任务统计信息

---

## 状态同步 (sync_state)

### 功能概述

同步 proposer 的缓存状态与链上状态，确保本地视图与链上一致。

### 调用链

```
sync_state()
├── sync_games()          // 同步游戏列表
├── sync_anchor_game()    // 同步锚点游戏
└── compute_canonical_head()  // 计算规范头
```

---

## 1. sync_games() - 同步游戏列表

### 1.1 功能概述

从 Factory 合约获取新创建的游戏，更新本地缓存。这是状态同步的核心步骤，包括：
- 加载新游戏
- 同步所有缓存游戏的状态
- 清理无效游戏

### 1.2 详细流程

```rust
// fault-proof/src/proposer.rs:361-628
pub async fn sync_games(&self) -> Result<()> {
    // 步骤1: 加载新游戏
    // 步骤2: 同步所有缓存游戏的状态
    // 步骤3: 清理无效游戏
}
```

### 1.3 步骤1: 加载新游戏

#### 1.3.1 获取最新游戏索引

```rust
let latest_index = if let Some(index) = self.factory.fetch_latest_game_index().await? {
    Cursor::from(index)
} else {
    return Ok(());
};
```

**调用的接口**:
- `factory.fetch_latest_game_index()` → `DisputeGameFactory.gameCount()`

#### 1.3.2 获取锚点游戏

```rust
let anchor_game = self.factory.get_anchor_game(self.config.game_type).await?;
let anchor_address = anchor_game.address();
```

**调用的接口**:
- `factory.get_anchor_game()` → `DisputeGameFactory.anchorGame()`

#### 1.3.3 确定起始游标

```rust
let cursor = {
    let state = self.state.read().await;
    let current_cursor = state.cursor.clone();
    
    // 如果工厂合约被重置，重置游标
    if latest_index < current_cursor {
        Cursor::none()
    } else {
        current_cursor
    }
};
```

#### 1.3.4 从最新索引向后遍历，获取新游戏

```rust
let mut index = latest_index.clone();
let mut anchor_deadline: Option<u64> = None;
let mut invalid_game_ids = Vec::new();

loop {
    if index == cursor {
        break;
    }
    
    let i = index.index().expect("must have an index here");
    let fetch_result = self.fetch_game(i).await?;
    
    match fetch_result {
        GameFetchResult::ValidGame { game_address, deadline } => {
            // 记录锚点游戏的deadline
            if &game_address == anchor_address {
                anchor_deadline = Some(deadline);
            }
            
            // 检查deadline lag约束
            if let Some(anchor_d) = anchor_deadline {
                if anchor_d.abs_diff(deadline) > MAX_GAME_DEADLINE_LAG {
                    break;  // 超过lag限制，停止获取
                }
            }
        }
        GameFetchResult::UnsupportedType { game_address } => {
            // 如果锚点游戏类型不支持，停止获取
            if &game_address == anchor_address {
                break
            }
        }
        GameFetchResult::InvalidGame { index } => {
            invalid_game_ids.push(index);
        }
        GameFetchResult::AlreadyExists => {}
    }
    
    index.step_back();
}
```

**调用的接口**:
- `self.fetch_game(i)` → 内部调用：
  - `factory.gameAtIndex(index)` → `DisputeGameFactory.gameAtIndex(index)`
  - `l2_provider.compute_output_root_at_block()` → 见下文

#### 1.3.5 fetch_game() 内部实现

`fetch_game()` 方法会：
1. 从 Factory 合约获取游戏地址
2. 验证游戏类型是否正确
3. 计算游戏的输出根并验证
4. 返回游戏信息

**调用的接口**:
- `factory.gameAtIndex(index)` → `DisputeGameFactory.gameAtIndex(index)`
- `contract.gameType()` → `OPSuccinctFaultDisputeGame.gameType()`
- `l2_provider.compute_output_root_at_block()` → 见下文

#### 1.3.6 compute_output_root_at_block() - 计算输出根

```rust
// fault-proof/src/lib.rs:80-101
async fn compute_output_root_at_block(&self, l2_block_number: U256) -> Result<FixedBytes<32>> {
    // 1.3.6.1 获取L2区块
    let l2_block = self
        .get_l2_block_by_number(BlockNumberOrTag::Number(l2_block_number.to::<u64>()))
        .await?;
    
    // 1.3.6.2 提取状态根和区块哈希
    let l2_state_root = l2_block.header.state_root;
    let l2_claim_hash = l2_block.header.hash;
    
    // 1.3.6.3 获取L2ToL1MessagePasser合约的存储根
    let l2_storage_root = self
        .get_l2_storage_root(
            address!("0x4200000000000000000000000000000000000016"),  // L2ToL1MessagePasser
            BlockNumberOrTag::Number(l2_block_number.to::<u64>()),
        )
        .await?;
    
    // 1.3.6.4 编码并计算哈希
    let l2_claim_encoded = L2Output {
        zero: 0,
        l2_state_root: l2_state_root.0.into(),
        l2_storage_hash: l2_storage_root.0.into(),
        l2_claim_hash: l2_claim_hash.0.into(),
    };
    let l2_output_root = keccak256(l2_claim_encoded.abi_encode());
    
    Ok(l2_output_root)
}
```

**调用的接口**:
- `l2_provider.get_block_by_number(block_number)` → `eth_getBlockByNumber(block_number, false)`
- `l2_provider.get_proof(address, [])` → `eth_getProof(address, [], block_number)`

#### 1.3.7 更新游标并移除无效游戏

```rust
{
    let mut state = self.state.write().await;
    state.cursor = latest_index;
}

if !invalid_game_ids.is_empty() {
    let mut state = self.state.write().await;
    for idx in invalid_game_ids {
        state.remove_subtree(idx);
    }
}
```

### 1.4 步骤2: 同步所有缓存游戏的状态

#### 1.4.1 获取当前时间戳

```rust
let now_ts = self
    .l1_provider
    .get_block_by_number(BlockNumberOrTag::Latest)
    .await?
    .context("Failed to fetch latest L1 block timestamp")?
    .header
    .timestamp;
```

**调用的接口**:
- `l1_provider.get_block_by_number(BlockNumberOrTag::Latest)` → `eth_getBlockByNumber("latest", false)`

#### 1.4.2 遍历所有缓存游戏，获取链上状态

```rust
for (index, game_address) in games {
    let contract = OPSuccinctFaultDisputeGame::new(game_address, self.l1_provider.clone());
    let claim_data = contract.claimData().call().await?;
    let status = contract.status().call().await?;
    let deadline = U256::from(claim_data.deadline).to::<u64>();
    let parent_index = claim_data.parentIndex;
    
    let is_finalized =
        self.factory.is_game_finalized(self.config.game_type, game_address).await?;
    
    // 根据状态决定操作
}
```

**调用的接口**:
- `contract.claimData()` → `OPSuccinctFaultDisputeGame.claimData()`
- `contract.status()` → `OPSuccinctFaultDisputeGame.status()`
- `factory.is_game_finalized()` → `DisputeGameFactory.isGameFinalized()`

#### 1.4.3 处理 IN_PROGRESS 状态的游戏

```rust
match status {
    GameStatus::IN_PROGRESS => {
        let game_type = contract.gameType().call().await?;
        let parent_resolved =
            is_parent_resolved(parent_index, self.factory.as_ref()).await?;
        let is_game_over = match claim_data.status {
            ProposalStatus::Unchallenged => now_ts >= deadline,
            ProposalStatus::UnchallengedAndValidProofProvided |
            ProposalStatus::ChallengedAndValidProofProvided => true,
            _ => false,
        };
        let creator = contract.gameCreator().call().await?;
        let is_own_game = match claim_data.status {
            ProposalStatus::Unchallenged => creator == signer_address,
            ProposalStatus::UnchallengedAndValidProofProvided |
            ProposalStatus::ChallengedAndValidProofProvided => {
                creator == signer_address || claim_data.prover == signer_address
            }
            _ => false,
        };
        
        let should_attempt_to_resolve = game_type == self.config.game_type &&
            parent_resolved &&
            is_game_over &&
            is_own_game;
        
        // 更新游戏状态
    }
}
```

**调用的接口**:
- `contract.gameType()` → `OPSuccinctFaultDisputeGame.gameType()`
- `contract.gameCreator()` → `OPSuccinctFaultDisputeGame.gameCreator()`
- `is_parent_resolved()` → 内部调用 `factory.is_game_finalized()`

#### 1.4.4 处理 DEFENDER_WINS 状态的游戏

```rust
GameStatus::DEFENDER_WINS => {
    let credit = contract.credit(signer_address).call().await?;
    
    if is_finalized && credit == U256::ZERO {
        // 检查是否应该移除游戏
        // - 规范头游戏保留
        // - 锚点游戏保留
        // - 其他游戏移除
        let should_remove = /* ... */;
        
        if should_remove {
            actions.push(GameSyncAction::Remove(index));
        }
    } else {
        // 标记可以提取保证金
        let should_attempt_to_claim_bond = is_finalized && credit > U256::ZERO;
    }
}
```

**调用的接口**:
- `contract.credit(address)` → `OPSuccinctFaultDisputeGame.credit(address)`

#### 1.4.5 处理 CHALLENGER_WINS 状态的游戏

```rust
GameStatus::CHALLENGER_WINS => {
    // 移除整个子树
    actions.push(GameSyncAction::RemoveSubtree(index));
}
```

#### 1.4.6 应用所有状态更新

```rust
let mut state = self.state.write().await;
for action in actions {
    match action {
        GameSyncAction::Update { ... } => {
            // 更新游戏状态
        }
        GameSyncAction::Remove(index) => {
            state.games.remove(&index);
        }
        GameSyncAction::RemoveSubtree(index) => {
            state.remove_subtree(index);
        }
    }
}
```

### 1.5 步骤3: 清理无效游戏

在步骤1和步骤2中已经处理了无效游戏的移除：
- 步骤1中：移除无效游戏及其子树
- 步骤2中：移除已完成的游戏（如果保证金已提取）和被挑战者获胜的游戏及其子树

---

## 2. sync_anchor_game() - 同步锚点游戏

### 2.1 功能概述

从 Factory 合约获取锚点游戏，更新本地缓存中的锚点游戏引用。

### 2.2 详细流程

```rust
// fault-proof/src/proposer.rs:631-650
async fn sync_anchor_game(&self) -> Result<()> {
    // 2.2.1 获取锚点游戏
    let anchor_game = self.factory.get_anchor_game(self.config.game_type).await?;
    let anchor_address = anchor_game.address();
    
    // 2.2.2 从缓存中查找锚点游戏
    let mut state = self.state.write().await;
    if let Some(game) = state.games.iter().find(|(_, g)| g.address == anchor_address) {
        state.anchor_game = Some(game.clone());
    }
    
    Ok(())
}
```

### 2.3 调用的合约接口

- `factory.get_anchor_game()` → `DisputeGameFactory.anchorGame()`

---

## 3. compute_canonical_head() - 计算规范头

### 3.1 功能概述

计算规范头游戏（L2区块号最高的游戏）。规范头用于确定下一个要提议的L2区块号。

### 3.2 详细流程

```rust
// fault-proof/src/proposer.rs:653-698
async fn compute_canonical_head(&self) {
    let mut state = self.state.write().await;
    
    // 3.2.1 如果有锚点游戏，只考虑锚点的后代
    let canonical_head = if let Some(anchor_game) = state.anchor_game.as_ref() {
        let reachable = state.descendants_of(anchor_game.index);
        state.games.values()
            .filter(|game| reachable.contains(&game.index))
            .max_by_key(|game| game.l2_block)  // 找到L2区块号最高的
    } else {
        // 3.2.2 如果没有锚点游戏，从所有游戏中找
        state.games.values()
            .max_by_key(|game| game.l2_block)
    };
    
    // 3.2.3 更新规范头
    state.canonical_head_index = canonical_head.map(|g| g.index);
    state.canonical_head_l2_block = canonical_head.map(|g| g.l2_block);
}
```

### 3.3 说明

这是一个纯本地计算操作，不涉及任何链上调用。它基于已经缓存的游戏数据，找到L2区块号最高的游戏作为规范头。

---

## 4. handle_completed_tasks() - 处理已完成任务

### 4.1 功能概述

检查并清理已完成的任务，处理任务结果（成功或失败）。

### 4.2 详细流程

```rust
// fault-proof/src/proposer.rs:1242-1274
async fn handle_completed_tasks(&self) -> Result<()> {
    let mut tasks = self.tasks.lock().await;
    let mut completed = Vec::new();
    
    // 4.2.1 查找已完成的任务
    for (id, (handle, _)) in tasks.iter() {
        if handle.is_finished() {
            completed.push(*id);
        }
    }
    
    // 4.2.2 处理已完成的任务
    for id in completed {
        if let Some((handle, info)) = tasks.remove(&id) {
            match handle.await {
                Ok(Ok(())) => {
                    tracing::info!("Task {:?} completed successfully", info);
                }
                Ok(Err(e)) => {
                    tracing::warn!("Task {:?} failed: {:?}", info, e);
                    self.handle_task_failure(&info, e).await?;
                }
                Err(panic) => {
                    tracing::error!("Task {:?} panicked: {:?}", info, panic);
                }
            }
        }
    }
    
    Ok(())
}
```

### 4.3 任务类型

- **GameCreation**: 游戏创建任务
- **GameProving**: 游戏证明任务
- **GameResolution**: 游戏解析任务
- **BondClaim**: 保证金提取任务

---

## 5. spawn_pending_operations() - 生成待处理操作

### 5.1 功能概述

检查是否需要执行新操作，并生成相应的任务。

### 5.2 详细流程

```rust
// fault-proof/src/proposer.rs:1295-1339
async fn spawn_pending_operations(&self) -> Result<()> {
    // 5.2.1 检查是否需要创建新游戏
    if !self.has_active_task_of_type(&TaskInfo::GameCreation { ... }).await {
        match self.spawn_game_creation_task().await {
            Ok(true) => tracing::info!("Successfully spawned game creation task"),
            Ok(false) => tracing::debug!("No game creation needed"),
            Err(e) => tracing::warn!("Failed to spawn game creation task: {:?}", e),
        }
    }
    
    // 5.2.2 检查是否需要防御游戏（被挑战的游戏）
    match self.spawn_game_defense_tasks().await {
        Ok(true) => tracing::info!("Successfully spawned game defense tasks"),
        Ok(false) => tracing::debug!("No games need defense"),
        Err(e) => tracing::warn!("Failed to spawn game defense tasks: {:?}", e),
    }
    
    // 5.2.3 检查是否需要解析游戏
    if !self.has_active_task_of_type(&TaskInfo::GameResolution).await {
        self.spawn_game_resolution_task().await?;
    }
    
    // 5.2.4 检查是否需要提取保证金
    if !self.has_active_task_of_type(&TaskInfo::BondClaim).await {
        self.spawn_bond_claim_task().await?;
    }
    
    Ok(())
}
```

---

## 6. 游戏创建流程

### 6.1 spawn_game_creation_task() - 生成游戏创建任务

#### 6.1.1 功能
检查是否需要创建新游戏，如果需要则生成任务。

#### 6.1.2 详细流程

```rust
// fault-proof/src/proposer.rs:1390-1423
async fn spawn_game_creation_task(&self) -> Result<bool> {
    // 6.1.2.1 检查是否应该创建游戏
    let (should_create, next_l2_block_number, parent_game_index) = 
        self.should_create_game().await?;
    
    if !should_create {
        return Ok(false);
    }
    
    // 6.1.2.2 生成异步任务
    let proposer = self.clone();
    let task_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
    
    let handle = tokio::spawn(async move {
        proposer.handle_game_creation(next_l2_block_number, parent_game_index).await?;
        ProposerGauge::GamesCreated.increment(1.0);
        Ok(())
    });
    
    // 6.1.2.3 记录任务
    self.tasks.lock().await.insert(task_id, (handle, task_info));
    
    Ok(true)
}
```

### 6.2 should_create_game() - 判断是否应该创建游戏

#### 6.2.1 功能
检查条件，判断是否应该创建新游戏。

#### 6.2.2 详细流程

```rust
// fault-proof/src/proposer.rs:1438-1580
async fn should_create_game(&self) -> Result<(bool, U256, u32)> {
    // 6.2.2.1 Fast Finality 模式检查
    if self.config.fast_finality_mode {
        let active_proving = self.count_active_proving_tasks().await;
        
        // 如果证明任务未达到上限，先恢复未证明的游戏
        if active_proving < self.config.fast_finality_proving_limit {
            // 查找未证明的游戏并恢复证明任务
            for (index, game_address) in unproven_games {
                self.spawn_game_proving_task(game_address, false).await?;
            }
        }
        
        // 如果证明容量已满，不创建新游戏
        if active_proving >= self.config.fast_finality_proving_limit {
            return Ok((false, U256::ZERO, u32::MAX));
        }
    }
    
    // 6.2.2.2 获取规范头信息
    let (canonical_head_l2_block, parent_game_index) = {
        let state = self.state.read().await;
        (state.canonical_head_l2_block, state.canonical_head_index)
    };
    
    // 6.2.2.3 计算下一个要提议的L2区块号
    let next_l2_block_number = 
        canonical_head_l2_block + U256::from(self.config.proposal_interval_in_blocks);
    
    // 6.2.2.4 检查是否有足够的finalized L2区块
    let finalized_l2_head = self.host
        .get_finalized_l2_block_number(&self.fetcher, canonical_head_l2_block.to::<u64>())
        .await?;
    
    let should_create = finalized_l2_head
        .map(|finalized| U256::from(finalized) >= next_l2_block_number)
        .unwrap_or(false);
    
    Ok((should_create, next_l2_block_number, parent_game_index))
}
```

#### 6.2.3 调用的接口

**Host 接口**:
- `host.get_finalized_l2_block_number()` → 见下文

**L2 RPC 调用**:
- `fetcher.get_l2_header(BlockId::finalized())` → `eth_getBlockByNumber("finalized")`

### 6.3 handle_game_creation() - 处理游戏创建

#### 6.3.1 功能
实际创建游戏并提交到链上。

#### 6.3.2 详细流程

```rust
// fault-proof/src/proposer.rs:1130-1175
pub async fn handle_game_creation(
    &self,
    mut next_l2_block_number_for_proposal: U256,
    parent_game_index: u32,
) -> Result<()> {
    // 6.3.2.1 计算输出根
    let mut output_root = self
        .l2_provider
        .compute_output_root_at_block(next_l2_block_number_for_proposal)
        .await?;
    
    // 6.3.2.2 检查游戏是否已存在
    let mut maybe_existing_game = self
        .factory
        .games(self.config.game_type, output_root, extra_data.clone().into())
        .call()
        .await?
        .proxy;
    
    // 6.3.2.3 如果游戏已存在，递增L2区块号
    while maybe_existing_game != Address::ZERO {
        next_l2_block_number_for_proposal += U256::from(1);
        output_root = self
            .l2_provider
            .compute_output_root_at_block(next_l2_block_number_for_proposal)
            .await?;
        // 重新检查...
    }
    
    // 6.3.2.4 创建游戏
    self.create_game(output_root, extra_data).await?;
    
    Ok(())
}
```

#### 6.3.3 调用的接口

- `l2_provider.compute_output_root_at_block()` → 见 1.3.6
- `factory.games()` → `DisputeGameFactory.games()`
- `create_game()` → 见 6.4

### 6.4 create_game() - 创建游戏

#### 6.4.1 功能
调用 Factory 合约创建新游戏。

#### 6.4.2 详细流程

```rust
// fault-proof/src/proposer.rs:878-924
pub async fn create_game(
    &self,
    output_root: FixedBytes<32>,
    extra_data: Vec<u8>,
) -> Result<Address> {
    // 6.4.2.1 构建交易请求
    let transaction_request = self
        .factory
        .create(self.config.game_type, output_root, extra_data.into())
        .value(self.init_bond)  // 附加初始保证金
        .into_transaction_request();
    
    // 6.4.2.2 发送交易
    let receipt = self
        .signer
        .send_transaction_request(self.config.l1_rpc.clone(), transaction_request)
        .await?;
    
    // 6.4.2.3 从交易日志中提取游戏地址
    let game_address = receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| {
            DisputeGameCreated::decode_log(&log.inner)
                .ok()
                .map(|event| event.disputeProxy)
        })
        .context("Could not find DisputeGameCreated event")?;
    
    // 6.4.2.4 Fast Finality 模式：立即生成证明任务
    if self.config.fast_finality_mode {
        self.spawn_game_proving_task(game_address, false).await?;
    }
    
    Ok(game_address)
}
```

#### 6.4.3 调用的合约接口

**L1 合约调用**:
- `factory.create(game_type, output_root, extra_data)` → `DisputeGameFactory.create(gameType, rootClaim, extraData)`
- `factory.gameCount()` → `DisputeGameFactory.gameCount()`

**L1 RPC 调用**:
- `signer.send_transaction_request()` → `eth_sendTransaction()`
- 等待交易确认 → `eth_getTransactionReceipt()`

---

## 7. 游戏证明流程

### 7.1 spawn_game_proving_task() - 生成游戏证明任务

#### 7.1.1 功能
为指定游戏生成证明任务。

#### 7.1.2 详细流程

```rust
// fault-proof/src/proposer.rs:1642-1716
async fn spawn_game_proving_task(&self, game_address: Address, is_defense: bool) -> Result<()> {
    // 7.1.2.1 获取游戏的区块范围
    let game = OPSuccinctFaultDisputeGame::new(game_address, self.l1_provider.clone());
    let starting_l2_block_number = game.startingBlockNumber().call().await?;
    let l2_block_number = game.l2BlockNumber().call().await?;
    let start_block = starting_l2_block_number.to::<u64>();
    let end_block = l2_block_number.to::<u64>();
    
    // 7.1.2.2 生成异步任务
    let handle = if proposer.config.mock_mode {
        // Mock模式：使用阻塞任务
        tokio::task::spawn_blocking(move || {
            // ...
        })
    } else {
        // 网络模式：使用异步任务
        tokio::spawn(async move {
            let (tx_hash, cycles, gas) = 
                proposer.prove_game(game_address, start_block, end_block).await?;
            // 记录指标...
            Ok(())
        })
    };
    
    // 7.1.2.3 记录任务
    self.tasks.lock().await.insert(task_id, (handle, task_info));
    
    Ok(())
}
```

#### 7.1.3 调用的合约接口

- `game.startingBlockNumber()` → `OPSuccinctFaultDisputeGame.startingBlockNumber()`
- `game.l2BlockNumber()` → `OPSuccinctFaultDisputeGame.l2BlockNumber()`

### 7.2 prove_game() - 生成游戏证明

#### 7.2.1 功能
为游戏生成ZK证明并提交到链上。

#### 7.2.2 详细流程

```rust
// fault-proof/src/proposer.rs:709-872
pub async fn prove_game(
    &self,
    game_address: Address,
    start_block: u64,
    end_block: u64,
) -> Result<(TxHash, u64, u64)> {
    // 7.2.2.1 创建数据获取器
    let fetcher = OPSuccinctDataFetcher::new_with_rollup_config().await?;
    
    // 7.2.2.2 获取游戏的L1 head hash
    let game = OPSuccinctFaultDisputeGame::new(game_address, self.l1_provider.clone());
    let l1_head_hash = game.l1Head().call().await?.0;
    
    // 7.2.2.3 获取 Host 参数（准备Kona调用）
    let host_args = self
        .host
        .fetch(start_block, end_block, Some(l1_head_hash.into()), ...)
        .await?;
    
    // 7.2.2.4 运行 Host 和 Client（调用Kona执行状态转换）
    let witness_data = self.host.run(&host_args).await?;
    
    // 7.2.2.5 生成 SP1 输入
    let sp1_stdin = self.host.witness_generator().get_sp1_stdin(witness_data)?;
    
    // 7.2.2.6 生成 Range Proof
    let range_proof = if self.config.mock_mode {
        // Mock模式：本地执行，生成mock proof
        let (public_values, report) = self
            .prover
            .network_prover
            .execute(get_range_elf_embedded(), &sp1_stdin)
            .run()?;
        SP1ProofWithPublicValues::create_mock_proof(...)
    } else {
        // 网络模式：调用SP1网络生成真实proof
        self.prover
            .network_prover
            .prove(&self.prover.range_pk, &sp1_stdin)
            .strategy(self.config.range_proof_strategy)
            .timeout(...)
            .run_async()
            .await?
    };
    
    // 7.2.2.7 准备 Aggregation Proof 输入
    let headers = fetcher
        .get_header_preimages(&vec![boot_info.clone()], boot_info.l1Head)
        .await?;
    
    let sp1_stdin = get_agg_proof_stdin(
        vec![proof],
        vec![boot_info],
        headers,
        &self.prover.range_vk,
        boot_info.l1Head,
        self.signer.address(),
    )?;
    
    // 7.2.2.8 生成 Aggregation Proof
    let agg_proof = if self.config.mock_mode {
        // Mock模式...
    } else {
        // 网络模式：调用SP1网络
        self.prover
            .network_prover
            .prove(&self.prover.agg_pk, &sp1_stdin)
            .mode(self.prover.agg_mode)
            .strategy(self.config.agg_proof_strategy)
            .run_async()
            .await?
    };
    
    // 7.2.2.9 提交证明到链上
    let transaction_request = game.prove(agg_proof.bytes().into()).into_transaction_request();
    let receipt = self
        .signer
        .send_transaction_request(self.config.l1_rpc.clone(), transaction_request)
        .await?;
    
    Ok((receipt.transaction_hash, total_instruction_cycles, total_sp1_gas))
}
```

#### 7.2.3 调用的合约接口

- `game.l1Head()` → `OPSuccinctFaultDisputeGame.l1Head()`
- `game.prove(proof)` → `OPSuccinctFaultDisputeGame.prove(proof)`

#### 7.2.4 调用的 SP1 接口

**Mock 模式**:
- `network_prover.execute(elf, stdin)` → 本地执行SP1程序
- `SP1ProofWithPublicValues::create_mock_proof()` → 创建mock proof

**网络模式**:
- `network_prover.prove(proving_key, stdin)` → 调用SP1网络生成proof
  - 内部调用: `ProverClient.prove()` → SP1 Prover Network API

---

## 8. Host 和 Kona 调用流程

### 8.1 host.fetch() - 获取 Host 参数

#### 8.1.1 功能
准备 Kona Host 所需的参数。

#### 8.1.2 详细流程

```rust
// utils/ethereum/host/src/host.rs:27-44
async fn fetch(
    &self,
    l2_start_block: u64,
    l2_end_block: u64,
    l1_head_hash: Option<B256>,
    safe_db_fallback: bool,
) -> Result<SingleChainHost> {
    // 8.1.2.1 计算或使用提供的L1 head hash
    let l1_head_hash = match l1_head_hash {
        Some(hash) => hash,
        None => {
            self.calculate_safe_l1_head(&self.fetcher, l2_end_block, safe_db_fallback).await?
        }
    };
    
    // 8.1.2.2 获取 Host 参数
    let host = self.fetcher.get_host_args(l2_start_block, l2_end_block, l1_head_hash).await?;
    
    Ok(host)
}
```

### 8.2 calculate_safe_l1_head() - 计算安全的L1 Head

#### 8.2.1 功能
计算一个安全的L1区块哈希，用于派生L2区块。

#### 8.2.2 详细流程

```rust
// utils/ethereum/host/src/host.rs:59-78
async fn calculate_safe_l1_head(
    &self,
    fetcher: &OPSuccinctDataFetcher,
    l2_end_block: u64,
    safe_db_fallback: bool,
) -> Result<B256> {
    // 8.2.2.1 获取包含L2数据的L1区块
    let (_, l1_head_number) = fetcher.get_l1_head(l2_end_block, safe_db_fallback).await?;
    
    // 8.2.2.2 添加20个区块的缓冲
    let l1_head_number = l1_head_number + 20;
    
    // 8.2.2.3 确保不超过finalized L1区块
    let finalized_l1_header = fetcher.get_l1_header(BlockId::finalized()).await?;
    let safe_l1_head_number = std::cmp::min(l1_head_number, finalized_l1_header.number);
    
    // 8.2.2.4 获取L1区块哈希
    Ok(fetcher.get_l1_header(safe_l1_head_number.into()).await?.hash_slow())
}
```

#### 8.2.3 调用的接口

**L2 Node RPC 调用**:
- `fetcher.get_safe_l1_block_for_l2_block(l2_end_block)` → 
  - `optimism_outputAtBlock(l2_end_block)` → 获取L2区块的L1 origin
  - `optimism_safeHeadAtL1Block(l1_block)` → 二分查找第一个L1区块，其L2 safe head >= l2_end_block

**L1 RPC 调用**:
- `fetcher.get_l1_header(BlockId::finalized())` → `eth_getBlockByNumber("finalized", false)`
- `fetcher.get_l1_header(block_number)` → `eth_getBlockByNumber(block_number, false)`

### 8.3 get_host_args() - 获取 Host 参数

#### 8.3.1 功能
构建 Kona SingleChainHost 所需的完整参数。

#### 8.3.2 详细流程

```rust
// utils/host/src/fetcher.rs:674-762
pub async fn get_host_args(
    &self,
    l2_start_block: u64,
    l2_end_block: u64,
    l1_head_hash: B256,
) -> Result<SingleChainHost> {
    // 8.3.2.1 获取L2起始区块的输出根（agreed state）
    let l2_output_block = 
        self.l2_provider.get_block_by_number(l2_start_block.into()).await?;
    let l2_output_state_root = l2_output_block.header.state_root;
    let agreed_l2_head_hash = l2_output_block.header.hash;
    let l2_output_storage_hash = self.l2_provider
        .get_proof(Address::from_str("0x4200000000000000000000000000000000000016")?, Vec::new())
        .block_id(l2_start_block.into())
        .await?
        .storage_hash;
    
    let agreed_l2_output_root = keccak256(L2Output {
        zero: 0,
        l2_state_root: l2_output_state_root.0.into(),
        l2_storage_hash: l2_output_storage_hash.0.into(),
        l2_claim_hash: agreed_l2_head_hash.0.into(),
    }.abi_encode());
    
    // 8.3.2.2 获取L2结束区块的输出根（claimed state）
    let l2_claim_block = 
        self.l2_provider.get_block_by_number(l2_end_block.into()).await?;
    // ... 类似计算 ...
    let claimed_l2_output_root = keccak256(...);
    
    // 8.3.2.3 构建 SingleChainHost
    Ok(SingleChainHost {
        l1_head: l1_head_hash,
        agreed_l2_output_root,
        agreed_l2_head_hash,
        claimed_l2_output_root,
        claimed_l2_block_number: l2_end_block,
        l2_chain_id: None,
        l2_node_address: Some(self.rpc_config.l2_rpc.as_str().trim_end_matches('/').to_string()),
        l1_node_address: Some(self.rpc_config.l1_rpc.as_str().trim_end_matches('/').to_string()),
        l1_beacon_address: self.rpc_config.l1_beacon_rpc.as_ref().map(|a| a.as_str().to_string()),
        data_dir: None,
        native: false,
        server: true,
        rollup_config_path: self.rollup_config_path.clone(),
        l1_config_path: self.l1_config_path.clone(),
        enable_experimental_witness_endpoint: false,
    })
}
```

#### 8.3.3 调用的接口

**L2 RPC 调用**:
- `l2_provider.get_block_by_number(block_number)` → `eth_getBlockByNumber(block_number, false)`
- `l2_provider.get_proof(address, [])` → `eth_getProof(address, [], block_number)`

### 8.4 host.run() - 运行 Host 和 Client

#### 8.4.1 功能
启动 Kona Host Server 并运行 Client，执行状态转换。

#### 8.4.2 详细流程

```rust
// utils/host/src/host.rs:91-106
async fn run(
    &self,
    args: &Self::Args,
) -> Result<WitnessData> {
    // 8.4.2.1 创建双向通道（用于host和client通信）
    let preimage = BidirectionalChannel::new()?;
    let hint = BidirectionalChannel::new()?;
    
    // 8.4.2.2 启动 Kona Host Server（作为preimage oracle）
    let server_task = args.start_server(hint.host, preimage.host).await?;
    //    这里调用 SingleChainHost.start_server()
    //    Kona Host 作为服务器，提供preimage数据
    
    // 8.4.2.3 运行 Witness Generator（client端）
    let witness = self.witness_generator().run(preimage.client, hint.client).await?;
    //    这里调用 ETHDAWitnessGenerator.run()
    //    内部使用 ETHDAWitnessExecutor 执行状态转换
    
    // 8.4.2.4 终止服务器任务
    server_task.abort();
    
    Ok(witness)
}
```

### 8.5 WitnessGenerator.run() - 运行 Witness Generator

#### 8.5.1 功能
运行 Client 端程序，执行状态转换并收集 witness。

#### 8.5.2 详细流程

```rust
// utils/client/src/witness/executor.rs:114-152
async fn run<O, DP, P>(
    &self,
    boot: BootInfo,
    pipeline: DP,
    cursor: Arc<RwLock<PipelineCursor>>,
    l2_provider: OracleL2ChainProvider<O>,
) -> Result<BootInfo> {
    // 8.5.2.1 安装自定义加密提供器（用于KZG预编译）
    revm::precompile::install_crypto(CustomCrypto::default());
    
    // 8.5.2.2 创建 Kona Executor
    let executor = KonaExecutor::new(
        rollup_config.as_ref(),
        l2_provider.clone(),
        l2_provider,
        ZkvmOpEvmFactory::new(),
        None,
    );
    
    // 8.5.2.3 创建 Driver
    let mut driver = Driver::new(cursor, executor, pipeline);
    
    // 8.5.2.4 运行 derivation pipeline，执行状态转换
    let (safe_head, output_root) = advance_to_target(
        &mut driver,
        rollup_config.as_ref(),
        Some(boot.claimed_l2_block_number),
    ).await?;
    
    // 8.5.2.5 验证输出根
    if output_root != boot.claimed_l2_output_root {
        return Err(anyhow!("Output root mismatch"));
    }
    
    Ok(boot)
}
```

### 8.6 Kona Executor 执行流程

#### 8.6.1 Driver.advance_to_target() - 推进到目标区块

```rust
// utils/client/src/client.rs:advance_to_target()
async fn advance_to_target(
    driver: &mut Driver<...>,
    rollup_config: &RollupConfig,
    target_block: Option<u64>,
) -> Result<(L2BlockRef, OutputRoot)> {
    loop {
        // 8.6.1.1 从 L1 派生 L2 区块
        let attributes = driver.pipeline.advance().await?;
        
        // 8.6.1.2 执行 L2 区块（使用 Kona Executor）
        let outcome = driver.executor.execute_payload(attributes.clone()).await?;
        
        // 8.6.1.3 更新 safe head
        driver.pipeline.signal(Signal::UpdateSafeHead(outcome)).await?;
        
        // 8.6.1.4 检查是否到达目标
        if let Some(target) = target_block {
            if outcome.number >= target {
                break;
            }
        }
    }
    
    Ok((safe_head, output_root))
}
```

#### 8.6.2 KonaExecutor.execute_payload() - 执行 L2 区块

**Kona 内部调用**:
- `KonaExecutor.execute_payload()` → 执行 OP Stack 状态转换函数
  - 使用 `revm` 执行 EVM 交易
  - 处理 OP Stack 特定的预编译合约
  - 更新状态树

**数据获取（通过 Preimage Oracle）**:
- Client 通过 `BidirectionalChannel` 请求数据
- Host Server 从 L1/L2 RPC 获取数据并返回

---

## 9. 游戏解析流程

### 9.1 spawn_game_resolution_task() - 生成游戏解析任务

#### 9.1.1 功能
为可以解析的游戏生成解析任务。

#### 9.1.2 详细流程

```rust
// fault-proof/src/proposer.rs:1719-1729
async fn spawn_game_resolution_task(&self) -> Result<()> {
    let proposer = self.clone();
    let task_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
    
    let handle = tokio::spawn(async move {
        proposer.resolve_games().await
    });
    
    self.tasks.lock().await.insert(task_id, (handle, task_info));
    Ok(())
}
```

### 9.2 resolve_games() - 解析游戏

#### 9.2.1 功能
解析所有可以解析的游戏。

#### 9.2.2 详细流程

```rust
// fault-proof/src/proposer.rs:926-954
async fn resolve_games(&self) -> Result<()> {
    // 9.2.2.1 获取需要解析的游戏
    let candidates = {
        let state = self.state.read().await;
        state.games.values()
            .filter(|game| game.should_attempt_to_resolve)
            .cloned()
            .collect::<Vec<_>>()
    };
    
    // 9.2.2.2 为每个游戏提交解析交易
    for game in candidates {
        if let Err(error) = self.submit_resolution_transaction(&game).await {
            tracing::warn!("Failed to resolve game: {:?}", error);
            continue
        }
        
        ProposerGauge::GamesResolved.increment(1.0);
    }
    
    Ok(())
}
```

### 9.3 submit_resolution_transaction() - 提交解析交易

#### 9.3.1 功能
调用游戏合约的 `resolve()` 方法。

#### 9.3.2 详细流程

```rust
// fault-proof/src/proposer.rs:987-1004
pub async fn submit_resolution_transaction(&self, game: &Game) -> Result<()> {
    let contract = OPSuccinctFaultDisputeGame::new(game.address, self.l1_provider.clone());
    let transaction_request = contract.resolve().into_transaction_request();
    
    let receipt = self
        .signer
        .send_transaction_request(self.config.l1_rpc.clone(), transaction_request)
        .await?;
    
    tracing::info!("Game resolved successfully");
    Ok(())
}
```

#### 9.3.3 调用的合约接口

- `contract.resolve()` → `OPSuccinctFaultDisputeGame.resolve()`

#### 9.3.4 调用的 RPC 接口

- `signer.send_transaction_request()` → `eth_sendTransaction()`
- 等待交易确认 → `eth_getTransactionReceipt()`

---

## 10. 底层接口调用

### L1 合约接口调用

#### DisputeGameFactory 合约

| 方法 | 调用位置 | 说明 |
|------|---------|------|
| `gameCount()` | `sync_games()` | 获取游戏总数 |
| `gameAtIndex(index)` | `sync_games()` | 获取指定索引的游戏 |
| `anchorGame()` | `sync_anchor_game()` | 获取锚点游戏 |
| `create(gameType, rootClaim, extraData)` | `create_game()` | 创建新游戏 |
| `games(gameType, rootClaim, extraData)` | `handle_game_creation()` | 检查游戏是否存在 |
| `is_game_finalized(gameType, address)` | `sync_games()` | 检查游戏是否已finalized |

#### OPSuccinctFaultDisputeGame 合约

| 方法 | 调用位置 | 说明 |
|------|---------|------|
| `status()` | `sync_games()` | 获取游戏状态 |
| `claimData()` | `sync_games()` | 获取游戏声明数据 |
| `gameCreator()` | `sync_games()` | 获取游戏创建者 |
| `credit(address)` | `sync_games()` | 获取可提取的保证金 |
| `l1Head()` | `prove_game()` | 获取游戏的L1 head |
| `startingBlockNumber()` | `spawn_game_proving_task()` | 获取起始区块号 |
| `l2BlockNumber()` | `spawn_game_proving_task()` | 获取L2区块号 |
| `prove(proof)` | `prove_game()` | 提交证明 |
| `resolve()` | `submit_resolution_transaction()` | 解析游戏 |
| `claimCredit(address)` | `submit_bond_claim_transaction()` | 提取保证金 |

### L1 RPC 调用

| RPC 方法 | 调用位置 | 说明 |
|---------|---------|------|
| `eth_getBlockByNumber("finalized", false)` | `calculate_safe_l1_head()` | 获取finalized L1区块 |
| `eth_getBlockByNumber(block_number, false)` | `get_l1_header()` | 获取指定L1区块 |
| `eth_sendTransaction()` | `create_game()`, `prove_game()`, `resolve_games()` | 发送交易 |
| `eth_getTransactionReceipt()` | 各种交易提交后 | 获取交易收据 |

### L2 RPC 调用

#### 标准以太坊 RPC

| RPC 方法 | 调用位置 | 说明 |
|---------|---------|------|
| `eth_getBlockByNumber(block_number, false)` | `compute_output_root_at_block()`, `get_host_args()` | 获取L2区块 |
| `eth_getProof(address, [], block_number)` | `compute_output_root_at_block()`, `get_host_args()` | 获取存储证明 |
| `eth_getBlockByNumber("finalized", false)` | `get_finalized_l2_block_number()` | 获取finalized L2区块 |

#### Optimism 扩展 RPC

| RPC 方法 | 调用位置 | 说明 |
|---------|---------|------|
| `optimism_outputAtBlock(block_number)` | `get_safe_l1_block_for_l2_block()` | 获取L2区块的输出信息 |
| `optimism_safeHeadAtL1Block(l1_block)` | `get_safe_l1_block_for_l2_block()` | 获取指定L1区块对应的L2 safe head |

### Kona 接口调用

#### SingleChainHost.start_server()

**功能**: 启动 Kona Host Server，作为 preimage oracle。

**内部实现**:
- 启动 `kona-host` 二进制程序
- 配置 L1/L2 RPC 端点
- 配置 Rollup 配置路径
- 监听 preimage 请求

**通信方式**:
- 通过 `BidirectionalChannel` 与 Client 通信
- Client 请求 preimage（区块、交易、状态等）
- Host 从 RPC 获取数据并返回

#### KonaExecutor.execute_payload()

**功能**: 执行 L2 区块的状态转换。

**内部实现**:
- 使用 `revm` 执行 EVM 交易
- 处理 OP Stack 预编译合约
- 更新状态树
- 计算输出根

**数据获取**:
- 通过 `OracleL1ChainProvider` 从 L1 获取数据
- 通过 `OracleL2ChainProvider` 从 L2 获取数据
- 数据通过 preimage oracle（Host Server）提供

#### Driver.advance() - Derivation Pipeline

**功能**: 从 L1 派生 L2 区块。

**内部实现**:
- `OraclePipeline.advance()` → 从 L1 获取 batch 数据
- 解析 batch → 提取 L2 交易
- 构建 L2 区块属性
- 返回给 Executor 执行

### SP1 接口调用

#### SP1 Prover Network API

**Mock 模式**:
```rust
network_prover.execute(elf, stdin)
    .calculate_gas(true)
    .deferred_proof_verification(false)
    .run()
```
- 本地执行 SP1 程序
- 返回 public values 和执行报告
- 生成 mock proof

**网络模式**:
```rust
network_prover.prove(proving_key, stdin)
    .compressed()
    .skip_simulation(true)
    .strategy(FulfillmentStrategy::Auction)
    .timeout(Duration::from_secs(timeout))
    .min_auction_period(min_auction_period)
    .max_price_per_pgu(max_price_per_pgu)
    .cycle_limit(cycle_limit)
    .gas_limit(gas_limit)
    .whitelist(whitelist)
    .run_async()
    .await
```

**内部调用**:
- `ProverClient.prove()` → SP1 Prover Network HTTP API
- 提交证明请求到网络
- 等待网络中的 prover 生成证明
- 返回生成的 proof

#### SP1 程序

**Range Proof 程序** (`range-elf-embedded`):
- 执行 OP Stack 状态转换
- 验证从 `start_block` 到 `end_block` 的状态转换
- 生成 public values（包含输出根）

**Aggregation Proof 程序** (`AGGREGATION_ELF`):
- 聚合多个 range proof
- 验证 range proof 的正确性
- 生成最终的聚合证明

---

## 完整调用链示例

### 游戏创建和证明的完整流程

```
1. Proposer.run() 主循环
   ↓
2. sync_state()
   ├─ sync_games()
   │  ├─ factory.fetch_latest_game_index()
   │  │  └─ L1合约: DisputeGameFactory.gameCount()
   │  ├─ factory.get_anchor_game()
   │  │  └─ L1合约: DisputeGameFactory.anchorGame()
   │  └─ fetch_game(index)
   │     ├─ factory.gameAtIndex(index)
   │     │  └─ L1合约: DisputeGameFactory.gameAtIndex(index)
   │     └─ l2_provider.compute_output_root_at_block()
   │        ├─ L2 RPC: eth_getBlockByNumber(block_number)
   │        └─ L2 RPC: eth_getProof(address, [], block_number)
   ├─ sync_anchor_game()
   │  └─ factory.get_anchor_game()
   └─ compute_canonical_head()
      └─ 本地计算（遍历缓存）
   ↓
3. spawn_pending_operations()
   ├─ spawn_game_creation_task()
   │  ├─ should_create_game()
   │  │  ├─ host.get_finalized_l2_block_number()
   │  │  │  └─ L2 RPC: eth_getBlockByNumber("finalized")
   │  │  └─ 本地计算（比较区块号）
   │  └─ handle_game_creation()
   │     ├─ l2_provider.compute_output_root_at_block()
   │     │  ├─ L2 RPC: eth_getBlockByNumber(block_number)
   │     │  └─ L2 RPC: eth_getProof(address, [], block_number)
   │     ├─ factory.games()
   │     │  └─ L1合约: DisputeGameFactory.games()
   │     └─ create_game()
   │        ├─ factory.create()
   │        │  └─ L1合约: DisputeGameFactory.create()
   │        ├─ signer.send_transaction_request()
   │        │  └─ L1 RPC: eth_sendTransaction()
   │        └─ 等待交易确认
   │           └─ L1 RPC: eth_getTransactionReceipt()
   │
   └─ spawn_game_proving_task()
      └─ prove_game()
         ├─ game.l1Head()
         │  └─ L1合约: OPSuccinctFaultDisputeGame.l1Head()
         ├─ host.fetch()
         │  ├─ calculate_safe_l1_head()
         │  │  ├─ fetcher.get_l1_head()
         │  │  │  ├─ get_safe_l1_block_for_l2_block()
         │  │  │  │  ├─ L2 Node RPC: optimism_outputAtBlock(l2_end_block)
         │  │  │  │  └─ L2 Node RPC: optimism_safeHeadAtL1Block(l1_block)
         │  │  │  └─ L1 RPC: eth_getBlockByNumber("finalized")
         │  │  └─ L1 RPC: eth_getBlockByNumber(block_number)
         │  └─ fetcher.get_host_args()
         │     ├─ L2 RPC: eth_getBlockByNumber(start_block)
         │     ├─ L2 RPC: eth_getProof(address, [], start_block)
         │     ├─ L2 RPC: eth_getBlockByNumber(end_block)
         │     └─ L2 RPC: eth_getProof(address, [], end_block)
         ├─ host.run()
         │  ├─ SingleChainHost.start_server()
         │  │  └─ 启动 kona-host 进程（preimage oracle）
         │  └─ witness_generator.run()
         │     └─ ETHDAWitnessExecutor.run()
         │        ├─ KonaExecutor::new()
         │        ├─ Driver::new()
         │        └─ advance_to_target()
         │           ├─ driver.pipeline.advance()
         │           │  └─ OraclePipeline.advance()
         │           │     └─ 通过 preimage oracle 获取 L1 batch 数据
         │           └─ driver.executor.execute_payload()
         │              └─ KonaExecutor.execute_payload()
         │                 └─ 执行 OP Stack 状态转换
         │                    └─ 通过 preimage oracle 获取交易和状态数据
         ├─ witness_generator.get_sp1_stdin()
         │  └─ 序列化 witness data
         ├─ network_prover.prove(range_pk, stdin)
         │  └─ SP1 Prover Network API
         │     └─ HTTP POST 到 SP1 网络
         ├─ get_agg_proof_stdin()
         │  └─ 准备聚合证明输入
         ├─ network_prover.prove(agg_pk, stdin)
         │  └─ SP1 Prover Network API
         │     └─ HTTP POST 到 SP1 网络
         └─ game.prove(agg_proof)
            ├─ L1合约: OPSuccinctFaultDisputeGame.prove(proof)
            ├─ signer.send_transaction_request()
            │  └─ L1 RPC: eth_sendTransaction()
            └─ 等待交易确认
               └─ L1 RPC: eth_getTransactionReceipt()
```

---

## 总结

### 关键调用点

1. **L1 合约调用**: 通过 `alloy` 库调用 L1 合约方法
2. **L1/L2 RPC 调用**: 通过 `alloy_provider` 调用标准以太坊 RPC
3. **Optimism RPC 调用**: 通过 `op_alloy_rpc_types` 调用 Optimism 扩展 RPC
4. **Kona 调用**: 通过 `kona_host` 和 `kona_executor` 调用 Kona
5. **SP1 调用**: 通过 `sp1_sdk` 调用 SP1 Prover Network

### 数据流向

```
L1/L2 链上数据
    ↓ (通过 RPC)
Proposer (状态同步)
    ↓ (准备参数)
Host (Kona Host Server)
    ↓ (preimage oracle)
Client (Kona Executor)
    ↓ (执行状态转换)
Witness Data
    ↓ (序列化)
SP1 Prover Network
    ↓ (生成证明)
ZK Proof
    ↓ (提交到链上)
L1 合约验证
```

### 性能考虑

- **异步任务**: 所有耗时操作都在独立的异步任务中执行
- **并发控制**: 通过 `max_concurrent_defense_tasks` 和 `fast_finality_proving_limit` 控制并发
- **错误处理**: 每个步骤都有错误处理，失败不会影响其他任务
- **指标收集**: 通过 Prometheus 收集各种指标

---

## 参考资料

- [OP Stack 架构](https://specs.optimism.io/)
- [Kona 文档](https://op-rs.github.io/kona/)
- [SP1 文档](https://docs.succinct.xyz/docs/sp1/introduction)
- [Optimism RPC 方法](https://docs.optimism.io/builders/node-operators/node-apis)

