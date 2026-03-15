# OP Succinct 框架复用设计方案

## 概述

本文档描述如何将 OP Succinct 的 fault-proof 框架重构为可复用的架构，支持两个不同的项目：
1. **OP 兼容项目**：使用 Kona 作为 program，完全兼容 OP Stack
2. **X2 项目**：完全重写自己的 program

> 📊 **架构图**: 详细的架构图和组件关系图请参考 [FRAMEWORK_ARCHITECTURE.md](./FRAMEWORK_ARCHITECTURE.md)

## 架构分析

### 当前架构

```
OPSuccinctProposer
├── 游戏状态管理（可复用）
├── 任务调度逻辑（可复用）
├── 合约交互（可复用）
└── 证明生成（需要抽象）
    ├── Host (已有 trait)
    ├── WitnessGenerator (已有 trait)
    ├── Program ELF (硬编码)
    └── Aggregation Proof (硬编码 OP 逻辑)
```

### 可复用的组件

1. **游戏状态同步逻辑**
   - `sync_state()`
   - `sync_games()`
   - `sync_anchor_game()`
   - `compute_canonical_head()`

2. **任务调度逻辑**
   - `spawn_pending_operations()`
   - `handle_completed_tasks()`
   - `TaskMap` 管理

3. **游戏状态管理**
   - `Game` 结构
   - `ProposerState` / `ChallengerState`
   - 游戏树遍历逻辑

4. **合约交互**
   - `DisputeGameFactory` 交互
   - `OPSuccinctFaultDisputeGame` 交互
   - 游戏创建/挑战/解决/债券领取

5. **Challenger 逻辑**
   - `handle_game_challenging()`
   - `handle_game_resolution()`
   - `handle_bond_claiming()`

### 需要抽象的组件

1. **Program Provider** - 提供不同的 ELF 程序
2. **Aggregation Proof Builder** - 构建聚合证明的 stdin
3. **Data Fetcher** - 获取链上数据（可选，当前硬编码）

## 设计方案

### 1. Program Provider Trait

```rust
/// 提供 range program 和 aggregation program 的 ELF
#[async_trait]
pub trait ProgramProvider: Send + Sync + 'static {
    /// 获取 range program 的 ELF
    fn get_range_elf(&self) -> &[u8];
    
    /// 获取 aggregation program 的 ELF
    fn get_aggregation_elf(&self) -> &[u8];
    
    /// 获取 range program 的验证密钥（用于聚合证明）
    fn get_range_vk(&self) -> &SP1VerifyingKey;
}
```

### 2. Aggregation Proof Builder Trait

```rust
/// 构建聚合证明的 stdin
#[async_trait]
pub trait AggregationProofBuilder: Send + Sync + 'static {
    /// 构建聚合证明的 stdin
    /// 
    /// Parameters:
    /// - `range_proofs`: Range proofs 列表
    /// - `public_values`: 对应的 public values
    /// - `range_vk`: Range program 的验证密钥
    /// - `l1_head_hash`: L1 头哈希
    /// - `proposer_address`: Proposer 地址
    async fn build_aggregation_stdin(
        &self,
        range_proofs: Vec<SP1Proof>,
        public_values: Vec<Vec<u8>>,
        range_vk: &SP1VerifyingKey,
        l1_head_hash: B256,
        proposer_address: Address,
    ) -> Result<SP1Stdin>;
}
```

### 3. 重构后的 Proposer

```rust
pub struct GenericProposer<P, H, PP, APB>
where
    P: Provider + Clone + Send + Sync + 'static,
    H: OPSuccinctHost + Clone + Send + Sync + 'static,
    PP: ProgramProvider,
    APB: AggregationProofBuilder,
{
    // ... 现有字段 ...
    program_provider: Arc<PP>,
    aggregation_builder: Arc<APB>,
}

impl<P, H, PP, APB> GenericProposer<P, H, PP, APB>
where
    P: Provider + Clone + Send + Sync + 'static,
    H: OPSuccinctHost + Clone + Send + Sync + 'static,
    PP: ProgramProvider,
    APB: AggregationProofBuilder,
{
    pub async fn prove_game(
        &self,
        game_address: Address,
        start_block: u64,
        end_block: u64,
    ) -> Result<(TxHash, u64, u64)> {
        // 1. 获取 witness data（使用 Host trait，已抽象）
        let witness_data = self.host.run(&host_args).await?;
        let sp1_stdin = self.host.witness_generator().get_sp1_stdin(witness_data)?;
        
        // 2. 生成 range proof（使用 ProgramProvider）
        let range_elf = self.program_provider.get_range_elf();
        let range_proof = self.prover.network_prover
            .prove(&self.prover.range_pk, &sp1_stdin)
            .run_async()
            .await?;
        
        // 3. 构建聚合证明 stdin（使用 AggregationProofBuilder）
        let agg_stdin = self.aggregation_builder
            .build_aggregation_stdin(
                vec![range_proof.proof.clone()],
                vec![range_proof.public_values.clone()],
                self.program_provider.get_range_vk(),
                l1_head_hash,
                self.signer.address(),
            )
            .await?;
        
        // 4. 生成聚合证明（使用 ProgramProvider）
        let agg_elf = self.program_provider.get_aggregation_elf();
        let agg_proof = self.prover.network_prover
            .prove(&self.prover.agg_pk, &agg_stdin)
            .run_async()
            .await?;
        
        // 5. 提交证明（合约交互，可复用）
        // ...
    }
}
```

### 4. OP 特定的实现

```rust
/// OP 项目的 ProgramProvider 实现
pub struct OPProgramProvider {
    range_elf: Vec<u8>,
    aggregation_elf: Vec<u8>,
    range_vk: SP1VerifyingKey,
}

impl ProgramProvider for OPProgramProvider {
    fn get_range_elf(&self) -> &[u8] {
        &self.range_elf
    }
    
    fn get_aggregation_elf(&self) -> &[u8] {
        &self.aggregation_elf
    }
    
    fn get_range_vk(&self) -> &SP1VerifyingKey {
        &self.range_vk
    }
}

/// OP 项目的 AggregationProofBuilder 实现
pub struct OPAggregationProofBuilder {
    fetcher: Arc<OPSuccinctDataFetcher>,
}

#[async_trait]
impl AggregationProofBuilder for OPAggregationProofBuilder {
    async fn build_aggregation_stdin(
        &self,
        range_proofs: Vec<SP1Proof>,
        public_values: Vec<Vec<u8>>,
        range_vk: &SP1VerifyingKey,
        l1_head_hash: B256,
        proposer_address: Address,
    ) -> Result<SP1Stdin> {
        // 使用现有的 get_agg_proof_stdin 逻辑
        let boot_info: BootInfoStruct = public_values[0].read();
        let headers = self.fetcher
            .get_header_preimages(&vec![boot_info.clone()], boot_info.l1Head)
            .await?;
        
        get_agg_proof_stdin(
            range_proofs,
            vec![boot_info],
            headers,
            range_vk,
            l1_head_hash,
            proposer_address,
        )
    }
}
```

### 5. X2 项目的实现

```rust
/// X2 项目的 ProgramProvider 实现
pub struct X2ProgramProvider {
    range_elf: Vec<u8>,
    aggregation_elf: Vec<u8>,
    range_vk: SP1VerifyingKey,
}

impl ProgramProvider for X2ProgramProvider {
    // ... 实现 ...
}

/// X2 项目的 AggregationProofBuilder 实现
pub struct X2AggregationProofBuilder {
    // X2 的数据获取逻辑
}

#[async_trait]
impl AggregationProofBuilder for X2AggregationProofBuilder {
    async fn build_aggregation_stdin(
        &self,
        range_proofs: Vec<SP1Proof>,
        public_values: Vec<Vec<u8>>,
        range_vk: &SP1VerifyingKey,
        l1_head_hash: B256,
        proposer_address: Address,
    ) -> Result<SP1Stdin> {
        // X2 的聚合证明构建逻辑
        // 不需要依赖 OP 特定的数据结构
    }
}
```

## 实施步骤

### 阶段 1: 创建抽象 Trait

1. 在 `fault-proof/src` 下创建 `traits.rs`
2. 定义 `ProgramProvider` 和 `AggregationProofBuilder` trait
3. 将 trait 添加到 `lib.rs` 导出

### 阶段 2: 重构现有代码

1. 将 `OPSuccinctProposer` 重构为 `GenericProposer<P, H, PP, APB>`
2. 提取可复用的游戏状态管理和任务调度逻辑
3. 将证明生成逻辑改为使用 trait

### 阶段 3: 创建 OP 特定实现

1. 创建 `OPProgramProvider` 和 `OPAggregationProofBuilder`
2. 创建 `OPSuccinctProposer` 作为 `GenericProposer` 的类型别名
3. 确保现有功能不受影响

### 阶段 4: 支持 X2 项目

1. 创建 `X2ProgramProvider` 和 `X2AggregationProofBuilder`
2. 创建 `X2Proposer` 类型别名
3. 编写使用示例

## 可复用的其他组件

### 1. Challenger

Challenger 的逻辑相对简单，主要是：
- 游戏状态同步（可复用）
- 挑战逻辑（可复用，基于合约交互）
- 解决和债券领取（可复用）

Challenger 不需要大的改动，因为它不直接生成证明。

### 2. 合约交互

所有合约交互逻辑都可以复用：
- `DisputeGameFactory` 交互
- `OPSuccinctFaultDisputeGame` 交互
- 游戏创建/挑战/解决/债券领取

### 3. 配置和工具

- `ProposerConfig` / `ChallengerConfig`（可能需要扩展）
- Metrics 收集
- 日志系统
- Signer 管理

## 使用示例

### OP 项目

```rust
let program_provider = Arc::new(OPProgramProvider::new()?);
let aggregation_builder = Arc::new(OPAggregationProofBuilder::new(fetcher)?);
let host = initialize_host(Arc::new(fetcher.clone()));

let proposer = Arc::new(
    GenericProposer::new(
        config,
        signer,
        factory,
        fetcher,
        host,
        program_provider,
        aggregation_builder,
    )
    .await?,
);
```

### X2 项目

```rust
let program_provider = Arc::new(X2ProgramProvider::new(x2_elf_path)?);
let aggregation_builder = Arc::new(X2AggregationProofBuilder::new()?);
let host = initialize_x2_host(x2_config);

let proposer = Arc::new(
    GenericProposer::new(
        config,
        signer,
        factory,
        fetcher,
        host,
        program_provider,
        aggregation_builder,
    )
    .await?,
);
```

## 优势

1. **代码复用**：核心逻辑（游戏管理、任务调度、合约交互）完全复用
2. **灵活性**：不同项目只需实现 trait，无需修改核心代码
3. **类型安全**：使用 Rust 的类型系统确保正确性
4. **向后兼容**：现有 OP 项目代码可以平滑迁移
5. **易于测试**：可以轻松创建 mock 实现进行测试

## 注意事项

1. **Host trait 的通用性**：确保 `OPSuccinctHost` trait 足够通用，或者创建更通用的 `Host` trait
2. **WitnessGenerator 的通用性**：确保 `WitnessGenerator` trait 支持不同的 witness 数据结构
3. **配置扩展**：可能需要扩展配置以支持不同项目的特定需求
4. **文档**：需要为每个 trait 编写清晰的文档和使用示例

## 总结

通过引入 `ProgramProvider` 和 `AggregationProofBuilder` trait，我们可以将 OP Succinct 框架重构为高度可复用的架构。核心的游戏管理、任务调度和合约交互逻辑可以完全复用，而不同项目只需要实现特定的 trait 即可。

