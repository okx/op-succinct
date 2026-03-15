# Hint Handler 详细逻辑说明

## 概述

`fetch_hint` 方法是 Host Server 处理 hint 请求的核心方法。当 Client 发送 hint 时，Host Server 会根据 hint 类型从 RPC 获取相应的数据，并存储到 KV store 中，供后续 preimage 请求使用。

## 方法签名

```rust
async fn fetch_hint(
    hint: Hint<HintType>,
    cfg: &SingleChainHost,
    providers: &Providers,
    kv: SharedKeyValueStore,
) -> Result<()>
```

## Hint 类型分类

### 1. 简单 KV 请求类型（简要说明）

这些类型直接从 RPC 获取单个数据项并存储：

| Hint 类型 | RPC 方法 | 数据格式 | 说明 |
|----------|---------|---------|------|
| **L1BlockHeader** | `debug_getRawHeader` | `[32 bytes hash]` | 获取 L1 区块头 |
| **L1Transactions** | `get_block_by_hash` | `[32 bytes hash]` | 获取 L1 交易列表，存储 trie 节点 |
| **L1Receipts** | `debug_getRawReceipts` | `[32 bytes hash]` | 获取 L1 收据列表，存储 trie 节点 |
| **L1Blob** | `fetch_filtered_blob_sidecars` | `[32 bytes hash] + [8 bytes index] + [8 bytes timestamp]` | 获取 EIP-4844 blob 数据 |
| **L1Precompile** | 本地执行 | `[20 bytes address] + [8 bytes gas] + [input data]` | 执行预编译合约 |
| **L2BlockHeader** | `debug_getRawHeader` | `[32 bytes hash]` | 获取 L2 区块头 |
| **L2Transactions** | `get_block_by_hash` | `[32 bytes hash]` | 获取 L2 交易列表，存储 trie 节点 |
| **StartingL2Output** | `debug_getRawHeader` + `get_proof` | `[32 bytes output_root]` | 获取并验证起始 L2 output root |
| **L2Code** | `debug_dbGet` | `[32 bytes code_hash]` | 获取合约代码 |
| **L2StateNode** | `debug_dbGet` | `[32 bytes node_hash]` | 获取状态节点 |

---

## 需要 Proof 的类型（详细说明）

### 1. `L2AccountProof` (284-304行)

**用途**：获取账户的 Merkle proof，包含从 state root 到账户的所有 trie 节点。

**详细流程**：

```rust
HintType::L2AccountProof => {
    // 1. 解析 hint 数据
    // hint.data = [8 bytes block_number] + [20 bytes address]
    ensure!(hint.data.len() == 8 + 20, "Invalid hint data length");
    
    let block_number = u64::from_be_bytes(hint.data.as_ref()[..8].try_into()?);
    let address = Address::from_slice(&hint.data.as_ref()[8..28]);
    
    // 2. 请求账户 proof
    // RPC: eth_getProof(address, [], block_number)
    // 返回: AccountProof (包含 account_proof 数组)
    let proof_response = providers
        .l2
        .get_proof(address, Default::default())  // 空数组表示只要账户 proof，不要 storage proof
        .block_id(block_number.into())
        .await?;
    
    // 3. 存储所有 proof 节点到 KV store
    let mut kv_lock = kv.write().await;
    proof_response.account_proof.into_iter().try_for_each(|node| {
        // 计算节点的 hash（作为 key）
        let node_hash = keccak256(node.as_ref());
        let key = PreimageKey::new_keccak256(*node_hash);
        
        // 存储: key = node_hash, value = node_data
        kv_lock.set(key.into(), node.into())?;
        Ok::<(), anyhow::Error>(())
    })?;
}
```

**关键点**：

- **RPC 请求**：`eth_getProof(address, [], block_number)`
  - 第二个参数为空数组 `[]`，表示只要账户 proof，不需要 storage proof
- **返回内容**：`account_proof` 数组，包含从 state root 到账户路径上的所有 trie 节点
- **存储方式**：每个节点的 hash 作为 key，节点数据作为 value
- **用途**：验证账户存在性和账户状态（nonce、balance、storage root、code hash）

**数据结构**：

```
account_proof: [
    节点1,  // state root 的子节点
    节点2,  // 中间节点
    ...
    节点N   // 账户节点
]
```

---

### 2. `L2AccountStorageProof` (305-336行)

**用途**：获取账户的账户 proof 和指定 storage slot 的 storage proof。

**详细流程**：

```rust
HintType::L2AccountStorageProof => {
    // 1. 解析 hint 数据
    // hint.data = [8 bytes block_number] + [20 bytes address] + [32 bytes slot]
    ensure!(hint.data.len() == 8 + 20 + 32, "Invalid hint data length");
    
    let block_number = u64::from_be_bytes(hint.data.as_ref()[..8].try_into()?);
    let address = Address::from_slice(&hint.data.as_ref()[8..28]);
    let slot = B256::from_slice(&hint.data.as_ref()[28..]);
    
    // 2. 请求账户和 storage proof
    // RPC: eth_getProof(address, [slot], block_number)
    // 返回: AccountProof + StorageProof
    let mut proof_response = providers
        .l2
        .get_proof(address, vec![slot])  // 指定要证明的 storage slot
        .block_id(block_number.into())
        .await?;
    
    let mut kv_lock = kv.write().await;
    
    // 3. 存储账户 proof 节点
    proof_response.account_proof.into_iter().try_for_each(|node| {
        let node_hash = keccak256(node.as_ref());
        let key = PreimageKey::new_keccak256(*node_hash);
        kv_lock.set(key.into(), node.into())?;
        Ok::<(), anyhow::Error>(())
    })?;
    
    // 4. 存储 storage proof 节点
    let storage_proof = proof_response.storage_proof.remove(0);  // 取出第一个 storage proof
    storage_proof.proof.into_iter().try_for_each(|node| {
        let node_hash = keccak256(node.as_ref());
        let key = PreimageKey::new_keccak256(*node_hash);
        kv_lock.set(key.into(), node.into())?;
        Ok::<(), anyhow::Error>(())
    })?;
}
```

**关键点**：

- **RPC 请求**：`eth_getProof(address, [slot], block_number)`
  - 第二个参数包含要证明的 storage slot
- **返回内容**：
  - `account_proof`：账户 proof 节点数组
  - `storage_proof`：storage proof 数组（每个 slot 一个）
- **存储方式**：
  - 先存储账户 proof 的所有节点
  - 再存储 storage proof 的所有节点
- **用途**：验证账户存在性和 storage slot 的值

**数据结构**：

```
account_proof: [
    节点1,  // state root 的子节点
    节点2,  // 中间节点
    ...
    节点N   // 账户节点
]

storage_proof: [
    {
        proof: [
            节点1,  // storage root 的子节点
            节点2,  // 中间节点
            ...
            节点M   // slot 节点
        ],
        value: slot 的值
    }
]
```

**Proof 结构说明**：

- **Account Proof**：从 state root 到账户的路径上的所有 trie 节点
- **Storage Proof**：从账户的 storage root 到指定 slot 的路径上的所有 trie 节点

---

### 3. `L2PayloadWitness` (337-379行)

**用途**：通过执行 payload 获取完整的执行 witness（状态节点、代码、keys）。

**详细流程**：

```rust
HintType::L2PayloadWitness => {
    // 1. 检查是否启用实验性功能
    if !cfg.enable_experimental_witness_endpoint {
        warn!("L2PayloadWitness hint was sent, but payload witness is disabled. Skipping hint.");
        return Ok(());
    }
    
    // 2. 解析 hint 数据
    // hint.data = [32 bytes parent_block_hash] + [JSON payload_attributes]
    ensure!(hint.data.len() >= 32, "Invalid hint data length");
    
    let parent_block_hash = B256::from_slice(&hint.data.as_ref()[..32]);
    let payload_attributes: OpPayloadAttributes =
        serde_json::from_slice(&hint.data[32..])?;
    
    // 3. 调用 debug_executePayload RPC
    // 这个 RPC 会执行 payload，并返回执行过程中访问的所有数据
    let Ok(execute_payload_response) = providers
        .l2
        .client()
        .request::<(B256, OpPayloadAttributes), ExecutionWitness>(
            "debug_executePayload",  // 实验性 RPC 方法
            (parent_block_hash, payload_attributes),
        )
        .await
    else {
        // 如果 RPC 不支持，静默失败（不是所有执行客户端都支持）
        return Ok(());
    };
    
    // 4. 合并所有 preimage 数据
    // ExecutionWitness 包含：
    // - state: 状态节点数组
    // - codes: 合约代码数组
    // - keys: 其他 key 数组
    let preimages = execute_payload_response
        .state      // 状态 trie 节点
        .into_iter()
        .chain(execute_payload_response.codes)  // 合约代码
        .chain(execute_payload_response.keys);   // 其他 keys
    
    // 5. 存储所有 preimage 到 KV store
    let mut kv_lock = kv.write().await;
    for preimage in preimages {
        // 计算 hash 作为 key
        let computed_hash = keccak256(preimage.as_ref());
        let key = PreimageKey::new_keccak256(*computed_hash);
        
        // 存储: key = hash, value = preimage_data
        kv_lock.set(key.into(), preimage.into())?;
    }
}
```

**关键点**：

- **RPC 方法**：`debug_executePayload`（实验性，不是所有客户端都支持）
- **输入参数**：
  - `parent_block_hash`：父区块 hash
  - `payload_attributes`：包含交易、时间戳等信息的 JSON
- **返回内容**：`ExecutionWitness`，包含执行过程中访问的所有数据：
  - `state`：状态 trie 节点数组
  - `codes`：合约代码数组
  - `keys`：其他 key 数组
- **存储方式**：所有 preimage 的 hash 作为 key，数据作为 value
- **用途**：一次性获取执行 payload 所需的所有 witness 数据

**优势**：

- ✅ **一次性获取**：避免多次 RPC 调用
- ✅ **完整数据**：包含执行过程中实际访问的所有数据
- ✅ **性能优化**：减少网络往返次数

**限制**：

- ⚠️ **实验性功能**：需要执行客户端支持 `debug_executePayload`
- ⚠️ **可能不稳定**：某些客户端可能不支持此方法
- ⚠️ **静默失败**：如果不支持，会静默跳过，不会报错

**数据结构**：

```rust
ExecutionWitness {
    state: Vec<Bytes>,   // 状态 trie 节点
    codes: Vec<Bytes>,   // 合约代码
    keys: Vec<Bytes>,    // 其他 keys
}
```

---

## 总结对比

| 类型 | RPC 方法 | 返回内容 | 存储内容 | 用途 | 特点 |
|------|---------|---------|---------|------|------|
| **L2AccountProof** | `eth_getProof(address, [], block)` | `account_proof` 数组 | 账户 proof 的所有 trie 节点 | 验证账户存在性 | 只获取账户 proof |
| **L2AccountStorageProof** | `eth_getProof(address, [slot], block)` | `account_proof` + `storage_proof` | 账户 proof 节点 + storage proof 节点 | 验证账户和 storage slot | 获取账户和 storage proof |
| **L2PayloadWitness** | `debug_executePayload(...)` | `ExecutionWitness` (state + codes + keys) | 执行过程中访问的所有数据 | 一次性获取完整执行 witness | 实验性，最完整但可能不支持 |

## 关键设计思想

1. **预取优化**：通过 hint 提前获取数据，减少执行时的 RPC 调用
2. **Proof 完整性**：存储完整的 proof 路径，确保可以验证数据
3. **按需加载**：只获取实际需要的数据，避免浪费
4. **容错处理**：对于不支持的功能（如 `debug_executePayload`），静默失败而不是报错

## 数据流

```
Client 发送 Hint
    ↓
Host Server 接收 Hint
    ↓
根据 Hint 类型调用相应的 RPC
    ↓
获取数据（区块头、交易、proof 等）
    ↓
计算每个数据项的 hash
    ↓
存储到 KV Store (key = hash, value = data)
    ↓
后续 Client 请求 preimage 时，直接从 KV Store 获取
```

