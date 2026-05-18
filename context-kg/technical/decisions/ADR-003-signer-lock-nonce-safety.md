---
name: "ADR-003-signer-lock-nonce-safety"
description: "ADR: 使用 SignerLock (Arc<Mutex<Signer>>) 序列化交易提交防止 nonce 冲突"
---

# ADR-003: SignerLock 实现 Nonce 安全

## Status

Accepted

## Context

validity 和 fault-proof 服务在异步运行时中生成多个并发任务（如同时提交范围证明和聚合证明）。这些任务共享同一个 L1 签名地址。

如果多个任务同时调用 `send_transaction_request()`，可能获取到相同的 nonce，导致交易冲突。链上 nonce 冲突是不可恢复的硬错误，需要人工干预。相关踩坑记录见 `modules/utils-signer.md` [Pitfall]。

## Decision

**使用 `Arc<Mutex<Signer>>` 封装签名器，命名为 `SignerLock`，序列化所有交易提交。**

```rust
// utils/signer/src/lib.rs
pub struct SignerLock {
    inner: Arc<Mutex<Signer>>,
    cached_address: Address,  // 避免仅查询地址时加锁
}
```

所有发送交易的调用必须通过 `SignerLock`，确保同一时刻只有一个交易在签名和发送。`cached_address` 字段允许无锁读取地址。

## Alternatives Considered

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| RPC 端 nonce 管理 | 不需要本地锁 | 增加延迟；provider 返回的 nonce 在签名前可能已变 | **否决** |
| 乐观并发（提交所有，容忍失败） | 高吞吐量 | nonce 冲突导致灾难性失败，需人工干预 | **否决** |
| Channel 队列 | 更精细的控制 | 过度设计；简单 Mutex 足够且易理解 | **否决** |
| `Arc<Mutex<Signer>>` (SignerLock) | 简单可靠；Rust 原生并发安全 | 吞吐量限制为约 1 tx/block | **采纳** |

## Consequences

- **正面**: 正确性保证高于吞吐量——对证明提交场景而言是正确的权衡
- **负面**: 单地址交易完全序列化，吞吐量约为每区块 1 笔交易
- **中性**: `cached_address` 避免仅查询地址时的锁竞争
