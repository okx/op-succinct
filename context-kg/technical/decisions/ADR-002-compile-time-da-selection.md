---
name: "ADR-002-compile-time-da-selection"
description: "ADR: DA 层通过 Cargo feature 在编译时选择，每个二进制只含一种 DA 实现"
---

# ADR-002: 编译期 DA 层选择（Cargo Features）

## Status

Accepted

## Context

op-succinct 需要支持多种数据可用性（DA）方案：Ethereum blobs、Celestia、EigenDA。每种 DA 层有不同的见证格式、验证逻辑和预编译调用。

zkVM guest 程序对代码大小和执行性能有严格约束，运行时多态分发会增加开销。

## Decision

**DA 层通过 Cargo feature flag 在编译时选择，每个二进制文件只包含一种 DA 实现。** 默认 feature 为 `ethereum`。

```rust
// utils/proof/src/lib.rs — initialize_host()
cfg_if::cfg_if! {
    if #[cfg(feature = "celestia")] {
        use op_succinct_celestia_host_utils::host::CelestiaOPSuccinctHost;
    } else if #[cfg(feature = "eigenda")] {
        use op_succinct_eigenda_host_utils::host::EigenDAOPSuccinctHost;
    } else {
        use op_succinct_ethereum_host_utils::host::SingleChainOPSuccinctHost;
    }
}
```

三个 feature 在 `utils/proof/Cargo.toml`、`validity/Cargo.toml`、`fault-proof/Cargo.toml` 中均有定义。此规则在 `knowledge-base.md` 和 `conventions/feature-types.md` 中以 [Rule] 标记强制执行：不得在同一构建中启用两个 DA feature。

每种 DA 有独立的 range 程序和 client/host 工具对：`programs/range/{ethereum,celestia,eigenda}/` 和 `utils/{ethereum,celestia,eigenda}/{client,host}/`。

## Alternatives Considered

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| 运行时 trait 分发 | 单一二进制适用所有 DA | zkVM 内多态开销；代码体积增大；类型擦除增加复杂度 | **否决** |
| 编译时 feature 选择 | 零运行时开销；zkVM 内代码精简；类型安全 | 需维护三套构建产物；运营方可能部署错误版本 | **采纳** |
| 多 DA 单二进制 | 灵活性最高 | DA 特有的预编译必须静态解析，架构不支持 | **否决** |

## Consequences

- **正面**: zkVM guest 内零分发开销，最优执行性能
- **负面**: CI/CD 需要构建三个版本；运营方需确保部署正确的 DA 变体
- **扩展**: 新增 DA 层需要创建 `programs/range/<da>/` 和 `utils/<da>/{client,host}` crate
