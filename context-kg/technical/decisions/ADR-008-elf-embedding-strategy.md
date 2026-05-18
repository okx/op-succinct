---
name: "ADR-008-elf-embedding-strategy"
description: "ADR: 使用 include_bytes! 在编译时嵌入 SP1 ELF，确保 host 和 guest 版本一致"
---

# ADR-008: ELF 编译时嵌入策略

## Status

Accepted

## Context

SP1 zkVM 程序编译为 ELF 格式，需要在 host 端加载并提交给 prover。ELF 文件约 1-2 MB，需要为每种 DA 层维护独立版本。

## Decision

**使用 `include_bytes!()` 宏在编译时将 ELF 文件嵌入二进制。**

```rust
// utils/elfs/src/lib.rs
pub const AGGREGATION_ELF: &[u8] = include_bytes!("../../../elf/aggregation-elf");
pub const RANGE_ELF_EMBEDDED: &[u8] = include_bytes!("../../../elf/range-elf-embedded");
pub const CELESTIA_RANGE_ELF_EMBEDDED: &[u8] =
    include_bytes!("../../../elf/celestia-range-elf-embedded");
pub const EIGENDA_RANGE_ELF_EMBEDDED: &[u8] =
    include_bytes!("../../../elf/eigenda-range-elf-embedded");
```

通过 feature flag 选择对应 DA 的 ELF（`utils/proof/src/lib.rs` 的 `get_range_elf_embedded()` 函数）：

```rust
pub fn get_range_elf_embedded() -> &'static [u8] {
    cfg_if::cfg_if! {
        if #[cfg(feature = "celestia")] { CELESTIA_RANGE_ELF_EMBEDDED }
        else if #[cfg(feature = "eigenda")] { EIGENDA_RANGE_ELF_EMBEDDED }
        else { RANGE_ELF_EMBEDDED }
    }
}
```

ELF 编译逻辑在 `utils/build/src/lib.rs` 的 `build_program()` / `build_all()` 中。

## Alternatives Considered

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| 运行时文件加载 | 更小的二进制；可热更新 ELF | 版本偏差风险；额外 I/O；需独立分发 ELF | **否决** |
| `include_bytes!()` 嵌入 | 确定性；零运行时 I/O；ELF 随二进制版本化 | 二进制体积增大 ~10 MB；更新需重编译 | **采纳** |

## Consequences

- **正面**: ELF 不匹配错误在编译时而非运行时暴露；零运行时 I/O
- **负面**: 二进制体积增加约 10 MB；更新 ELF 需重编译部署
- **中性**: ELF 构建时间约 10 分钟（Docker 中的 SP1 编译）
