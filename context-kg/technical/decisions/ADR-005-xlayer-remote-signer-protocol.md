---
name: "ADR-005-xlayer-remote-signer-protocol"
description: "ADR: XLayer 远程签名协议 (AES-ECB + HMAC)，Rust 实现必须与 Go 字节级兼容"
---

# ADR-005: XLayer 远程签名协议（AES-ECB + HMAC）

## Status

Accepted

## Context

XLayer 是 OKX 托管的硬件安全模块（HSM）服务，用于私钥保管。它使用非标准的 HTTP 签名协议（不是 JSON-RPC 或 Web3Signer），且 Rust 实现必须与 Go 实现字节级兼容以通过服务端验证。

这不是一个可选择的架构决策——XLayer 的协议是外部约束，Rust 实现必须完全匹配。完整协议流程见 `core-flows/xlayer-remote-signing.md`。

## Decision

**实现 OKX XLayer 远程签名认证协议，签名公式:**

```
signature = base64(AES-ECB(SHA256(sorted_url_values + body), secret_key))
```

关键步骤（实现于 `utils/signer/src/xlayer_remote_client.rs` 的 `generate_signature()` 方法）：
1. 对 URL 查询参数的**值**（非键）按字典序排序
2. 拼接排序后的值和请求体
3. SHA-256 哈希
4. AES-ECB 加密（密钥长度必须为 16/24/32 字节）
5. Base64 编码作为 `sign` 请求头

**关键约束**（在 `knowledge-base.md` 中以 [Rule] 标记）：
- [Rule] AES 密钥长度必须为 16/24/32 字节
- [Pitfall] 签名输入是 URL 查询参数的**值**（按字典序），不是键
- [Rule] 当 `access_key` 或 `secret_key` 为空时，跳过所有认证头（匿名模式）
- 签名轮询超时: 5 分钟（300 次 × 1 秒）

## Alternatives Considered

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| 标准 HMAC-SHA256 | 业界标准 | XLayer 后端不支持 | **不可用** |
| Web3Signer 协议 | 标准化 | XLayer 协议已固定，无法更改 | **不可用** |

## Consequences

- **正面**: 与 OKX HSM 基础设施完全集成
- **负面**: 不可复用于其他签名服务（XLayer 专有协议）；需要跨语言 fixture 测试（Go ↔ Rust）
- **中性**: AES-ECB 非现代密码学最佳实践，但这是外部 API 合约
