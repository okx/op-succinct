# xlayer-tee-enclave

`xlayer-tee-prover` ELF 实体——HTTP server，跑 kona range program、签 EIP712
`RangeJournal`。**当前 Phase 2B**：enclave 真跑 op-succinct `ETHDAWitnessExecutor`
做派生 + execution + claim 校验，跟 op-succinct SP1 range program 行为等价，
只是签名端用 EIP712 + secp256k1 替代 SP1 proof。

## 构建模式

| Build | feature | 适用 |
|---|---|---|
| 默认 | （无） | 本地 / CI；hardcoded dev key + placeholder attestation + TCP loopback。enclave 还是真跑 kona 派生 |
| 生产 | `--features vsock` (linux only) | 真 Nitro Enclave；NSM 硬件 key + 真 attestation + vsock。Phase 2C **尚未实现**，目前是 `todo!()` 占位 |

跟父 spec §4.3 的 `dev-mode` 命名不一样——这边走 **opt-in 真 Nitro**（默认就是 dev）。
理由：不小心运行默认 build 不会拿到一个看起来像生产其实是 dev 的进程。

## 跑

```bash
cd xlayer-tee-prover
cargo run -p xlayer-tee-enclave
# listening on 127.0.0.1:7878
# signer = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266   (Anvil account #0)
```

环境变量：

| 变量 | 默认 | 用途 |
|---|---|---|
| `LISTEN` | `127.0.0.1:7878` | bind 地址 |
| `L1_CHAIN_ID` | `1` | EIP712 domain chain id |
| `VERIFYING_CONTRACT` | `0x0000...0000` | EIP712 domain verifying contract address |
| `RUST_LOG` | `info` | log level |

## 端点

| 路由 | 方法 | 请求 body | 响应 |
|---|---|---|---|
| `/tasks/range` | POST | `rkyv(Witness)` = `rkyv(op_succinct DefaultWitnessData)` | 200 `rkyv(RangeTaskResponse)` / 4xx-5xx JSON `ErrorResponse` |
| `/attestation` | GET | — | 200 `application/octet-stream` placeholder COSE-ish blob |
| `/health` | GET | — | 200 JSON `{status, signer_address, signer_pubkey, pcr0, elf_version}` |

请求处理流程（Phase 2B）：

```
1. rkyv::from_bytes::<Witness>     ← witness = DefaultWitnessData
2. witness.get_oracle_and_blob_provider()  ← oracle + beacon
3. BootInfo::load(oracle)          ← 取出 6 个 Local key 字段
4. check_bounds                    ← claimed_l2_block > 0
5. ETHDAWitnessExecutor.run()      ← 真跑 kona derive + execute
   ├─ 不一致 → ClaimMismatch (400)
   └─ 一致   → output_root 等于 claim
6. 构造 RangeJournalWire           ← pcr0 + boot 各字段
7. EIP712 sign with DEV_KEY_HEX    ← 65 字节 sig
8. 返回 rkyv(RangeTaskResponse)
```

## 模块

| 文件 | 行数 | 内容 |
|---|---|---|
| `lib.rs` | 极小 | 模块声明 |
| `main.rs` | ~60 | tokio entry + axum bind + env config |
| `keys.rs` | ~110 | hardcoded Anvil acct #0 dev key + 单测匹配 |
| `attestation.rs` | ~110 | cfg-gated：dev placeholder / `todo!()` 真 NSM |
| `witness.rs` | ~55 | re-export `Witness` (`xlayer-tee-witness`) + `check_bounds(BootInfo)` |
| `replay.rs` | ~70 | **Phase 2B**：调 op-succinct `ETHDAWitnessExecutor.run` 真跑 kona |
| `signing.rs` | ~110 | EIP712 hash + k256 prehash sign + v normalize |
| `server.rs` | ~160 | axum router + 3 handler + 错误映射 |
| `error.rs` | ~55 | 内部 Error → wire ErrorKind |

## 测试

```bash
cargo test -p xlayer-tee-enclave
# 10 unit + 5 integration = 15 tests
```

Unit tests 覆盖：

- `keys`：DEV_KEY_HEX 解码、pubkey 长度 / SEC1 前缀、address 匹配 Anvil acct #0、`init_dev_keys` 幂等
- `witness`：`check_bounds` 拒零 claimed block
- `attestation`：empty nonce 校验、pubkey 校验、happy path
- `signing`：sign → ecrecover 回到 enclave 地址

Integration tests（用 `tower::ServiceExt::oneshot`，无 TCP 端口冲突）：

- `health.rs`：JSON shape
- `attestation.rs`：dev marker prefix
- `range_signing.rs` × 3:
  - synth witness（只有 Local keys）触发 `InvalidWitness`（kona run 缺 L2 chain preimages 时的预期行为）
  - 零 claimed block 触发 `InvalidWitness`
  - 非 rkyv body 触发 `DeserializeRkyv` 500

> Happy path "真 Witness → 签名 → ecrecover" 需要一个 host fetcher 录的
> 完整 witness blob（含 L2 chain preimages + blobs）。当前 synth fixture 只
> 有 Local keys，无法走完 kona 派生。Phase 2D 阶段录一个真 fixture 后会补
> 一个 happy-path 集成测试。

## Smoke test

```bash
cargo run --release -p xlayer-tee-enclave &
curl http://127.0.0.1:7878/health | jq
curl -o /tmp/att.bin http://127.0.0.1:7878/attestation
xxd /tmp/att.bin | head -5
```

## 不在本 crate 范围

- proposer fork / `RangeProverBackend` trait（另一同事做，见父 spec 附录 A）
- `/tasks/aggregation`（父 spec §3.3 已划出 scope）
- 真 NSM / vsock transport（`--features vsock` 留出口，未实现）
- 链上 `approvedEnclaves` 注册脚本

## 给 host/proposer 同事接入时要注意

1. **HTTP body**：`rkyv(op_succinct_client_utils::witness::DefaultWitnessData)`
   等价于 `rkyv(xlayer_tee_witness::Witness)`——两边 import 同一 crate
   commit 即可。BootInfo / RollupConfig / claim / 起止 block 全部通过
   `PreimageKey::Local` 嵌进 `preimage_store`，**和 op-succinct SP1 range
   program 同一份 wire 格式**。
2. **signer address 是 `0xf39F...2266`**（Anvil acct #0）。合约端在
   `approvedEnclaves` 注册测试时用这个地址 + 对应 65-byte uncompressed
   pubkey；切到真 NSM 后 pubkey 会变，host 端轮询 `/health` 拿到新值。
3. **PCR0 是全零**（dev mode）。合约端在 dev / testnet 环境别拒绝零 PCR0。
4. **错误协议**：`{ "error_kind": "...", "message": "..." }` JSON，路径见
   `xlayer-tee-types::error::ErrorKind`。HTTP 400 = terminal，500 = retryable。
   `ClaimMismatch` 在 Phase 2B 由 kona run 触发（不是 enclave bug，是 host
   投错 witness）。
