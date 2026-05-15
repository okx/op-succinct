# TZ Proposer / Challenger 操作手册

## 1. 编译

```bash
# 准备（只需一次）
touch /tmp/dummy_sp1_runner && chmod +x /tmp/dummy_sp1_runner

export SP1_CORE_RUNNER_OVERRIDE_BINARY=/tmp/dummy_sp1_runner
export SKIP_FORGE_BINDINGS=1

# 编译（release 模式，生产用）
cargo build --release --features tz \
  --bin tz-proposer \
  --bin tz-challenger \
  -p op-succinct-fp

# 产物路径
# target/release/tz-proposer
# target/release/tz-challenger
```

> **为什么需要两个环境变量？**
>
> | 变量 | 绕过什么 | 原因 |
> |---|---|---|
> | `SP1_CORE_RUNNER_OVERRIDE_BINARY` | `sp1-core-executor-runner` 的 build.rs | 该 crate 在构建时编译一个 native 二进制，内存不足会被 SIGKILL |
> | `SKIP_FORGE_BINDINGS` | `op-succinct-bindings` 的 build.rs | `forge bind` 因 contracts/lib/optimism 子模块版本不兼容而失败 |
>
> 预生成的 bindings（`bindings/src/codegen/`）仍然正常使用，跳过的只是重新生成步骤。

---

## 2. 单元测试

```bash
# 运行所有单元测试（含 tz_chain_client / tz_l2_provider / tz_proposer_config）
SP1_CORE_RUNNER_OVERRIDE_BINARY=/tmp/dummy_sp1_runner \
SKIP_FORGE_BINDINGS=1 \
cargo test --lib --features tz -p op-succinct-fp

# 只跑 tz 相关测试
SP1_CORE_RUNNER_OVERRIDE_BINARY=/tmp/dummy_sp1_runner \
SKIP_FORGE_BINDINGS=1 \
cargo test --lib --features tz -p op-succinct-fp tz_
```

---

## 3. 配置文件

二进制启动时自动读取当前目录下的 `.env` 文件：

| 二进制 | 读取文件 |
|---|---|
| `tz-proposer` | `.env.tz-proposer` |
| `tz-challenger` | `.env.tz-challenger` |

### `.env.tz-proposer` 完整示例

```bash
# ── TZ 链专用 ──────────────────────────────────────────────────────────────
# TZ L2 节点 REST API，逗号分隔多个地址（自动故障转移）
TZ_RPC_URLS=http://tz-node-1:8080,http://tz-node-2:8080

# rollup config 的 keccak256 哈希，用于生成 rootClaim
TZ_ROLLUP_CONFIG_HASH=0xabcdef...

# dispute game type ID，默认 1961
TZ_GAME_TYPE=1961

# ── L1 / L2 连接 ────────────────────────────────────────────────────────────
L1_RPC=https://l1-rpc.example.com
# tz 模式下 L2_RPC 仍需设置（ProposerConfig 解析时读取），但不会实际使用
L2_RPC=http://tz-node-1:8080

# ── 合约地址 ────────────────────────────────────────────────────────────────
ANCHOR_STATE_REGISTRY_ADDRESS=0x...
FACTORY_ADDRESS=0x...

# ── Proposer 行为 ────────────────────────────────────────────────────────────
# 每隔多少个 L2 block 提交一次 game（默认 1800）
PROPOSAL_INTERVAL_IN_BLOCKS=1800
# 主循环轮询间隔（秒，默认 30）
FETCH_INTERVAL=30

# ── Signer（三选一）─────────────────────────────────────────────────────────
# 方式 A：本地私钥
PRIVATE_KEY=0x...

# 方式 B：Web3Signer
# SIGNER_URL=http://web3signer:9000
# SIGNER_ADDRESS=0x...

# 方式 C：XLayer Remote Signer
# XLAYER_SIGNER_ENABLED=true
# XLAYER_SIGNER_ENDPOINT=http://...
# XLAYER_SIGNER_ADDRESS=0x...
# XLAYER_ACCESS_KEY=...
# XLAYER_SECRET_KEY=...

# ── SP1 Prover ───────────────────────────────────────────────────────────────
# 使用 SP1 Network（需要 NETWORK_PRIVATE_KEY）
SP1_PROVER=network
NETWORK_PRIVATE_KEY=0x...

# 或使用 mock 模式（仅测试，不生成真实证明）
# MOCK_MODE=true
# SP1_PROVER=mock

# ── Metrics ─────────────────────────────────────────────────────────────────
PROPOSER_METRICS_PORT=9000

# ── 可选调优 ─────────────────────────────────────────────────────────────────
# FAST_FINALITY_MODE=false
# FAST_FINALITY_PROVING_LIMIT=1
# RANGE_SPLIT_COUNT=1
# MAX_CONCURRENT_RANGE_PROOFS=1
# TIMEOUT=14400
# TX_CONFIRMATION_TIMEOUT=60
# BACKUP_PATH=/data/proposer-state.json
```

### `.env.tz-challenger` 完整示例

```bash
# ── TZ 链专用 ──────────────────────────────────────────────────────────────
TZ_RPC_URLS=http://tz-node-1:8080,http://tz-node-2:8080
# challenger 不需要 TZ_ROLLUP_CONFIG_HASH
TZ_GAME_TYPE=1961

# ── L1 / L2 连接 ────────────────────────────────────────────────────────────
L1_RPC=https://l1-rpc.example.com
L2_RPC=http://tz-node-1:8080

# ── 合约地址 ────────────────────────────────────────────────────────────────
ANCHOR_STATE_REGISTRY_ADDRESS=0x...
FACTORY_ADDRESS=0x...

# ── Signer（三选一，同 proposer）────────────────────────────────────────────
PRIVATE_KEY=0x...

# ── 行为 ────────────────────────────────────────────────────────────────────
FETCH_INTERVAL=30

# ── Metrics ─────────────────────────────────────────────────────────────────
CHALLENGER_METRICS_PORT=9001

# 仅测试：随机挑战合法 game 的比例（生产必须为 0.0）
# MALICIOUS_CHALLENGE_PERCENTAGE=0.0
```

---

## 4. 启动

将编译产物和对应的 `.env` 文件放在同一目录下，直接运行：

```bash
./tz-proposer

./tz-challenger
```

通过 `RUST_LOG` 控制日志级别：

```bash
RUST_LOG=info  ./tz-proposer   # 生产推荐
RUST_LOG=debug ./tz-proposer   # 调试用
```

### systemd 示例（proposer）

```ini
[Unit]
Description=TZ Proposer
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/tz-proposer
ExecStart=/opt/tz-proposer/tz-proposer
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

---

## 5. 关键环境变量速查

### TZ 专用（proposer + challenger 共用）

| 变量 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `TZ_RPC_URLS` | ✅ | — | TZ 节点 REST API，逗号分隔，自动故障转移 |
| `TZ_ROLLUP_CONFIG_HASH` | ✅ (仅 proposer) | — | rollup config keccak256，challenger 不需要 |
| `TZ_GAME_TYPE` | — | `1961` | dispute game type ID |

### 通用（proposer + challenger 均需）

| 变量 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `L1_RPC` | ✅ | — | L1 节点 RPC |
| `L2_RPC` | ✅ | — | tz 模式下填 TZ 节点地址即可 |
| `ANCHOR_STATE_REGISTRY_ADDRESS` | ✅ | — | 合约地址 |
| `FACTORY_ADDRESS` | ✅ | — | 合约地址 |
| `PRIVATE_KEY` | ✅¹ | — | 签名私钥（本地模式） |
| `FETCH_INTERVAL` | — | `30` | 主循环间隔（秒） |
| `TX_CONFIRMATION_TIMEOUT` | — | `60` | L1 交易确认等待上限（秒） |

¹ 或使用 `SIGNER_URL`+`SIGNER_ADDRESS`（Web3Signer）/ XLayer Signer

### Proposer 专用

| 变量 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `SP1_PROVER` | ✅ | — | `network` / `cluster` / `mock` |
| `NETWORK_PRIVATE_KEY` | ✅² | — | SP1 Network 账户私钥 |
| `PROPOSAL_INTERVAL_IN_BLOCKS` | — | `1800` | 每隔多少 L2 block 提交一次 game |
| `PROPOSER_METRICS_PORT` | — | `9000` | Prometheus metrics 端口 |
| `MOCK_MODE` | — | `false` | `true` = 不生成真实证明（仅测试） |
| `FAST_FINALITY_MODE` | — | `false` | 快速最终性模式 |
| `FAST_FINALITY_PROVING_LIMIT` | — | `1` | 最大并行证明任务数 |
| `RANGE_SPLIT_COUNT` | — | `1` | range 证明拆分段数（1-16） |
| `MAX_CONCURRENT_RANGE_PROOFS` | — | `1` | 最大并行 range 证明数 |
| `TIMEOUT` | — | `14400` | 证明超时（秒，默认 4 小时） |
| `BACKUP_PATH` | — | — | 状态持久化文件路径 |

² `SP1_PROVER=network` 时必填

### Challenger 专用

| 变量 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `CHALLENGER_METRICS_PORT` | — | `9001` | Prometheus metrics 端口 |
| `MALICIOUS_CHALLENGE_PERCENTAGE` | — | `0.0` | 恶意挑战比例，**生产必须为 0.0** |

---

## 6. 验证启动成功

### Proposer 正常日志

```
INFO Proposer configuration loaded  game_type=1961 proposal_interval_in_blocks=1800 ...
INFO Valid game: adding to cache     game_index=0 l2_block=... status=...
INFO [[Proposing]]                   l2_block_number=... output_root=...
```

### Challenger 正常日志

```
INFO Challenger configuration loaded game_type=1961 ...
INFO tz: checkpoint poll             （每 60 秒后台预填 cache）
DEBUG tz: cache miss — own game, skipping rootClaim validation
```

### Metrics 检查

```bash
curl http://localhost:9000/metrics   # proposer
curl http://localhost:9001/metrics   # challenger
```

---

## 7. TZ 适配说明（与 xlayer 的主要差异）

| 行为 | xlayer | tz |
|---|---|---|
| L2 数据来源 | `eth_getBlockByNumber` RPC | `GET /chain/confirmed_block_info` REST |
| rootClaim 计算 | OP Stack output root | `keccak256(blockHash ++ stateHash)` |
| 锚点 L2 block 验证 | 对比 finalized block | **跳过**（tz 无 finalized 概念） |
| 提案触发条件 | `eth_getBlockByNumber("finalized")` | TZ confirmed checkpoint |
| cache miss 处理 | 不存在 | 自建游戏跳过 rootClaim 校验；外部游戏仍记录但不证明 |
| challenger 预填 cache | 无 | 每 60 秒后台轮询，防止 game 创建与 sync 之间的窗口期丢失 |
| metrics 中的 finalized block | 上报 | **跳过** |
