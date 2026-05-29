---
name: "tz-prove-pipeline"
description: "tz fault-proof prove 流水线：从 Witness Builder REST 异步 replay 协议拉 witness → 装配 SP1Stdin → cluster/network 生成 range + aggregation proof → 上链调用 OPSuccinctFaultDisputeGame.prove。包含 host/guest 协议不变量、replay 等待状态机、调试 escape hatch。"
---

# tz Fault-Proof Prove Pipeline

## Entry Point

`OPSuccinctProposer::prove_game(game_address, start_block, end_block)` 在 `fault-proof/src/tz/proposer.rs` —— tz feature gate 下覆盖了上游同名方法（`#[path]` 子模块继承父模块作用域）。

## Primary Entities

- `OPSuccinctFaultDisputeGame`（链上合约，cwia immutable args 包含 `startingBlockNumber()` = parent 的 `l2BlockNumber()`、当前 `l2BlockNumber()`）
- `DexState`（tz 链状态对象，msgpack 编码，含 `context.height`、`context.block_hash`、`context.app_hash`）
- `Vec<Block>`（一段连续 tz block，msgpack 编码）
- `BootInfoStruct`（range guest 的公共输出，Solidity ABI 编码 160 字节）
- `AggregationInputs` / `AggregationOutputs`
- `SP1Stdin` / `SP1ProofWithPublicValues`
- `SnapshotReplayStatus`（异步 replay 任务的服务端状态，见 [`apis/witness-builder-rpc.md`](../apis/witness-builder-rpc.md)）

## Normal Flow Steps

| Step | Action | Module |
|------|--------|--------|
| 1 | 从链上合约读出 `start_block = game.startingBlockNumber()`、`end_block = game.l2BlockNumber()` | `fault-proof/src/proposer.rs::spawn_game_proving_task` |
| 2 | 调 `prove_game(addr, start, end)` → 分发到 tz 实现 | `fault-proof/src/tz/proposer.rs::prove_game` |
| 3 | `tz_prove(start, end)` 装配 witness | tz/proposer.rs |
| 3a | `chain_client.get_dex_state_snapshot(start_block)` 内部执行异步 replay 协议（见下方"Snapshot replay 状态机"）| tz/chain_client.rs |
| 3b | 按 `TZ_BLOCKS_PER_FETCH`（默认 1000）切片，逐段 `chain_client.get_blocks_range(cur, cur+chunk-1)` | tz/chain_client.rs::get_blocks_range |
| 4 | 装配 `SP1Stdin`：`write_vec(snapshot)` → `write(chunk_count: u32)` → 重复 N 次 `write_vec(chunk_bytes)` | tz/proposer.rs::tz_prove |
| 5 | 调 `self.prover.generate_range_proof(stdin)` → cluster 或 network 路径 | fault-proof/src/prover.rs |
| 6 | 从 range proof 的 public_values 反序列化 BootInfoStruct（**`abi_decode`，不是 bincode**）| tz/proposer.rs |
| 7 | 装配 `AggregationInputs`（boot_infos[]、`latest_l1_checkpoint_head=B256::ZERO`、`multi_block_vkey=range_vk.hash_u32()`、`prover_address`）和 agg stdin（local `aggregation_stdin()` helper：`write_proof + range_vk` × N，然后 `write(&agg_inputs)`）| tz/proposer.rs |
| 8 | `self.prover.generate_agg_proof(agg_stdin)` → 通常 Plonk 包装 | prover.rs |
| 9 | `agg_proof.bytes()` 作为 `proofBytes` 调 `OPSuccinctFaultDisputeGame.prove(...)` 上链 | tz/proposer.rs::prove_game |

## Snapshot Replay 状态机（Step 3a 的展开）

服务端 snapshot 是**稀疏存储 + 按需 forward-replay** 的，host 端通过下列循环驱动：

```
                              ┌─────────────────────────────────────┐
                              │ GET /chain/dex_state_snapshot?H     │
                              └────────────┬────────────────────────┘
                                           │
                ┌──────────────────────────┼──────────────────────────────┐
                │                          │                              │
        state_available=true       state_available=false           HTTP 404
                │                  task_status.state ∈                    │
                │                  {running, finished}                    │
                ▼                          │                              ▼
        GET /chain/dex_state               │                        Permanent
        _snapshot/download                 │ sleep 5s                    bail
        ?height=H                          │ (TZ_SNAPSHOT_POLL_INTERVAL  (情况 1 or 5)
                │                          │  _SECS, 默认 5)
                │                          │
                ▼                          │
            return bytes                   └─→ 回到顶层 query
                                                (start_or_get 幂等，不重复 spawn task)

state_available=false 且 task_status.state ∈ {failed, cancelled}：
        立即 bail，log task_id + error
```

**约束**：
- 总 deadline 2h（写死，`SNAPSHOT_DEADLINE` 常量），超过即 bail
- 轮询间隔由 env `TZ_SNAPSHOT_POLL_INTERVAL_SECS` 控制，默认 5s
- 单个端点不可达时 endpoint failover（按 `TzConfig.rpc_urls` 顺序）
- 重启 host 不影响服务端 task 状态（task_id 服务端持久）；新 host 实例会用同一 height 再调一次主接口，命中已 running 的 task

详细接口规范见 [`apis/witness-builder-rpc.md`](../apis/witness-builder-rpc.md)。

## Exception Branches

| Trigger | State Change | Compensation |
|---------|-------------|-------------|
| Snapshot 永久不可用（情况 1 `requested > confirmed`、情况 5 `no snapshot ≤ requested`）| task 失败，下次 fetch_interval 重试 | 检查 server snapshot pruning 配置；可能要等 confirmed_height 推进 |
| Snapshot replay task `state=failed`（含 error message）| 立即 bail，log error；30s 后 outer loop 起新一轮 prove | 看 error message 定位（process_block panic / disk full / OOM / 等）；确定性失败再起也会 fail，可能要 patch tz-block-processor |
| Snapshot replay task `state=cancelled` | 立即 bail | 通常是运维 DELETE 触发；联系运维 |
| Snapshot replay 超过 2h 仍未完成 | bail | 几千 block 不应该需要这么久，检查服务端 / 实际 base_snapshot_height 是不是太老 |
| Block range fetch 失败 / 部分 prune | task 失败 | 检查 server `blocks_range_cap`；范围未确认时等待 confirmed_height 推进 |
| `BootInfoStruct::abi_decode` panic (`buffer overrun` / `pv_len ≠ 160`) | task 失败 | guest 提前 panic（未到 commit 行）；用 `TZ_LOCAL_EXECUTE=1` 在本地 CPU 复现 |
| range guest 内部 panic（snapshot decode / block decode / verify_next_block / process_block）| cluster 可能返回 stub proof（pv_len=0）| 同上 |
| agg guest pv_digest mismatch | agg proof 失败 | range guest 与 agg guest 必须用同一字节流编码 boot_info；当前两侧都是 `abi_encode` |
| 链上 `prove(...)` revert | tx fail | 通常是 vkey / rollup_config_hash 跟链上 immutable 对不上；查 deploy-tz 时写入的 `rangeVkeyCommitment` / `aggregationVkey` |

## Host/Guest 协议不变量

这条流水线跨越了 tradezone server / op-succinct host / SP1 zkVM guest 三方，几个隐式契约**必须**对齐：

### 1. `BootInfoStruct` 用 Solidity ABI 编码，不是 bincode

- **range guest**：`programs/tz/range/src/main.rs` `sp1_zkvm::io::commit_slice(&SolValue::abi_encode(&boot_info))`
- **agg guest 校验**：`programs/tz/aggregation/src/verify.rs` `Sha256::digest(boot_info.abi_encode())` 算 pv_digest 调 `sp1_lib::verify::verify_sp1_proof`
- **host 端**：`fault-proof/src/tz/proposer.rs` `BootInfoStruct::abi_decode(range_proof.public_values.as_slice())`
- **链上 verifier**：合约里也按 ABI 解码 agg proof 的 public values

跟非 tz 路径相反 —— 非 tz 全链路 bincode（range guest `commit(&boot_info)`、agg guest `bincode::serialize(boot_info)`、host `public_values.read()`）。任一环节漂移会引发 `buffer overrun while deserializing`（参考 commit `16ad725f`）。

### 2. Block 范围是 **(start_block, end_block]** 半开区间

- snapshot 在高度 N 处取的，等于 **block N 的 post-state**（`state.context.height == N`）
- 因此 guest 期望接收的第一个 block 高度 = `state.context.height + 1`
- host 必须从 `start_block + 1` 开始抓 blocks，到 `end_block` 结束（参考 commit `252dfece`）
- guest 端 `verify_next_block(&state, block)` 严格断言 `block.height == state.context.height + 1`，失败立即 panic

由于新版异步 replay 协议**保证** `state.context.height == requested_height`（server 会 forward-replay 到精确请求高度），这条不变量在 host 端的实现就是简单的 `start_block + 1`，不需要先反序列化 snapshot 探测真实高度。

### 3. SP1Stdin 装配顺序固定

```
SP1Stdin layout (range guest):
┌─────────────────────────────┐
│ write_vec(snapshot_bytes)   │  ← order_preserving_serde::to_msgpack 的字节
├─────────────────────────────┤
│ write(chunk_count: u32)     │  ← LE u32
├─────────────────────────────┤
│ write_vec(chunk_1_bytes)    │  ← rmp_serde::to_vec_named(Vec<Block>) 的字节
├─────────────────────────────┤
│ ... (chunk_count 个 chunk)   │
└─────────────────────────────┘
```

Guest 反序列化严格按此顺序 read。新增字段必须同时改 host + guest，且会改变 range vkey。

### 4. ELF 与 vkey 与链上配置三方对齐

- host CpuProver setup 用的 ELF（feature-gated）算出来的 vkey
- 链上 `OPSuccinctFaultDisputeGame.rangeVkeyCommitment()` immutable
- agg guest stdin 中的 `multi_block_vkey` 字段

三个值必须严格一致。任一处变化都需 `just build-tz-elfs` + `just tz-vkeys` + 更新 `contracts/config/tz/opsuccinctfdgconfig.json` + 重新部署。

→ Cluster 模式下 ELF 来源的决策见 [`decisions/ADR-011-tz-cluster-elf-routing.md`](../decisions/ADR-011-tz-cluster-elf-routing.md)。

## Diagnostics

### `TZ_LOCAL_EXECUTE=1` —— 在本地 CPU 跑一遍 range guest

`tz_prove` 在调 `generate_range_proof` 之前，会在本地用 `sp1_sdk::CpuProver` execute 一次相同的 stdin（只跑 trace，不出 proof）。

**用途**：

- cluster 返回的 proof 公共值长度异常（如 `pv_len=0`）时区分根因：
  - 本地 execute 成功 + 公共值正常 → cluster 路径出问题（artifact 缓存、版本 skew、internal mock 等）
  - 本地 execute 失败 + panic 信息明确 → guest 内部某步反序列化 / verify_next_block / process_block 失败

**启用方式**：

```bash
TZ_LOCAL_EXECUTE=1 ./target/release/tz-proposer
```

env 未设置时完全不执行（`std::env::var(...).ok().as_deref() == Some("1")`），生产路径零开销。

→ 历史引入 commit `08f10e15`。

### 公共值长度异常的解读

| 现象 | 含义 |
|---|---|
| `pv_len=0` + cluster 完成时间异常短（如 < 5s 对几千个 block） | cluster 在 mock / stub 模式，或 guest panic 被 cluster 吞掉返回 stub |
| `pv_len ≠ 160` 且 ≠ 0 | guest commit 了错的字节流（如错用 bincode），或链路上有截断 |
| `pv_len=160` 但 `abi_decode` 失败 | BootInfoStruct 字段类型/顺序漂移（tz feature 没开导致用了非 tz 的 BootInfoStruct？） |

### Snapshot replay 卡住的诊断

`get_dex_state_snapshot` 在轮询期间会每 `TZ_SNAPSHOT_POLL_INTERVAL_SECS` 秒打一条 INFO log：

```
INFO tz: snapshot replay in progress
  task_id="abc-123"
  requested_height=137000 base_snapshot_height=130000
  current_height=132500 blocks_processed=2500 total_blocks=7000
  progress_pct=35.7 blocks_per_sec=42.1 state=Running
```

- `current_height` 不动 → 服务端 process_block 卡住或挂了
- `blocks_per_sec` 异常低 → 服务端 CPU / IO 瓶颈
- `base_snapshot_height` 比预期低很多 → 服务端最近的 snapshot 也很旧，需要 replay 大量 block；可以推动 tradezone 端增加 snapshot 频率

### vkey 对齐自检

启动时打印：

```
tz: loaded identity from on-chain game implementation
  rollup_config_hash=0x000...
  on_chain_agg_vkey=0x...
  on_chain_range_vkey=0x...
```

如果链上 vkey 跟 `just tz-vkeys` 本地算出的 vkey 不一致，说明：
- 链上 game implementation 不是本次 ELF 部署的版本
- 或 ELF 没用 `--features tz` 重 build（cluster_setup_keys 会落到 ethereum elf 上）

## Flow-Specific Pitfalls

- 跨进程 ELF 版本必须一致 —— host build、链上配置、tradezone 端 block 序列化（rmp_serde / order_preserving_serde）三方都受 x2 git rev 影响。bump x2 rev 之后必须重 build ELF + 重 deploy 合约 + 重启服务，缺一不可。
- agg proof 模式默认 Plonk，链上 verifier 必须接 Plonk verifier 地址（`contracts/config/tz/opsuccinctfdgconfig.json::verifierAddress`）。
- cluster artifact 缓存按 `(vkey, stdin_hash)` 索引；测试中反复用同一份 stdin 可能命中旧 proof。redis 清缓存：`docker exec infra-redis-1 redis-cli -a redispassword FLUSHDB`。
- snapshot replay 任务**不主动 cancel**。即使 prove task 被 outer loop 替换，旧的服务端 replay 仍会跑完（artifact 会被缓存，下次 prove 同一 height 直接命中）。

## 相关引用

- [`apis/witness-builder-rpc.md`](../apis/witness-builder-rpc.md) — `/chain/dex_state_snapshot` async replay 协议 + `/chain/blocks` 接口规范
- [`decisions/ADR-011-tz-cluster-elf-routing.md`](../decisions/ADR-011-tz-cluster-elf-routing.md) — cluster mode 下 TZ_RANGE_ELF / TZ_AGGREGATION_ELF 的 feature-gated 路由
- [`pitfalls/tradezone-zkvm-time-leaks.md`](../pitfalls/tradezone-zkvm-time-leaks.md) — x2 升级时 zkvm 时间 syscall 漏修复审计
- [`pitfalls/tz-binaries.md`](../pitfalls/tz-binaries.md) — tz-proposer/tz-challenger 二进制 env 耦合
- [`pitfalls/tz-cache.md`](../pitfalls/tz-cache.md) — `TzChainClient` 内存 checkpoint 缓存的同步 Mutex 约定
- [`decisions/ADR-009-tz-phase-1-vkey-suppression.md`](../decisions/ADR-009-tz-phase-1-vkey-suppression.md) — Phase 1 vkey 抑制
- [`core-flows/aggregation-proof.md`](./aggregation-proof.md) — 通用 aggregation guest 流程（tz agg guest 在 pv_digest 算法上不同 —— ABI 不是 bincode）
