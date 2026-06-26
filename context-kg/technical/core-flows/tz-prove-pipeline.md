---
name: "tz-prove-pipeline"
description: "tz fault-proof prove 流水线：把 (start, end] 切成 N (1–16) 段 sub-range，每段从 Witness Builder REST 异步 replay 协议拉 witness → 装配 SP1Stdin → 并发生成 range proof，按 idx 重排后用 N 份 boot_info 聚合成单份 aggregation proof → 上链调用 OPSuccinctFaultDisputeGame.prove。包含 host/guest 协议不变量、replay 等待状态机、调试 escape hatch。N=1 时与旧单段路径字节等价。"
---

# tz Fault-Proof Prove Pipeline

## Entry Point

`OPSuccinctProposer::prove_game(game_address, start_block, end_block)` 在 `fault-proof/src/tz/proposer.rs` —— tz feature gate 下覆盖了上游同名方法（`#[path]` 子模块继承父模块作用域）。

## Primary Entities

- `OPSuccinctFaultDisputeGame`（链上合约，cwia immutable args 包含 `startingBlockNumber()` = parent 的 `l2BlockNumber()`、当前 `l2BlockNumber()`）
- `DexState`（tz 链状态对象，msgpack 编码，含 `context.height`、`context.block_hash`、`context.app_hash`）
- `Vec<Block>`（一段连续 tz block，msgpack 编码）
- `BootInfoStruct`（range guest 的公共输出，Solidity ABI 编码 160 字节）—— multi-range 下每个 sub-range 产出一个，聚合时按 idx 排成 `Vec`
- `RangeSplitCount`（`config.rs`，1–16，`split(start, end) → Vec<(s_i, e_i)>` 连续无缝切分，INV-2a）
- `AggregationInputs`（`boot_infos: Vec`，长度 = N）/ `AggregationOutputs`
- `SP1Stdin` / `SP1ProofWithPublicValues`
- `SnapshotReplayStatus`（异步 replay 任务的服务端状态，见 [`apis/witness-builder-rpc.md`](../apis/witness-builder-rpc.md)）

## Normal Flow Steps

自 PRF-49（ADR-012）起，prove 路径是 **multi-range**：`tz_prove` 把 `(start, end]` 切成 N (1–16) 段，
对每段并发调用 per-sub-range 子例程 `tz_range_proof`，再用 N 份 boot_info 聚合成单份 agg proof。
形态镜像 generic 非-tz `prove_game`（`proposer.rs:1240-1262`），但保留 tz 专属的 Solidity-ABI decode。
N=1 时退化为单段，与旧路径字节等价（INV-1a/1b）。

### tz_prove 编排（FR-1）

| Step | Action | Module |
|------|--------|--------|
| 1 | 从链上合约读出 `start_block = game.startingBlockNumber()`、`end_block = game.l2BlockNumber()` | `fault-proof/src/proposer.rs::spawn_game_proving_task` |
| 2 | 调 `prove_game(addr, start, end)` → 分发到 tz 实现；读 `game.l1Head()` 作 `game_l1_head` | `fault-proof/src/tz/proposer.rs::prove_game` |
| 3 | `tz_prove(start, end, game_l1_head)`：`config.range_split_count.split(start, end)` → N 段 `Vec<(s_i, e_i)>`（INV-2a 连续无缝）；log `tz: proving over {N} sub-range(s)` | tz/proposer.rs::tz_prove |
| 4 | 每段一个 future（`self.clone()` per task）；`stream::iter(tasks).buffer_unordered(min(max_concurrent_range_proofs, N)).try_collect()` 并发执行 `tz_range_proof`（见下方子例程）| tz/proposer.rs::tz_prove |
| 5 | 收集 `(idx, SP1ProofWithPublicValues, BootInfoStruct)`，按 `idx` 重排成有序 `proofs[N]` / `boot_infos[N]`（`ok_or_else` → 缺段返 `Err`，**不 panic**）| tz/proposer.rs::tz_prove |
| 6 | 装配 `AggregationInputs { boot_infos: N 个, latest_l1_checkpoint_head: game_l1_head, multi_block_vkey: range_vk.hash_u32(), prover_address }`；agg stdin 经 local `aggregation_stdin()` helper（`write_proof + range_vk` × N，然后 `write(&agg_inputs)`；非 Compressed 变体 → `Err`）| tz/proposer.rs::aggregation_stdin |
| 7 | log `tz: generating aggregation proof`；`self.prover.generate_agg_proof(agg_stdin)` → 通常 Plonk 包装 | prover.rs |
| 8 | `agg_proof.bytes()` 返回调用方 `prove_game`，作为 `proofBytes` 调 `OPSuccinctFaultDisputeGame.prove(...)` 上链 —— **单笔 tx**，经 `SignerLock` 串行化 nonce | tz/proposer.rs::prove_game |

**并发 / 失败语义**：任一 sub-range future resolve 为 `Err` → `try_collect` 整体 abort：(a) `tz_prove` 返 `Err`；(b) 尚未启动的 future 不再 poll；(c) in-flight future 被 drop（远端 cleanup 不保证，依赖 server-side timeout）；(d) 不上链，下次 tick 重 spawn。并发 sub-range future **不**各自取 signer——只有 Step 8 的 agg-submit 取（KG concurrency [Pitfall]）。

### tz_range_proof 单段子例程（FR-2，每段执行一次）

| Step | Action | Module |
|------|--------|--------|
| R-1 | `l2_provider.fetch_dex_state_snapshot(start_i)` 内部执行异步 replay 协议（见下方"Snapshot replay 状态机"）—— snapshot@start_i = block `start_i` 的 post-state | tz/l2_provider.rs / chain_client.rs |
| R-2 | 半开区间 `(start_i, end_i]`：first = `start_i + 1`，`total = end_i - start_i`，`chunk_count = ceil(total / TZ_BLOCKS_PER_FETCH)`（默认 1000）；逐 chunk `fetch_blocks_range(cur, chunk_end)` | tz/l2_provider.rs::fetch_blocks_range |
| R-3 | 装配 `SP1Stdin`：`write_vec(snapshot)` → `write(chunk_count: u32)` → 重复 `chunk_count` 次 `write_vec(chunk_bytes)` | tz/proposer.rs::tz_range_proof |
| R-4 | `TZ_LOCAL_EXECUTE=1` 时先本地 CPU `execute(range_elf, stdin)`（诊断，见 Diagnostics）| tz/proposer.rs::tz_range_proof |
| R-5 | `self.prover.generate_range_proof(stdin)` → cluster 或 network 路径，得 compressed range proof | fault-proof/src/prover.rs |
| R-6 | `BootInfoStruct::abi_decode(range_proof.public_values.as_slice())`（**`abi_decode`，不是 bincode**）；返回 `(SP1ProofWithPublicValues, BootInfoStruct)` | tz/proposer.rs::tz_range_proof |

> **N 倍 fetch**：N 段切分 = N 次 `fetch_dex_state_snapshot` + N 次 `fetch_blocks_range`，adjacent 段之间**不复用** snapshot 缓存。小 state（e2e 实测 1.3 KB）开销可忽略；大 state（≥ 数 GB）下 N 增大会放大网络 / 反序列化峰值——运维通过调小 `RANGE_SPLIT_COUNT` / `MAX_CONCURRENT_RANGE_PROOFS` 缓解（无运行时自适应保护）。

## Snapshot Replay 状态机（Step R-1 的展开）

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
- **multi-range link_check 只在 N≥2 才暴露 INV-2b 破坏**：agg guest `link_check.rs` 对 `boot_infos.windows(2)` 断言 `prev.l2PostRoot == curr.l2PreRoot`。N=1 时 `windows(2)` 不触发，host snapshot RPC 编码 ↔ guest 反序列化 / `blake3_hash_state` 的任何字节漂移看不见；N≥2 切分后 link_check 才真正校验这条跨进程不变量。改 snapshot codec 或 guest deserialize/hash 任一侧 → N≥2 时 `link_check` 必 panic（pre-existing 依赖，无新协同机制）。
- **重排 bug → boot_infos 乱序/缺段 → agg guest `link_check` panic**：`tz_prove` 用 `vec![None; N]` + idx-assign + `ok_or_else` 重排；缺段返 `Err`（不 panic），但若重排逻辑错误把不连续 boot_infos 喂给 agg，execute/verify 失败、proposer 视为 prove 失败重试。

## 相关引用

- [`apis/witness-builder-rpc.md`](../apis/witness-builder-rpc.md) — `/chain/dex_state_snapshot` async replay 协议 + `/chain/blocks` 接口规范
- [`decisions/ADR-011-tz-cluster-elf-routing.md`](../decisions/ADR-011-tz-cluster-elf-routing.md) — cluster mode 下 TZ_RANGE_ELF / TZ_AGGREGATION_ELF 的 feature-gated 路由
- [`pitfalls/tradezone-zkvm-time-leaks.md`](../pitfalls/tradezone-zkvm-time-leaks.md) — x2 升级时 zkvm 时间 syscall 漏修复审计
- [`pitfalls/tz-binaries.md`](../pitfalls/tz-binaries.md) — tz-proposer/tz-challenger 二进制 env 耦合
- [`pitfalls/tz-cache.md`](../pitfalls/tz-cache.md) — `TzChainClient` 内存 checkpoint 缓存的同步 Mutex 约定
- [`decisions/ADR-009-tz-phase-1-vkey-suppression.md`](../decisions/ADR-009-tz-phase-1-vkey-suppression.md) — Phase 1 vkey 抑制
- [`core-flows/aggregation-proof.md`](./aggregation-proof.md) — 通用 aggregation guest 流程（tz agg guest 在 pv_digest 算法上不同 —— ABI 不是 bincode）
- [`decisions/ADR-012-tz-prove-parallel-not-unified.md`](../decisions/ADR-012-tz-prove-parallel-not-unified.md) — 为何 `tz_prove` 与 generic `prove_game` 保持平行实现、不经 trait 统一（multi-range pipeline 的设计决策）
- [`conventions/env-vars.md`](../conventions/env-vars.md) — `RANGE_SPLIT_COUNT` / `MAX_CONCURRENT_RANGE_PROOFS` / `TZ_BLOCKS_PER_FETCH` / `TZ_LOCAL_EXECUTE` 等 tz prove-path env 参考
