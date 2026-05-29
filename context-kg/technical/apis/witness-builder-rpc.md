---
name: "witness-builder-rpc"
description: "Witness Builder REST API — proposer/challenger 端从 tradezone L2 拉 SP1 prove witness（DexState 快照 + Block 范围）的接口规范。采用 query → async replay → download 的异步协议，与通用 tradezone-rpc.md 分离，便于独立迭代。"
sources:
  - "tradezone/crates/chain/src/rpc/routes/zkvm_snapshot.rs"
  - "tradezone/crates/chain/src/rpc/routes/chain.rs"
  - "tradezone/crates/chain/src/rpc/handlers/zkvm_snapshot.rs"
  - "tradezone/crates/chain/src/rpc/handlers/chain.rs::query_blocks"
  - "tradezone/crates/chain/src/rpc/snapshot_replay.rs"
  - "fault-proof/src/tz/chain_client.rs"
updated_at: "2026-05-29"
---

# Witness Builder REST API

为 op-succinct 的 tz-proposer / tz-challenger 提供 SP1 range guest 所需的执行 witness：

1. **DexState snapshot**（特定高度的 tz 链状态二进制快照）—— 一个异步 replay 协议（4 个端点）
2. **Block range**（一段连续 block 的二进制序列）—— 单端点

由于服务端 snapshot 是稀疏存储（每隔若干 block 才落盘一份），任意请求高度大概率没有现成的 snapshot —— 服务端按需 forward-replay 出一份新的，**异步**进行。所以 snapshot 取值要走 "**查 → 等 → 下载**" 三步。

这部分跟通用 `tradezone-rpc.md` 中其它端点设计取舍不同（异步 / 任务化 / 进度可查），且只服务 ZKP 链路，会跟随 host/guest 协议独立迭代，所以拆成独立一篇。

---

## 通用约定

### 协议

- HTTP/HTTPS
- 路由前缀：无（挂在根路径下）
- 路由文件：`tradezone/crates/chain/src/rpc/routes/zkvm_snapshot.rs`（snapshot 4 个端点）、`tradezone/crates/chain/src/rpc/routes/chain.rs`（blocks 端点）

### 响应封装

**查询类端点**（`/chain/dex_state_snapshot`、`/chain/dex_state_snapshot/tasks/{task_id}`、`/chain/blocks` 的错误响应）走 `tradezone-rpc.md` 中定义的统一 envelope：

```json
{ "code": 0, "message": "OK", "block": null, "data": { ... } }
```

**字节流类端点**（`/chain/dex_state_snapshot/download`、`/chain/blocks` 的成功响应）返回 raw `application/x-msgpack` body，**不**包裹 envelope。错误时回退到 envelope JSON。

### 序列化约定

| 字节流端点 | 编码 | 模块 |
|------|------|------|
| `/chain/dex_state_snapshot/download` | `tz_dex::order_preserving_serde::to_msgpack` | `tradezone/crates/dex/src/order_preserving_serde.rs` |
| `/chain/blocks` | `rmp_serde::to_vec_named` | `tradezone/crates/chain/src/rpc/handlers/chain.rs` |

**编码不对称**：
- snapshot 用自定义 order-preserving msgpack（保持 Slab free-list 顺序，guest 端必须用同一模块的 `from_msgpack` 解）
- blocks 用 rmp_serde 默认的 named-map 编码（字段名作为 key），guest 端用 `rmp_serde::from_slice`，serde 自动 derive 的 Deserialize 同时兼容 map 和 array 形式

---

## 1. DexState 快照（异步 replay 协议）

### 1.1 GET /chain/dex_state_snapshot

**功能描述**：查询某高度的 DexState 快照可用性。**触发**异步 replay（如果该高度还没现成 artifact）。本端点是整个 snapshot 协议的入口。

**Query Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| height | u64 | Y | 请求的快照高度 |

**5 种返回情况**

| # | 场景 | HTTP | envelope `code` | `data.state_available` | `data.task_id` |
|---|---|---|---|---|---|
| 1 | `requested > confirmed` | 404 | 10004 | — | — |
| 2 | 盘上正好有 `height=H` 的 snapshot | 200 | 0 | `true` | `null` |
| 3 | 之前 replay 过，artifact 缓存命中 | 200 | 0 | `true` | `null` |
| 4 | 盘上只有 `< H` 的 snapshot —— 启动后台 replay | 200 | **10004** | `false` | `"<task-id>"` |
| 5 | 一个 `≤ H` 的 snapshot 都没有 | 404 | 10004 | — | — |

情况 4 是 HTTP 200 但 envelope code = `10004`（CODE_RESOURCE_NOT_FOUND），调用方**不能仅看 HTTP 状态或 envelope code 判断成功**，必须**看 `data.state_available` flag**。

情况 2 和 3 对调用方没有区别 —— 都是 download 就行。`data.base_snapshot_height` 在情况 2 中等于 `requested_height`、情况 3 中可能小于（artifact 的 forward-replay 起点），用作诊断 log，不影响后续逻辑。

**`data` 字段（`DexStateSnapshotResponse`）**

| 字段 | 类型 | 说明 |
|------|------|------|
| stateAvailable | bool | true → 可立刻 download；false → 需要轮询 |
| requestedHeight | u64 | 回显请求高度 |
| confirmedHeight | u64 | 服务端当前确认高度 |
| baseSnapshotHeight | u64 | 实际数据所在/起源的高度；情况 4 中是 forward-replay 的起点 |
| taskId | string \| null | 仅情况 4 出现，标识后台 replay 任务 |
| taskStatus | object \| null | 仅情况 4 出现，见 `SnapshotReplayStatus` 字段说明 |

**`taskStatus` 字段（`SnapshotReplayStatus`）**

| 字段 | 类型 | 说明 |
|------|------|------|
| taskId | string | 与外层 taskId 相同 |
| state | enum | `"running"` \| `"finished"` \| `"failed"` \| `"cancelled"` |
| requestedHeight | u64 | task 目标高度 |
| baseSnapshotHeight | u64 | replay 起点 |
| currentHeight | u64 | 当前已 replay 到的高度 |
| totalBlocks | u64 | 需 replay 的 block 总数 |
| blocksProcessed | u64 | 已 replay 的 block 数 |
| progressPct | f64 | 进度百分比 0–100 |
| blocksPerSec | f64 \| null | 实时速率（null 表示刚开始还没数据点） |
| artifact | object \| null | task 完成后填充，含 path / sha256 / size |
| error | string \| null | task failed 时填充 |
| startedAt | string | RFC 3339 timestamp |
| finishedAt | string \| null | RFC 3339 timestamp，task 终止后填充 |

**响应示例（情况 2/3 —— state ready）**

```json
{
  "code": 0,
  "message": "OK",
  "block": null,
  "data": {
    "stateAvailable": true,
    "requestedHeight": 137000,
    "confirmedHeight": 138521,
    "baseSnapshotHeight": 137000,
    "taskId": null,
    "taskStatus": null
  }
}
```

**响应示例（情况 4 —— replay 中）**

```json
{
  "code": 10004,
  "message": "exact DexState snapshot at height 137000 is not ready; async replay task abc-123 was created or reused, poll /chain/dex_state_snapshot/tasks/abc-123",
  "block": null,
  "data": {
    "stateAvailable": false,
    "requestedHeight": 137000,
    "confirmedHeight": 138521,
    "baseSnapshotHeight": 130000,
    "taskId": "abc-123",
    "taskStatus": {
      "taskId": "abc-123",
      "state": "running",
      "requestedHeight": 137000,
      "baseSnapshotHeight": 130000,
      "currentHeight": 132500,
      "totalBlocks": 7000,
      "blocksProcessed": 2500,
      "progressPct": 35.7,
      "blocksPerSec": 42.1,
      "artifact": null,
      "error": null,
      "startedAt": "2026-05-29T03:12:00Z",
      "finishedAt": null
    }
  }
}
```

**响应示例（情况 1/5 —— 永久不可用）**

```json
// 情况 1
{ "code": 10004, "message": "requested_height=137000 > confirmed_height=130000", "data": null }

// 情况 5b（有更早但没 ≤ H 的）
{ "code": 10004, "message": "no snapshot available at or before height 137000, earliest_available_snapshot_height=140000", "data": null }
```

**Note**：`start_or_get` 在服务端是**幂等**的 —— 同一 height 多次调用主接口只会生成一个 task，后续调用复用同一 task_id。重复查询无副作用，可作为轮询入口（见下文 1.4）。

---

### 1.2 GET /chain/dex_state_snapshot/download

**功能描述**：下载某高度的 DexState msgpack 字节流。**仅当 `state_available=true` 时**可用；否则返回 404，提示客户端先调 1.1 触发 / 等待 replay。

**Query Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| height | u64 | Y | 与 1.1 调用过的同一 height |

**成功响应**

- HTTP 200
- Content-Type: `application/x-msgpack`
- Body: `order_preserving_serde::to_msgpack(&dex_state)` 字节流；解到 `tz_dex::DexState` 后 **`state.context.height == requested_height`**（无论 base 是 H 还是 < H，server 都已 forward-replay 到 H）

**调用方契约**

> Host 端调用顺序必须是 1.1 → (轮询 1.1) → 1.2。直接调 1.2 在 cold start 时会 404，因为 replay 任务还没启动。

**错误响应（404）**

```json
{
  "code": 10004,
  "message": "DexState snapshot at height 137000 is not ready; call /chain/dex_state_snapshot?height=137000 to create or reuse replay task",
  "data": null
}
```

---

### 1.3 GET /chain/dex_state_snapshot/tasks/{task_id}

**功能描述**：查询某个 replay 任务的实时状态。**对 host 端不是必须的端点** —— 1.1 主接口返回值里已含完整 `taskStatus`，重复调 1.1 同样能拿到进度。该端点存在的意义是只读、不触发任何状态变化（不会 `start_or_get`），可用于运维/监控。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| task_id | string | Y | 1.1 返回的 task_id |

**响应**：envelope.data 为 `SnapshotReplayStatus`（结构见 1.1）。

**错误**：task_id 未知 → 404；任务已被 GC → 404。

---

### 1.4 DELETE /chain/dex_state_snapshot/tasks/{task_id}

**功能描述**：取消正在运行的 replay task。

**Path Params**：同 1.3。

**响应**

```json
{
  "code": 0,
  "message": "OK",
  "data": {
    "taskId": "abc-123",
    "status": { ... SnapshotReplayStatus with state="cancelled" ... }
  }
}
```

**调用方契约**

> 当前 tz-proposer **不主动 cancel**（在 prove 任务被打断时也是任其自然完成 —— 服务端有自己的 GC 节奏）。这个端点保留给运维场景。

---

## 2. Block 范围

### 2.1 GET /chain/blocks

**功能描述**：返回 `[start, end]` 闭区间内的 Block 列表。SP1 range guest 顺序 replay 这些 block 推进 DexState。

**Query Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| start | u64 | Y | 起始高度（包含） |
| end | u64 | Y | 终止高度（包含） |

**关键行为**

- 必须 `start ≤ end`，否则 400 `"invalid range: start must be <= end"`
- 单次请求上限 `blocks_range_cap`（默认 1024）
- 必须 `end ≤ confirmed_height`，否则 404 `"range not fully confirmed"`
- 若部分 block 已被剪枝 → 404 `"blocks pruned: earliest_available_block_height=<N>"`

**成功响应**

- HTTP 200
- Content-Type: `application/x-msgpack`
- Body: `rmp_serde::to_vec_named(&blocks)`（`Vec<Block>`）

**Host 端使用规范**

> Host 把 1.2 和 2.1 拉回来的 bytes 直接 `SP1Stdin::write_vec(...)` 喂给 range guest，**不做反序列化**。
> Host 端 chunking 策略（按 `TZ_BLOCKS_PER_FETCH` env，默认 1000）只影响 2.1 接口的并发调用，对 guest 透明。
> 区间是 **`(snapshot_height, end_block]`**：因为 snapshot 是 `snapshot_height` 这一 block 的 *post-state*，所以从下一个 block 开始 replay。

---

## Host 端集成模式

详细 host 状态机和踩坑见 [`core-flows/tz-prove-pipeline.md`](../core-flows/tz-prove-pipeline.md)。简版：

1. `fault-proof/src/tz/chain_client.rs::get_dex_state_snapshot(height)` 封装 1.1 + 1.2 全部状态机：
   - 调 1.1
   - 若 `state_available=true` → 调 1.2 → 返回字节流
   - 若 `state_available=false` 且 `task_status.state=running|finished` → 等 `TZ_SNAPSHOT_POLL_INTERVAL_SECS` 秒（默认 5）→ 回到第一步
   - 若 `task_status.state=failed|cancelled` → 立即 bail 抛 anyhow error（log task_id + error）
   - 总 deadline 2h（写死）— 超过即 bail

2. tz-proposer 的 `tz_prove(start_block, end_block)` 调用：
   - `chain_client.get_dex_state_snapshot(start_block)` —— 一行，内部含异步 replay 等待
   - `chain_client.get_blocks_range(start_block + 1, end_block)` —— 按 chunk 切分多次调

3. 失败重试由上层 prove task 30s/轮 outer loop 处理；`tz_prove` 内部不重试。

---

## 与 Phase 2 演进相关的版本契约

服务端 `tz-block-processor` / `tz-dex` 库的版本（x2 git rev）跟 op-succinct 端 ELF 编译用的 x2 rev **必须一致** —— DexState/Block 字段或 msgpack 编码任一漂移都会改 range vkey。

x2 rev bump 后流程：
1. tradezone 端发版
2. op-succinct 端 `Cargo.toml` bump x2 rev
3. `just build-tz-elfs`
4. `just tz-vkeys` 拿到新 vkey
5. 更新 `contracts/config/tz/opsuccinctfdgconfig.json::rangeVkeyCommitment` / `aggregationVkey`
6. 重 deploy `deploy-tz.sh`

→ 决策细节见 [`decisions/ADR-011-tz-cluster-elf-routing.md`](../decisions/ADR-011-tz-cluster-elf-routing.md)。

---

## 相关引用

- [`tradezone-rpc.md`](./tradezone-rpc.md) — tz 链通用 REST API（envelope 定义、错误码、其它端点）
- [`core-flows/tz-prove-pipeline.md`](../core-flows/tz-prove-pipeline.md) — host/guest 协议、replay 状态机、轮询/超时策略
- [`decisions/ADR-011-tz-cluster-elf-routing.md`](../decisions/ADR-011-tz-cluster-elf-routing.md) — cluster mode 下 TZ ELF 路由
- [`pitfalls/tradezone-zkvm-time-leaks.md`](../pitfalls/tradezone-zkvm-time-leaks.md) — x2 升级时 zkvm 时间 syscall 漏修复审计
