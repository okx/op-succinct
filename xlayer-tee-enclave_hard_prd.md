# PRD: xlayer-tee-enclave —— 在 Nitro Enclave 内重放 L2 并对 RangeJournal 签名

> 关联 Epic：XLOP-1059 ｜ Task：XLOP-1061 ｜ 设计文档：https://okg-block.sg.larksuite.com/docx/G82LdCJ8joDn6WxQJRllP6s0gwc （§5.1 / §6.1）
> 定位：**as-built 需求定档**。本 PRD 以 `tee/enclave/src/` 现有实现为准，将设计文档与 Jira 验收标准固化为正式需求与验收依据。

## 0. Summary

- **Goal**：在 AWS Nitro Enclave 内运行 kona 派生与 EVM 执行，独立重算单个 range 的 output root，重算通过后对 6 字段 `RangeJournal` 产出 65 字节 secp256k1 签名，并以 NSM attestation 暴露签名公钥——构成与 ZK 完全独立的 fault-proof 可信路径的叶子（leaf）签发端。
- **Not doing**：本迭代不做多 range 聚合（聚合在 SP1 aggregation 电路内完成，见 §5.4，非本 crate 范围），不做链上验证，不做 host 协调层。
- **Top risk**：默认 build（TCP + 硬编码 dev key + 占位 attestation）若被误部署到生产，将以可公开签名的 Anvil #0 私钥对外签名 `[Repo: tee/enclave/src/keys.rs:26]`；缓解措施为编译期严格区分 build 模式（仅 `--features vsock` 走真 NSM 路径）。
- **Current blockers**：`None`

## 1. Background

### 1.1 Current system description

**Module**：`tee/enclave`（crate `xlayer-tee-enclave`）—— 运行在 Nitro Enclave 内的 ELF 实体，对外仅暴露 vsock 一条通路（无网络、无持久化磁盘）。

X Layer 是基于 OP Stack 的 L2，其安全模型依赖 fault proof：当有人提交错误的 L2 状态时，挑战者可在 L1 发起 dispute game 推翻。当前主流 ZK 路径存在电路 bug 与 vkey 治理两类工程风险，X Layer 因此引入一条与 ZK 完全独立、仅依赖 AWS Nitro 硬件信任根与 enclave 镜像度量（PCR0）的可信路径，作为 fault proof 的第二条 game type `[设计文档 §2.1]`。

enclave 在该路径中承担两件事：①调用 op-succinct/kona 重放执行一段 L2（`replay.rs` → `ETHDAWitnessExecutor::run`）`[Repo: tee/enclave/src/replay.rs:31]`；②对 packed `RangeJournal` 做 `keccak256` 后 secp256k1 prehash 签名（`signing.rs`）`[Repo: tee/enclave/src/signing.rs:15]`。数据流单向：进的只有 host 投递的 witness 字节，出的只有签名 + attestation；签名私钥 `ENCLAVE_KEY` 由 NSM 熵生成，私钥永不跨边界，仅通过 attestation 暴露公钥 `[Repo: tee/enclave/src/keys.rs:50]`。

enclave 采用「POST 立即返回 + GET 轮询 + DELETE 取消」的异步任务模型：单 range 悲观耗时 5~15 分钟，长 HTTP keep-alive 易被中间设备断开，异步语义更适配失败重投、运维 kill、多 enclave 路由 `[设计文档 §A.2]`。任务核心在 `task_manager.rs`（注册表、并发上限、UUID 幂等、协作式取消）`[Repo: tee/enclave/src/task_manager.rs:127]`。

### 1.2 Problem

这是一条新建的可信路径，无既有 enclave 实现可复用其形态（base 的 TEE 路径在任务粒度、执行引擎、协议、聚合位置上均不满足需求，见设计文档附录 A）。需要一个**确定性、隔离、可并发、最小信任面**的 enclave，满足：

- 同 witness + 同 `ENCLAVE_KEY` 必须产出同一签名（聚合电路需可复算）。
- 信任面尽可能小（任何进入 PCR0 度量范围的代码都会扩大攻击面），因此聚合不在 enclave 内做，且直接依赖上游 crate 而非再包一层封装 `[设计文档 §3.2 / §A.3]`。
- 同一份 EIF 不固化任何特定 L2 链身份，可服务多条 L2 `[Repo: tee/enclave/src/main.rs:15]`。

## 2. Business goals

- **G-1**：提供与 ZK 独立的 TEE 单 range 签名能力——enclave 内独立重算 output root，重算通过后对 `RangeJournal` 产出可被聚合电路 ecrecover 校验的 65 字节 secp256k1 签名。
- **G-2**：最小化信任面与隔离边界——无网络、无磁盘；`ENCLAVE_KEY` 私钥永不出 enclave，仅通过 NSM attestation 暴露公钥；不在 enclave 内做聚合。
- **G-3**：提供异步、可并发、可取消、幂等的任务接口，供 host 托管单 range 任务的完整生命周期。
- **G-4**：跨链复用——同一份 EIF 通过 witness 携带的 rollup config 自算 configHash，可服务多条 L2，无需重新度量。
- **G-5**：编译期严格区分 dev / 生产 build，避免 dev 路径被误部署到生产时不报错。

## 3. Scope

### 3.1 In-Scope（本 crate 交付）

- FR-1：单 range kona 重放并对 `RangeJournal` 签名
- FR-2：output root 重算不一致时拒签（ClaimMismatch）
- FR-3：异步任务模型与生命周期状态机（POST/GET/DELETE/list + UUID 幂等 + 协作式取消）
- FR-4：并发上限与背压（TooManyTasks / 429）
- FR-5：请求体上限（256 MiB / 413）
- FR-6：`ENCLAVE_KEY` 管理与 NSM attestation（dev / vsock 双 build 模式）
- FR-7：终态任务 TTL 回收（GC）
- FR-8：wire 接口契约与错误码映射

### 3.2 Out-of-Scope（本迭代不做）

- 多 range 的 SP1 aggregation 聚合与 attestation 链上验证（属 `programs/aggregation`，见设计文档 §5.4，非本 crate）。
- host 协调层（协议转换、容量平滑、proofBytes 打包）属 `tee/host`（XLOP 另一 Task）。
- proposer 的 witness 生成、调度、上链（op-succinct fork）。
- 不在 enclave 内固化任何 L2 链 id；不引入 EIP-712 域分离（签名摘要直接为 `keccak256(packed 168B)`）。
- 不做 enclave 内多 range 聚合 / 两层签名（刻意收窄信任面）。
- enclave **不**产出 proposer-facing 数字码（0 / 10001 / 10004 / 20001）；enclave 仅输出 `ErrorKind`（PascalCase）+ HTTP 状态码，由 host 将其折叠为 proposer 数字码 `[设计文档 §7.4]`、`[Repo: tee/types/src/error.rs:84]`。

## 4. Functional requirements

### FR-1：单 range kona 重放并对 RangeJournal 签名

**Business rules**：
- enclave 不连外网；唯一输入为 host 经 `POST /tasks/range` 投递的 rkyv 序列化 `DefaultWitnessData` 字节 `[Repo: tee/enclave/src/witness.rs:10]`。
- pipeline 顺序固定：反序列化 witness → `BootInfo::load` + 边界检查（`claimed_l2_block_number > 0`，否则 InvalidRangeBounds）→ kona 派生与 EVM 执行（`ETHDAWitnessExecutor::run`）→ 签名 `[Repo: tee/enclave/src/runner.rs:19]`。
- 签名对象为 6 字段 `RangeJournal`：`pcr0`、`configHash`、`l1OriginHash`、`l2BlockNumber`、`prevOutputRoot`、`outputRoot`，按 168 字节大端序打包；其中 `configHash` 取 op-succinct-client-utils 上游规范函数 `hash_rollup_config(boot.rollup_config)` 的输出（journal 的 configHash 以该函数为唯一规范定义，本 PRD 不再另行声称其等价于 `keccak256(serde_json(...))`）、`l1OriginHash = boot.l1_head`、`prevOutputRoot = boot.agreed_l2_output_root`、`outputRoot = 重算结果` `[Repo: tee/enclave/src/runner.rs:45]`。
- 签名摘要 `= keccak256(packed 168B)`，算法 secp256k1 ECDSA，输出 65 字节 `r‖s‖v`，`v ∈ {27,28}`（recovery id + 27）`[Repo: tee/enclave/src/signing.rs:13]`。
- 链身份不固化在 ELF 内：`configHash` 由 enclave 对 witness 携带的 rollup config 自算并签入 journal，同一份 EIF 可服务多条 L2 `[Repo: tee/enclave/src/main.rs:15]`。

**Acceptance Criteria**（失败/终态语义统一遵循 FR-8 的双面错误模型）：
- Given 一份合法 witness 且重算 output root 与 witness 声称的 claim 一致，When 任务到达终态后 `GET /tasks/{id}`，Then 返回 HTTP 200 且 `status = Finished`，其中签名为 65 字节、`v ∈ {27,28}`，对 `keccak256(packed RangeJournal)` 做 ecrecover 得到的地址等于 enclave 公钥地址。
- Given witness 的 `claimed_l2_block_number == 0`，When `POST /tasks/range`，Then POST 返回 201（任务被接受）；任务在进入 `RunningKona` 之前转为终态，`GET /tasks/{id}` 返回 HTTP 200 且 `status = Failed`、`kind = InvalidWitness`（内部 `InvalidRangeBounds`），无签名。
- Given 两份内容相同的 witness 由同一 enclave 实例签名，When 分别完成，Then 两次签名一致（确定性）。

**Traceability**：implements G-1、G-4

### FR-2：output root 重算不一致时拒签（ClaimMismatch）

**Business rules**：
- enclave 仅在「独立重算的 output root == witness 内 `claimed_l2_output_root`」时才签名；不一致则拒签 `[设计文档 §3.1]`。
- 一致性由 op-succinct `WitnessExecutor::run` 内部断言（mismatch 时报 "Failed to validate L2 block"），enclave 将其映射为结构化的 ClaimMismatch 错误 `[Repo: tee/enclave/src/replay.rs:66]`。

**Acceptance Criteria**：
- Given 重算 output root 与 witness 声称值不一致，When 任务到达终态后 `GET /tasks/{id}`，Then 返回 HTTP 200 且 `status = Failed`、`kind = ClaimMismatch`，无签名。（ClaimMismatch 属异步 pipeline 终态失败，不是 POST 的非 2xx 响应；proposer 侧再折叠为数字码 10001，见 FR-8 与 §3.2。）

**Traceability**：implements G-1

### FR-3：异步任务模型与生命周期状态机

**Business rules**：
- 接口集：`POST /tasks/range`（必填 `x-task-id` header，UUID v4，body 为 rkyv `application/octet-stream`）、`GET /tasks/{id}`、`DELETE /tasks/{id}`、`GET /tasks` `[Repo: tee/enclave/src/server.rs:53]`。
- `task_id` 由调用方（host）分配，enclave 只校验形状不自造；同一 `x-task-id` 重复 POST 幂等返回同一 entry，不重新执行 `[Repo: tee/enclave/src/task_manager.rs:169]`。
- 任务阶段：Pending → DeserializingWitness → LoadingBootInfo → RunningKona → Signing → Terminal；三种终态 Finished / Failed / Cancelled `[Repo: tee/enclave/src/task_manager.rs:62]`。
- DELETE 触发协作式取消：向后台 pipeline future 发 oneshot abort 信号，在下一个 `.await` 点丢弃 future；运行中取消标记为 Cancelled `[Repo: tee/enclave/src/task_manager.rs:232]`。
- `ENCLAVE_KEY` 进程级 `OnceLock<SigningKey>` 单源只读，签名与 attestation 仅借用不可变引用；任务表锁（parking_lot::Mutex）不跨 `.await`，每 entry 长状态用独立 tokio mutex `[Repo: tee/enclave/src/task_manager.rs:1]`。

**Acceptance Criteria**：
- Given 一个新任务，When host `POST /tasks/range`，Then 立即返回 201 + CreateTaskResponse（含 taskId），kona pipeline 在后台异步执行。
- Given 同一 `x-task-id` 重复 POST，Then 返回 200 + 同一结果（`already_existed = true`），不重新执行。
- Given 缺失或非 UUID 形状的 `x-task-id`，When `POST /tasks/range`，Then 同步返回 HTTP 400 + JSON `ErrorResponse{error_kind:"InvalidTaskId"}`，不进入反序列化与 kona spawn。
- Given 一个运行中的任务，When host `DELETE /tasks/{id}`，Then 任务转入 Cancelled 终态，后续 `GET /tasks/{id}` 返回 HTTP 200 且 `status = Cancelled{at_phase}`。
- Given 一个不存在的 `task_id`，When `GET /tasks/{id}`，Then 同步返回 HTTP 404 + JSON `ErrorResponse{error_kind:"TaskUnknown"}`（proposer 侧折叠为 10004 / RESOURCE_NOT_FOUND）。

**Traceability**：implements G-3

### FR-4：并发上限与背压（TooManyTasks）

**Business rules**：
- 在跑任务数受 `MAX_INFLIGHT_TASKS` 限制；`0` 表示自动取 `num_cpus / 2`（最小 1）`[Repo: tee/enclave/src/task_manager.rs:37]`、`[Repo: tee/enclave/src/main.rs:122]`。
- 仅当新请求会创建新 entry 且在跑数已达上限时返回 TooManyTasks；幂等命中（已存在 task_id）不受上限限制 `[Repo: tee/enclave/src/task_manager.rs:194]`。
- in-flight 计数口径：仅统计 status 为非终态（非 Finished/Failed/Cancelled）的 entry；已终态但尚未被 TTL GC 回收的任务**不**占用容量；计数时若某 entry 的状态锁瞬时不可获取，则保守计为 in-flight `[Repo: tee/enclave/src/task_manager.rs:155]`、`[Repo: tee/enclave/src/task_manager.rs:194]`。

**Acceptance Criteria**：
- Given 在跑（非终态）任务数已达 `MAX_INFLIGHT_TASKS`，When 提交一个新 `x-task-id` 的 `POST /tasks/range`，Then 同步返回 HTTP 429 + JSON `ErrorResponse{error_kind:"TooManyTasks"}`，不创建新任务。
- Given 任务数已达上限但其中部分已进入终态（尚未 GC），When 提交一个新 `x-task-id` 的 `POST /tasks/range`，Then 因终态不占容量，任务被接受并返回 201。
- Given 在跑任务数已达上限，When 用一个已存在的 `x-task-id` 重复 POST，Then 仍幂等返回该任务结果，不受上限拒绝。

**Traceability**：implements G-3

### FR-5：请求体上限（256 MiB）

**Business rules**：
- `POST /tasks/range` 的 body 上限为 `MAX_RANGE_BODY_BYTES = 256 MiB`，由 axum `DefaultBodyLimit` 在路由层拦截 `[Repo: tee/enclave/src/server.rs:59]`。

**Acceptance Criteria**：
- Given 请求体超过 256 MiB，When `POST /tasks/range`，Then 直接返回 HTTP 413 拒收，不进入反序列化与任务注册。

**Traceability**：implements G-3

### FR-6：ENCLAVE_KEY 管理与 NSM attestation（dev / vsock 双 build）

**Business rules**：
- 默认 build（无 features）：监听 TCP `127.0.0.1:7878`（`LISTEN` 可覆盖），使用硬编码 dev key（Anvil #0），返回带 `XLAYER-DEV-ATTESTATION-V1` marker 的占位 attestation，PCR0 = `[0u8;32]` `[Repo: tee/enclave/src/main.rs:111]`、`[Repo: tee/enclave/src/keys.rs:38]`、`[Repo: tee/enclave/src/attestation.rs:18]`。
- `--features vsock`（linux，真 Nitro）：监听 vsock `(VMADDR_CID_ANY, 7878)`；`ENCLAVE_KEY` 经 `k256::SecretKey::random(OsRng)` 生成（enclave 内 `/dev/urandom` 由 NSM 硬件熵播种，等效 NSM-backed）；attestation 由 `aws_nitro_enclaves_nsm_api` 直接产出真 `COSE_Sign1`；PCR0 取 NSM `DescribePCR{index:0}` 的 48 字节度量后 `keccak256` 压缩为 32 字节，压缩值全零则拒绝启动 `[Repo: tee/enclave/src/main.rs:113]`、`[Repo: tee/enclave/src/keys.rs:50]`、`[Repo: tee/enclave/src/attestation.rs:72]`。
- `GET /attestation` 始终以 `user_data = "xlayer-tee-prover"`、空 nonce、当前公钥请求 attestation；私钥永不出现在任何响应中 `[Repo: tee/enclave/src/server.rs:153]`。dev 生成器对 nonce 非空 / pubkey 不匹配会返回 InvalidAttestationRequest（→ InternalEnclave / 500），但因 handler 固定传空 nonce + 当前公钥，该校验分支不可经公开端点触发 `[Repo: tee/enclave/src/attestation.rs:33]`。

**Acceptance Criteria**：
- Given 以 `--features vsock` 在 Nitro Enclave 内启动，When enclave 初始化，Then `ENCLAVE_KEY` 经 NSM 熵随机生成，公钥仅通过 attestation 暴露，私钥不出现在任何接口响应或日志中。
- Given vsock build 启动且 NSM 返回的压缩 PCR0 全零（异常配置），When 启动校验，Then enclave 拒绝启动。
- Given 默认 build，When `GET /attestation`，Then 返回带 dev marker 前缀的占位文档（非真 Nitro `COSE_Sign1`），供 host 侧识别并跳过 CA 链验证。

**Traceability**：implements G-2、G-5

### FR-7：终态任务 TTL 回收（GC）

**Business rules**：
- 独立后台 tokio task 周期性扫描，回收已超 TTL 的终态 entry，不影响在跑任务 `[Repo: tee/enclave/src/gc.rs]`、`[Repo: tee/enclave/src/task_manager.rs:285]`。
- TTL 由 `TERMINAL_TTL_SECS` 配置，默认 3600s `[Repo: tee/enclave/src/main.rs:36]`。

**Acceptance Criteria**：
- Given 一个终态任务的结束时间已超过 `TERMINAL_TTL_SECS`，When GC 周期触发，Then 该任务从注册表移除，后续 `GET /tasks/{id}` 返回 TaskUnknown。
- Given 一个仍在跑的任务，When GC 周期触发，Then 该任务不被回收。

**Traceability**：implements G-3

### FR-8：wire 接口契约与双面错误模型

**Business rules**：
- host ↔ enclave 的请求/响应 body 统一为 rkyv `application/octet-stream`（attestation 为原始 octet-stream）；错误以 JSON `ErrorResponse { error_kind, message }` 返回，`error_kind` 为 PascalCase 的 `ErrorKind` 变体名（如 `"ClaimMismatch"`）`[Repo: tee/enclave/src/server.rs:206]`、`[Repo: tee/types/src/error.rs:139]`。
- **双面错误模型（关键，AC 据此判定）**：
  - **同步面**——请求在 POST/GET 时被直接拒绝，返回非 2xx HTTP + JSON `ErrorResponse`：`TooManyTasks → 429`、`InvalidTaskId → 400`（缺失或非 UUID 的 `x-task-id`）、`TaskUnknown → 404`、body > 256 MiB → 413（axum body-limit 层拦截）`[Repo: tee/enclave/src/server.rs:78]`。
  - **异步面**——任务已被接受（POST 返回 201）后，pipeline 失败作为**终态任务状态**经 `GET /tasks/{id}` 以 **HTTP 200** 暴露：`status ∈ {Finished, Failed{kind,message}, Cancelled{at_phase}}`；`ClaimMismatch`、`DeserializeRkyv`、`InvalidWitness`、`KonaExec` 等均属此面，不会作为 POST 的非 2xx 出现 `[Repo: tee/enclave/src/task_manager.rs:316]`、`[Repo: tee/enclave/src/server.rs:113]`。
- enclave 实际产出的 HTTP 状态码由 `ErrorKind::status_code()` 决定，取值集合为 {400, 404, 409, 429, 500}：400（ClaimMismatch / InvalidWitness / DeserializeRkyv / InvalidTaskId 等）、404（TaskUnknown）、409（Cancelled）、429（TooManyTasks）、500（KonaExec / InternalEnclave / Timeout）`[Repo: tee/types/src/error.rs:89]`。
- 内部 `Error` 变体（`DeserializeWitness` / `MalformedWitness` / `MissingBootInfo` / `InvalidRangeBounds` / `ClaimMismatch` / …）经 `to_wire_kind()` 映射为公共 `ErrorKind`（分别为 `DeserializeRkyv` / `InvalidWitness` / `InvalidWitness` / `InvalidWitness` / `ClaimMismatch` / …），原始 message 保留供诊断 `[Repo: tee/enclave/src/error.rs:52]`。注意内部变体名与公共 `ErrorKind` 名不一一对应（如内部 `DeserializeWitness` → 公共 `DeserializeRkyv`）。
- `RangeJournal`、wire 路径常量、`ErrorKind` 均来自共享契约 crate `xlayer-tee-types`，三方（host/enclave/proposer）依赖同一 git commit `[设计文档 §5.3]`。

**Acceptance Criteria**：
- Given 一个同步面错误（如 cap 已满时 POST 新任务），When 请求返回，Then 返回对应非 2xx HTTP 状态（如 429）+ JSON `ErrorResponse{error_kind}`，HTTP 状态码与 `ErrorKind::status_code()` 一致。
- Given witness 字节无法被 rkyv 反序列化，When 任务执行至终态，Then `GET /tasks/{id}` 返回 HTTP 200 且 `status = Failed`、`kind = DeserializeRkyv`（异步面，非 POST 的非 2xx）。

**Traceability**：implements G-1、G-3

## 5. Preconditions and impact surface

| # | Surface | Current fact / evidence | Expected change / constraint | Risk / impact | Blocking? |
|---|---------|-------------------------|------------------------------|---------------|-----------|
| I-1 | 共享契约 crate `xlayer-tee-types` | `RangeJournal` 字段顺序与 168B packed 布局自 v0.1 锁定；既是签名输入又是合约 `prove(bytes)` 解码目标 `[设计文档 §5.3/§6.3]` | enclave 任何 journal 字段变更须与 host / proposer / 合约同步到同一 git commit | 字段重排会让旧签名 / 旧合约立即失效 | No（本迭代不改字段） |
| I-2 | 链上 aggregation vkey | `EXPECTED_PCR0_HASH = keccak256(PCR0)` 烤入 `programs/aggregation`；enclave 的 PCR0 由 EIF 字节决定 `[设计文档 §3.3]` | enclave 代码 / 依赖任何变化 → PCR0 变 → 须经治理多签升级链上 vkey；仅换密钥（PCR0 不变）不需改 vkey | 升级需治理流程；漏更新会导致聚合电路 PCR0 比对失败 | No |
| I-3 | 上游依赖 op-succinct / kona | enclave 直接复用 `DefaultWitnessData` / `ETHDAWitnessExecutor` / `hash_rollup_config` / `BootInfo::load` `[Repo: tee/enclave/src/replay.rs:16]` | witness schema 与 enclave 反序列化须保持一致 | 上游升级 witness 类型时 enclave 需同步 | No |
| I-4 | 部署 build 模式 | 默认 build 用公开 Anvil #0 dev key 与占位 attestation `[Repo: tee/enclave/src/keys.rs:26]` | 生产仅可用 `--features vsock`；默认 build 故意不走真 Nitro 路径 | dev build 误部署生产将以可公开签名的私钥对外签名 | No（编译期已隔离） |
| I-5 | NSM / Nitro 运行时 | vsock build 依赖 `aws-nitro-enclaves-nsm-api` 与 enclave 内 `/dev/urandom` NSM 播种 `[Repo: tee/enclave/src/attestation.rs:60]` | 必须在真实 Nitro Enclave 内运行；NSM 调用须成功否则启动失败 | 非 Nitro 环境无法获取真 attestation / PCR0 | No |

## 6. Open Items

- **Blocking Issues**：`None`
- **Non-blocking Questions**：
  - ClaimMismatch 错误目前 `computed` 字段为占位 `[0u8;32]`（op-succinct 错误未干净暴露重算值）`[Repo: tee/enclave/src/replay.rs:72]`；是否需要在诊断信息中暴露真实 computed root，待后续确认。
  - PCR0 压缩采用 `keccak256(48B measurement)`，与设计文档 `EXPECTED_PCR0_HASH = keccak256(PCR0)` 一致；如未来聚合电路改用原始 48B 比对，需三方同步。
  - `VSOCK_PORT = 7878` 当前在 enclave (`main.rs:41`) 与 host config 各写一份（见 §7 S-9），未收进 `xlayer-tee-types`；建议后续将其上提为 types 常量以消除双写 drift（非阻塞）。
- **Linked Pending Items**：`None`

## 7. 共享契约面（host ↔ enclave）

host crate 与 enclave 的业务接口契约 **100% 由 `xlayer-tee-types` 提供**（host 侧业务依赖仅此一个 crate，无 op-succinct / witness 依赖）。**本节 §7.1–§7.5 把该 crate 的完整定义就地写死**（已与 live crate 逐字核对一致），作为 codegen 与评审的唯一参照——AI 实现 enclave 时**必须按以下定义引用这些类型，不得自造、不得改名、不得增删字段或变体**；**权威来源恒为 `xlayer-tee-types`，enclave / host / proposer 三方依赖同一 git commit，任何变更须改 types crate 并三方同步，不得在本 PRD 单方修改**。文末 S 表为速查索引。

> 注：host PRD §5.6（北向 `{code,message,data}` 响应信封）与 §5.7（host `config.toml`）为 **host 专属**，不属 host↔enclave 契约面，enclave 不实现（见 §3.2）。

#### 7.1 `tee/types/src/lib.rs`（crate 顶层 + re-exports）

```rust
pub mod wire;
pub mod journal;
pub mod error;
pub mod task;

pub use error::{ErrorKind, ErrorResponse};
pub use journal::{RangeJournal, RangeJournalWire, RangeTaskResponse};
pub use task::{
    CreateTaskResponse, DeleteTaskResponse, TaskId, TaskListResponse, TaskPhase, TaskStateView,
    TaskStatusView, TaskSummary,
};
```

#### 7.2 `tee/types/src/journal.rs`（签名相关类型 + pack 算法）

```rust
use alloy_primitives::FixedBytes;
use alloy_sol_types::sol;
use rkyv::{Archive, Deserialize, Serialize};

pub const PACKED_JOURNAL_LEN: usize = 168;
pub const SIGNATURE_LEN: usize = 65;

sol! {
    #[derive(Debug, PartialEq, Eq)]
    struct RangeJournal {
        bytes32 pcr0;
        bytes32 configHash;
        bytes32 l1OriginHash;
        uint64  l2BlockNumber;
        bytes32 prevOutputRoot;
        bytes32 outputRoot;
    }
}

impl RangeJournal {
    pub fn pack(&self) -> [u8; PACKED_JOURNAL_LEN] {
        let mut out = [0u8; PACKED_JOURNAL_LEN];
        out[0..32].copy_from_slice(&self.pcr0.0);
        out[32..64].copy_from_slice(&self.configHash.0);
        out[64..96].copy_from_slice(&self.l1OriginHash.0);
        out[96..104].copy_from_slice(&self.l2BlockNumber.to_be_bytes());
        out[104..136].copy_from_slice(&self.prevOutputRoot.0);
        out[136..168].copy_from_slice(&self.outputRoot.0);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct RangeJournalWire {
    pub pcr0: [u8; 32],
    pub config_hash: [u8; 32],
    pub l1_origin_hash: [u8; 32],
    pub l2_block_number: u64,
    pub prev_output_root: [u8; 32],
    pub output_root: [u8; 32],
}

impl From<&RangeJournal> for RangeJournalWire {
    fn from(j: &RangeJournal) -> Self {
        Self {
            pcr0: j.pcr0.0,
            config_hash: j.configHash.0,
            l1_origin_hash: j.l1OriginHash.0,
            l2_block_number: j.l2BlockNumber,
            prev_output_root: j.prevOutputRoot.0,
            output_root: j.outputRoot.0,
        }
    }
}

impl From<&RangeJournalWire> for RangeJournal {
    fn from(w: &RangeJournalWire) -> Self {
        Self {
            pcr0: FixedBytes(w.pcr0),
            configHash: FixedBytes(w.config_hash),
            l1OriginHash: FixedBytes(w.l1_origin_hash),
            l2BlockNumber: w.l2_block_number,
            prevOutputRoot: FixedBytes(w.prev_output_root),
            outputRoot: FixedBytes(w.output_root),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct RangeTaskResponse {
    pub journal: RangeJournalWire,
    pub signature: [u8; SIGNATURE_LEN],
}
```

**enclave 侧用法**：`runner` 构造 `RangeJournalWire`，`signing` 经 `From<&RangeJournalWire> for RangeJournal` 转 `RangeJournal` 后对 `pack()`（168B）做 `keccak256` 再 secp256k1 签名；终态成功以 `RangeTaskResponse { journal, signature }` 返回。**严禁**在 enclave 内另立 journal 结构或改动字段顺序（packed 布局即签名输入，任何重排会让旧签名 / 链上合约立即失效）。

#### 7.3 `tee/types/src/wire.rs`（HTTP 协议常量）

```rust
pub const TASKS_RANGE: &str = "/tasks/range";
pub const TASKS_BY_ID: &str = "/tasks/{task_id}";
pub const TASKS_LIST: &str = "/tasks";
pub const ATTESTATION: &str = "/attestation";

pub const HEADER_TASK_ID: &str = "x-task-id";

pub fn task_path(task_id: &str) -> String {
    format!("/tasks/{task_id}")
}

pub const OCTET_STREAM: &str = "application/octet-stream";
pub const JSON: &str = "application/json";

pub const MAX_RANGE_BODY_BYTES: usize = 256 * 1024 * 1024;
```

**enclave 侧用法**：axum 路由路径必须取自 `wire::TASKS_RANGE` / `TASKS_BY_ID` / `TASKS_LIST` / `ATTESTATION`（**不得新增其它端点**，例如不得自造 `/health`）；幂等 header 名取 `wire::HEADER_TASK_ID`；响应 Content-Type 取 `OCTET_STREAM`（rkyv body）/ `JSON`（错误 body）；`POST /tasks/range` 的 `DefaultBodyLimit` 基准取 `MAX_RANGE_BODY_BYTES`。

#### 7.4 `tee/types/src/task.rs`（异步任务 wire 类型）

```rust
use rkyv::{Archive, Deserialize, Serialize};

use crate::{ErrorKind, RangeTaskResponse};

pub type TaskId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Archive, Serialize, Deserialize)]
pub enum TaskPhase {
    Pending,
    DeserializingWitness,
    LoadingBootInfo,
    RunningKona,
    Signing,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct CreateTaskResponse {
    pub task_id: TaskId,
    pub accepted_at_ms: u64,
    pub already_existed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct TaskStateView {
    pub task_id: TaskId,
    pub status: TaskStatusView,
    pub phase: TaskPhase,
    pub start_time_ms: u64,
    pub end_time_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub enum TaskStatusView {
    Running,
    Finished(Box<RangeTaskResponse>),
    Failed { kind: ErrorKind, message: String },
    Cancelled { at_phase: TaskPhase },
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct DeleteTaskResponse {
    pub task_id: TaskId,
    pub was_running: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct TaskSummary {
    pub task_id: TaskId,
    pub phase: TaskPhase,
    pub start_time_ms: u64,
    pub end_time_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct TaskListResponse {
    pub running: Vec<TaskSummary>,
    pub finished: Vec<TaskSummary>,
    pub failed: Vec<TaskSummary>,
    pub cancelled: Vec<TaskSummary>,
}

impl TaskStatusView {
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::Running)
    }
}
```

**enclave 侧用法**：`task_manager` 内部状态映射到 `TaskStatusView` / `TaskPhase`（阶段集合恰好为上述 6 个，**不得增减**）；`POST /tasks/range` 返回 `CreateTaskResponse`（新建 → 201、幂等命中 → 200，由 `already_existed` 区分）；`GET /tasks/{id}` 返回 `TaskStateView`；`GET /tasks` 返回按状态分桶的 `TaskListResponse`；`DELETE /tasks/{id}` 返回 `DeleteTaskResponse`。

#### 7.5 `tee/types/src/error.rs`（错误协议）

```rust
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
)]
pub enum ErrorKind {
    KonaExec,
    InternalEnclave,
    Timeout,
    DeserializeRkyv,
    ClaimMismatch,
    InvalidWitness,
    InvalidRangeSig,
    ChainBreak,
    Inconsistent,
    TooManyTasks,
    TaskUnknown,
    Cancelled,
    InvalidTaskId,
}

impl ErrorKind {
    pub const fn status_code(self) -> u16 {
        match self {
            Self::KonaExec | Self::InternalEnclave | Self::Timeout => 500,
            Self::ClaimMismatch
            | Self::InvalidWitness
            | Self::InvalidRangeSig
            | Self::ChainBreak
            | Self::Inconsistent
            | Self::DeserializeRkyv
            | Self::InvalidTaskId => 400,
            Self::TooManyTasks => 429,
            Self::TaskUnknown => 404,
            Self::Cancelled => 409,
        }
    }

    pub const fn is_retryable(self) -> bool {
        match self {
            Self::KonaExec
            | Self::InternalEnclave
            | Self::Timeout
            | Self::TooManyTasks
            | Self::TaskUnknown => true,
            Self::ClaimMismatch
            | Self::InvalidWitness
            | Self::InvalidRangeSig
            | Self::ChainBreak
            | Self::Inconsistent
            | Self::DeserializeRkyv
            | Self::Cancelled
            | Self::InvalidTaskId => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error_kind: ErrorKind,
    pub message: String,
}

impl ErrorResponse {
    pub fn new(error_kind: ErrorKind, message: impl Into<String>) -> Self {
        Self { error_kind, message: message.into() }
    }
}
```

**enclave 侧用法**：enclave 内部 `Error` 经 `to_wire_kind()` 映射到此公共 `ErrorKind`；HTTP 状态码取 `ErrorKind::status_code()`（集合 `{400,404,409,429,500}`）；错误体为 JSON `ErrorResponse { error_kind, message }`（`error_kind` 为 PascalCase 变体名）。
> 说明：`ErrorKind` 含 13 个变体，其中 `InvalidRangeSig` / `ChainBreak` / `Inconsistent` 属**聚合电路**域；`KonaExec` 当前 enclave **不再主动产出**（kona 执行失败映射为 `InternalEnclave`，重算不一致映射为 `ClaimMismatch`）。三者均作为共享契约保留以兼容 host / proposer / aggregation，**enclave 实现不得删除任何变体**。（注：FR-8 旧文将 `KonaExec` 列入异步终态错误，与此处略有出入，以本节定义为准。）

---

下方 S 表为 §7.1–§7.5 的**速查索引**（权威仍以上方完整定义为准）：

| # | 共享项 | 具体值（锁定） | 权威来源 |
|---|--------|----------------|----------|
| S-1 | 端点路径 | `POST /tasks/range`、`GET /tasks/{task_id}`、`GET /tasks`、`GET /attestation` | `types::wire` `[Repo: tee/types/src/wire.rs:20]` |
| S-2 | 幂等 header | `x-task-id`（UUID v4 canonical 36 字符） | `types::wire::HEADER_TASK_ID` `[Repo: tee/types/src/wire.rs:32]` |
| S-3 | content-type | rkyv body = `application/octet-stream`；错误 body = `application/json` | `types::wire` `[Repo: tee/types/src/wire.rs:44]` |
| S-4 | body 上限 | `MAX_RANGE_BODY_BYTES = 256 MiB`（超出 → 413） | `types::wire` `[Repo: tee/types/src/wire.rs:56]` |
| S-5 | 签名 journal | `RangeJournal`(sol 6 字段) / `RangeJournalWire`(rkyv) / `pack()` 168B 布局；`PACKED_JOURNAL_LEN = 168`、`SIGNATURE_LEN = 65`(`r‖s‖v`, v∈{27,28}) | `types::journal` `[Repo: tee/types/src/journal.rs:10]` |
| S-6 | 任务 wire 类型 | `TaskPhase`、`CreateTaskResponse`、`TaskStateView`、`TaskStatusView`、`TaskSummary`、`TaskListResponse`、`DeleteTaskResponse` | `types::task` `[Repo: tee/types/src/task.rs]` |
| S-7 | 错误模型 | `ErrorKind`(PascalCase 变体)、`ErrorResponse{error_kind,message}`、`status_code()`∈{400,404,409,429,500}、`is_retryable()` | `types::error` `[Repo: tee/types/src/error.rs:34]` |
| S-8 | 成功响应 | `RangeTaskResponse{ journal: RangeJournalWire, signature: [u8;65] }` | `types::journal::RangeTaskResponse` `[Repo: tee/types/src/journal.rs:80]` |

### ⚠️ 共享约定但 **未** 进 types（drift 风险，需人工对齐）

| # | 共享项 | 现状 | 风险 |
|---|--------|------|------|
| S-9 | 传输端点 | 应用层固定 HTTP/1.1；生产 vsock 端口 `7878`、dev TCP `127.0.0.1:7878`。`VSOCK_PORT = 7878` 硬编码在 enclave `main.rs:41`，host 经 `EnclaveConfig.vsock_port` 注入 `[Repo: tee/enclave/src/main.rs:41]`、`[Repo: tee/host/src/enclave_client.rs:224]` | 端口在两端各写一份，未由 types 统一；改动须人工同步（见 §6 Open Items） |
| S-10 | rkyv 编解码纪律 | 双方统一用 rkyv high API + `rancor::Error`；解码侧须将 `Bytes` 拷入对齐 buffer（enclave 入站 `AlignedVec::<16>`，host 出站 `AlignedVec::<8>`）`[Repo: tee/enclave/src/runner.rs:26]`、`[Repo: tee/host/src/enclave_client.rs:190]` | 隐式约定，非类型可强制；任一端改 rkyv 版本/对齐策略须双方一致 |

> 说明：dev attestation marker `\xffXLAYER-DEV-ATTESTATION-V1\xff`、`DefaultWitnessData` witness schema、AWS Nitro root / PCR0 常量等，host 均为**字节透传或不参与**，属 enclave↔verifier / proposer↔enclave 的共享，**不**计入 host↔enclave 契约面。
