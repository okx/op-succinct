# Gasless Kona Backport (N1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 okx/optimism `po/gasless_v1` 的 gasless 改动 backport 到 `kona-client/v1.2.13` 基线（GitLab optimism fork 两层分支 A/B），op-succinct 只改 Cargo.toml，并在本地 gasless devnet 上完成 witness + zkVM 验证。

**Architecture:** 分支 A（`po/gasless_v1_kona-1.2.13`）只放作者改动的 backport（alloy-op-evm vendor 拷贝 + kona tx.rs），分支 B（`xl/gasless-kona-1.2.13-proof`）基于 A 只放我们的 2 个 proof 接线 commit；op-succinct 的 kona 依赖指向 B，op-revm 继续经 `[patch.crates-io]` 指向 okx/revm 既有 gasless 分支。`git diff A..B` 恒等于我们的净改动。

**Tech Stack:** Rust / Cargo git-deps & patches、kona v1.2.13 monorepo（vendored alloy-op-evm 0.26.3）、okx/revm（revm 34 / op-revm 15）、SP1 v6.1.0、xlayer-toolkit devnet。

**设计文档:** `docs/superpowers/specs/2026-06-12-gasless-kona-backport-design.md`

**关键路径与对象（全计划通用）:**

| 名称 | 值 |
|------|-----|
| `$OPT`（GitLab optimism fork 本地 clone） | `/Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork` |
| `$REVM`（okx/revm 本地 clone） | `/Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/revm-fork` |
| `$OPS`（op-succinct 工作仓库） | `/Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct` |
| `$TOOLKIT`（devnet 工具） | `/Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/xlayer-toolkit` |
| v1.2.13 基线 commit | `348e129`（= 上游 tag `kona-client/v1.2.13`） |
| 作者 gasless 改动区间 | `bac34a11..okx/po/gasless_v1`（`bac34a11` = 作者分支上 gasless 前的最后一个 sync commit） |
| 分支 A | `po/gasless_v1_kona-1.2.13`（只含作者改动 backport） |
| 分支 B | `xl/gasless-kona-1.2.13-proof`（A + 我们的 2 个 commit，op-succinct 指向它） |
| okx/revm gasless 分支 | `github/xl/gasless_xl0.0.5.1_base`（revm 34 / op-revm 15 基线） |

**作者 gasless commit → backport 范围对照（已核实）:**

| 作者 commit | 内容 | backport? |
|---|---|---|
| `30722080` | alloy-op-evm 全部 gasless 文件 + op-revm handler/abstraction + kona tx.rs | ✅ alloy-op-evm/kona 部分 |
| `b39ff415` | op-reth mempool + alloy-op-evm/contract 小改 | ✅ 仅 alloy-op-evm 部分 |
| `d2f4e546` | gaslimit check（共识相关）+ op-reth | ✅ 仅 alloy-op-evm 部分 |
| `1a0f818e` `7f667730` `0c5c4620` | op-reth / Cargo.lock | ❌ sequencer 侧 |
| `736abc5a` | GaslessWhitelist.sol 合约源码 | ❌ rust 不需要；devnet 任务引用 |

> 实操采用**终态 diff**（`git diff bac34a11..okx/po/gasless_v1 -- <路径>`）一次性 backport，
> 避免逐 commit cherry-pick 踩中间态（如 `gasless_contract.rs` 改名、forktime 加了又删；
> `rust/alloy-op-hardforks` 净变化为 0，已核实不在范围内）。

---

### Task 0: 工作区准备与基线核验

**Files:** 无代码改动，只校验环境。

- [ ] **Step 0.1: 核验远端与关键 commit 可达**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork
git cat-file -t 348e129 && git cat-file -t bac34a11 && git rev-parse okx/po/gasless_v1
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/revm-fork
git rev-parse github/xl/gasless_xl0.0.5.1_base
```

Expected: 三个对象都存在，各输出 commit hash。若 `okx` remote 缺失：`git remote add okx https://github.com/okx/optimism.git && git fetch okx po/gasless_v1`。

- [ ] **Step 0.2: 确认 optimism-fork 工作区干净**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork && git status --short
```

Expected: 空输出（有脏文件先 stash 并记录）。

---

### Task 1: op-revm 语义 diff（前置检查，决定 okx/revm 引用方式）

**目的：** 设计 §5——作者**新的** vendored op-revm 改动（revm 38 基线）与**旧的** okx/revm 分支（revm 34 基线，op-succinct 将引用它）必须语义一致，否则 proof 与生产节点行为分歧。

**Files:**
- 产出: `/Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct/docs/superpowers/plans/notes/op-revm-semantic-diff.md`（检查记录）

- [ ] **Step 1.1: 导出两份 diff**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork
git diff bac34a11..okx/po/gasless_v1 -- rust/op-revm/ > /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct/.omc/new-op-revm.diff
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/revm-fork
git diff github/xl/xl0.0.5.1..github/xl/gasless_xl0.0.5.1_base -- crates/op-revm/ > /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct/.omc/old-op-revm.diff
```

- [ ] **Step 1.2: 按检查单逐项比对两份 diff 的语义**

检查单（每项在两份 diff 中找到对应 hunk，结论填入 notes 文件）：

| # | 语义点 | 旧分支位置（参考） |
|---|--------|--------------------|
| 1 | `OpTransaction.is_gasless` 字段 + `OpTxTr::is_gasless()`（默认 false） | `transaction/abstraction.rs` |
| 2 | `effective_gas_price()` 在 gasless 时恒返回 0 | `transaction/abstraction.rs` |
| 3 | gasless 时跳过 L1BlockInfo 加载 | `handler.rs` validate_against_state_and_deduct_caller |
| 4 | gasless 时跳过 L1/operator 费用扣除 | 同上 |
| 5 | gasless 时余额仅校验 `>= tx.value()` | 同上 |
| 6 | gas refund 仍记录（EIP-3529）但不退款 | `handler.rs` last_frame_result |
| 7 | gasless 时跳过 `reimburse_caller` | `handler.rs` |
| 8 | gasless 时跳过 `reward_beneficiary` | `handler.rs` |
| 9 | basefee 检查的处理方式（应都依赖外部 `disable_base_fee`，即 Hook 负责） | `handler.rs` validate_env |

- [ ] **Step 1.3: 写检查记录并做决策**

创建 `docs/superpowers/plans/notes/op-revm-semantic-diff.md`，逐项记录"一致/有差异 + 证据行号"。
决策门：
- 全部一致 → okx/revm 引用**远端分支 tip 的 rev**（`git ls-remote https://github.com/okx/revm xl/gasless_xl0.0.5.1_base` 取 hash），Task 6 使用；
- 有语义差异 → 把差异写成最小 patch commit（基于旧分支），推到我们 fork 的新分支 `xl/gasless_xl0.0.5.1_base-proof-fix` 并准备 MR 给作者，op-succinct 暂指我们的分支。

- [ ] **Step 1.4: Commit 检查记录（op-succinct 仓库）**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct
git add docs/superpowers/plans/notes/op-revm-semantic-diff.md
git commit -m "docs: record op-revm semantic diff check for gasless backport"
```

---

### Task 2: 分支 A + commit A1 — backport alloy-op-evm gasless

**Files:**
- Modify（在 `$OPT` 仓库）: `rust/alloy-op-evm/src/block/mod.rs`、`rust/alloy-op-evm/src/lib.rs`、`rust/alloy-op-evm/src/tx.rs`、`rust/alloy-op-evm/Cargo.toml`、`rust/Cargo.toml`
- Create: `rust/alloy-op-evm/src/block/xlayer_gasless_contract.rs`、`rust/alloy-op-evm/src/xlayer/gasless.rs`、`rust/alloy-op-evm/src/xlayer/mod.rs`

- [ ] **Step 2.1: 从基线切分支 A**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork
git checkout -b po/gasless_v1_kona-1.2.13 348e129
```

- [ ] **Step 2.2: 应用作者 alloy-op-evm 终态 diff（3-way）**

```bash
PATCH_DIR=/Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct/.omc
git diff bac34a11..okx/po/gasless_v1 -- rust/alloy-op-evm/ > $PATCH_DIR/gasless-alloy-op-evm.patch
git apply --3way $PATCH_DIR/gasless-alloy-op-evm.patch
```

Expected: 新文件（`xlayer_gasless_contract.rs`、`xlayer/gasless.rs`、`xlayer/mod.rs`）干净落盘；`block/mod.rs` 可能有冲突（0.26.3 与 0.31 上下文漂移）。

- [ ] **Step 2.3: 解决 block/mod.rs 冲突（gasless hunk 清单）**

需要落位的 gasless hunk 共 6 处（以 `okx/po/gasless_v1` 的版本为语义基准，适配 0.26.3 上下文）：
1. 顶部 imports：`use crate::{GaslessFeeHook, OpEvmFactory, XLayerGaslessFeeHook, XLayerGaslessFeeHookFactory};` + `use core::marker::PhantomData;` + `pub mod xlayer_gasless_contract; pub use xlayer_gasless_contract::{GaslessContract, XLAYER_DEVNET_GASLESS_CONTRACT, XLAYER_MAINNET_GASLESS_CONTRACT, XLAYER_TESTNET_GASLESS_CONTRACT, xlayer_gasless_contract};`
2. `OpTxEnv` trait 增加 `fn set_gasless(&mut self, is_gasless: bool);`，并为 `OpTransaction<T>` 实现（`self.is_gasless = is_gasless`）。
3. `OpBlockExecutor` 增加泛型 `Hook = XLayerGaslessFeeHook`、字段 `gasless_contract: Option<GaslessContract>` 与 `gasless_fee_hook: PhantomData<Hook>`；`new()` 初始化为 `None`/`PhantomData`；增加 `with_gasless_contract()`。
4. `execute_transaction_without_commit`（0.26.3 中签名为 `(tx_env: &E::Tx, tx: impl RecoveredTx<...>)`，作者版为 `into_parts()`——以 0.26.3 现有签名为准，把检测块插入执行前）：

```rust
let is_gasless = if !is_deposit && tx.tx().max_fee_per_gas() == 0 {
    match self.gasless_contract {
        Some(gasless_contract) => gasless_contract.is_gasless(&mut self.evm, tx.tx())?,
        None => false,
    }
} else {
    false
};
tx_env.set_gasless(is_gasless);
let result = Hook::transact_with_gasless_fee_checks(&mut self.evm, tx_env, is_gasless)
    .map_err(|err| { let hash = tx.tx().trie_hash(); BlockExecutionError::evm(err, hash) })?;
```

   注意：0.26.3 版签名里 `tx_env` 是 `&E::Tx`，作者版是 owned——如直接 set 不可行，参照 0.26.3 该函数当前对 `tx_env` 的使用方式做最小改造（允许把参数改为 owned/`mut`，调用方同步修改；这属于 backport 适配，留在分支 A）。
5. `BlockExecutor for OpBlockExecutor` impl 增加 `Hook: GaslessFeeHook<E>` bound。
6. `OpBlockExecutorFactory`：字段 `gasless_contract`、`with_gasless_contract()`、`gasless_contract()`；`BlockExecutorFactory` impl 的 `EvmF` bound 追加 `+ XLayerGaslessFeeHookFactory`；`create_executor` 改为 `OpBlockExecutor::<_, _, _, EvmF::Hook<DB, I>>::new(...).with_gasless_contract(self.gasless_contract)`。

- [ ] **Step 2.4: workspace 构建适配（rust/Cargo.toml）**

v1.2.13 workspace 的 op-revm 来自 crates.io 15.0.0（无 `is_gasless`）。为让 fork 仓库自身可编译，在 `rust/Cargo.toml` 末尾追加：

```toml
[patch.crates-io]
op-revm = { git = "https://github.com/okx/revm", branch = "xl/gasless_xl0.0.5.1_base" }
revm = { git = "https://github.com/okx/revm", branch = "xl/gasless_xl0.0.5.1_base" }
```

（若 cargo 报其余 revm-* 子 crate 版本冲突，按报错逐个补同源 patch 条目，与 op-succinct 现有 13 项对齐。）
同时按作者 diff 同步 `rust/alloy-op-evm/Cargo.toml` 的依赖/feature 增量（含 op-revm 的 `optional_no_base_fee` feature）。

- [ ] **Step 2.5: 编译 + 跑 backport 自带的单元测试**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork/rust
cargo check -p alloy-op-evm
cargo test -p alloy-op-evm xlayer
```

Expected: check 通过；作者自带的 3 个测试（gasless.rs×2 + xlayer_gasless_contract.rs×1）全部 PASS。
（此阶段 kona-client 预期**编译不过**——`FpvmOpEvmFactory` 尚未实现 `XLayerGaslessFeeHookFactory`，Task 4 解决，这是设计内状态。）

- [ ] **Step 2.6: Commit A1**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork
git add rust/alloy-op-evm rust/Cargo.toml rust/Cargo.lock
git commit -m "feat(alloy-op-evm): backport xlayer gasless detection and fee hook

Adapted-from: okx/optimism po/gasless_v1 (30722080, b39ff415, d2f4e546;
final-state diff bac34a11..po/gasless_v1 -- rust/alloy-op-evm), rebased
onto kona-client/v1.2.13 vendor copy (alloy-op-evm 0.26.3 API)."
```

---

### Task 3: 分支 A + commit A2 — backport kona tx.rs

**Files:**
- Modify: `rust/kona/bin/client/src/fpvm_evm/tx.rs`

- [ ] **Step 3.1: 应用作者 kona 终态 diff**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork
PATCH_DIR=/Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct/.omc
git diff bac34a11..okx/po/gasless_v1 -- rust/kona/ > $PATCH_DIR/gasless-kona-tx.patch
git apply --3way $PATCH_DIR/gasless-kona-tx.patch
```

内容（已核实仅 1 个文件）：`FpvmOpTx` 的 `OpTxEnv` impl 增加 `fn set_gasless(&mut self, is_gasless: bool) { self.0.is_gasless = is_gasless; }`；4 处 `OpTransaction` struct literal 补 `is_gasless: false`。

- [ ] **Step 3.2: 语法核验（kona-client 整体仍不可编译，仅核验本文件无误）**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork/rust
cargo check -p kona-client 2>&1 | grep -c "fpvm_evm/tx.rs"
```

Expected: `0`（报错只来自 factory bound 缺失，不来自 tx.rs）。

- [ ] **Step 3.3: Commit A2**

```bash
git add rust/kona/bin/client/src/fpvm_evm/tx.rs
git commit -m "feat(kona-client): backport gasless tx env support in FpvmOpTx

Adapted-from: okx/optimism po/gasless_v1 (30722080, kona part)."
```

---

### Task 4: 分支 B + commit B1 — FpvmOpEvmFactory 的 Hook factory impl

**Files:**
- Modify: `rust/kona/bin/client/src/fpvm_evm/factory.rs`

- [ ] **Step 4.1: 切分支 B**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork
git checkout -b xl/gasless-kona-1.2.13-proof po/gasless_v1_kona-1.2.13
```

- [ ] **Step 4.2: 实现 XLayerGaslessFeeHookFactory（先验证失败）**

```bash
cd rust && cargo check -p kona-client 2>&1 | grep "XLayerGaslessFeeHookFactory" | head -2
```

Expected: 报错确认 bound 不满足（这就是"失败的测试"）。

- [ ] **Step 4.3: 写实现**

在 `rust/kona/bin/client/src/fpvm_evm/factory.rs` 追加（import 按文件现有风格合并）：

```rust
use alloy_op_evm::{XLayerGaslessFeeHook, XLayerGaslessFeeHookFactory};

impl<H, O> XLayerGaslessFeeHookFactory for FpvmOpEvmFactory<H, O>
where
    H: HintWriterClient + Clone + Send + Sync + 'static,
    O: PreimageOracleClient + Clone + Send + Sync + 'static,
{
    type Hook<DB: Database, I: Inspector<OpContext<DB>>> = XLayerGaslessFeeHook;
}
```

要点：用**真 hook**（`XLayerGaslessFeeHook`，gasless 时临时 `disable_base_fee`），不是旧分支用过的 `NoopGaslessFeeHook`（Noop 会让 gasless 交易在 basefee 检查处失败）。`GaslessFeeHook` 对 `OpEvm<DB, I, P, Tx>` 的 `P` 泛型，FpvmOpEvmFactory 的 precompile 类型可直接满足；若 trait bound 报缺，按编译器提示补到 where 子句。

- [ ] **Step 4.4: 验证编译通过**

```bash
cargo check -p kona-client
```

Expected: PASS。

- [ ] **Step 4.5: Commit B1**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork
git add rust/kona/bin/client/src/fpvm_evm/factory.rs
git commit -m "feat(kona-client): implement XLayerGaslessFeeHookFactory for FpvmOpEvmFactory

Proof path uses the real XLayerGaslessFeeHook so gasless txs bypass the
base-fee check exactly like op-reth execution."
```

---

### Task 5: commit B2 — StatelessL2Builder 注入 gasless 合约 + 全量质量门 + push

**Files:**
- Modify: `rust/kona/crates/proof/executor/src/builder/core.rs`（`new()`，约 135-150 行）

- [ ] **Step 5.1: 接线 with_gasless_contract**

`StatelessL2Builder::new` 中（import：`use alloy_op_evm::{GaslessContract, xlayer_gasless_contract};`）：

```rust
let factory = OpBlockExecutorFactory::new(
    OpAlloyReceiptBuilder::default(),
    config.clone(),
    evm_factory,
)
.with_gasless_contract(
    // X Layer chains (195/1952/196) resolve to the on-chain whitelist
    // contract; every other chain id resolves to None (no-op).
    xlayer_gasless_contract(config.l2_chain_id.id()).map(GaslessContract::new),
);
```

- [ ] **Step 5.2: 编译 + kona-executor 回归测试（非 X Layer 链 id → None → 行为不变）**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork/rust
cargo check -p kona-executor && cargo test -p kona-executor
```

Expected: 全部 PASS（现有 fixture 都是 OP 系链 id，gasless_contract=None，是天然回归用例）。

- [ ] **Step 5.3: rust workspace 全量质量门**

```bash
cargo fmt --all --check && cargo check --workspace && cargo clippy --workspace -- -D warnings
```

Expected: 全部通过（fmt/clippy 报 backport 文件的问题就地修复，并入对应 commit：`git commit --amend` 仅当问题属于该 commit 的文件）。

- [ ] **Step 5.4: Commit B2 并 push 两个分支到 GitLab**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork
git add rust/kona/crates/proof/executor/src/builder/core.rs
git commit -m "feat(kona-executor): wire xlayer gasless contract into StatelessL2Builder

Mirrors op-reth's chain-id derived injection so the proof path runs the
same whitelist detection as the sequencer."
git push origin po/gasless_v1_kona-1.2.13 xl/gasless-kona-1.2.13-proof
```

（push 前向用户确认——项目规矩。）

---

### Task 6: op-succinct Cargo.toml 切换

**Files:**
- Modify: `/Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct/Cargo.toml`、`Cargo.lock`

- [ ] **Step 6.1: 替换 kona/op-alloy 分支引用**

把 Cargo.toml 中所有 `branch = "feat/xlayer-gasless-kona-client"`（约 16 处 + `[patch."https://github.com/ethereum-optimism/optimism"]` 段约 26 处）替换为 `branch = "xl/gasless-kona-1.2.13-proof"`：

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct
sed -i '' 's|branch = "feat/xlayer-gasless-kona-client"|branch = "xl/gasless-kona-1.2.13-proof"|g' Cargo.toml
```

- [ ] **Step 6.2: 移除 GitLab evm fork 依赖（回归 monorepo vendor 拷贝）**

逐项修改 Cargo.toml：
1. L195 `alloy-op-evm = { git = "https://gitlab.okg.com/github/evm", branch = "feat/xlayer-gasless-alloy-evm-0.27", ... }` → `alloy-op-evm = { git = "https://gitlab.okg.com/github/optimism", branch = "xl/gasless-kona-1.2.13-proof", default-features = false }`
2. L253 `[patch.crates-io]` 里 `alloy-evm = { git = "https://gitlab.okg.com/github/evm", ... }` → 删除（回到 crates.io 0.27.2，与上游基线一致）
3. `[patch."https://gitlab.okg.com/github/optimism"]` 段中 `alloy-op-evm = { git = ".../evm", ... }` → 删除该条目；若该段只剩这一条则整段删除
4. hokulea patch 段（L308-315）与 `[patch."https://github.com/ethereum-optimism/optimism"]` 段里的 `alloy-op-evm = { git = ".../evm", ... }` → 改为 `{ git = "https://gitlab.okg.com/github/optimism", branch = "xl/gasless-kona-1.2.13-proof" }`

- [ ] **Step 6.3: okx/revm patch 按 Task 1 决策定版**

把 13 条 `rev = "544a2ad5..."` 更新为 Task 1 决定的 rev（分支 tip 或我们的 fix 分支），保持 13 条同源同 rev。

- [ ] **Step 6.4: 重建 lock 并全量质量门**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct
cargo check --workspace --all-targets --all-features 2>&1 | tail -5
cargo fmt --check && typos && cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
```

Expected: 全部通过。重点排查重复 crate（`cargo tree -d | grep -E "alloy-op-evm|op-revm|alloy-evm"` 应无双版本）。

- [ ] **Step 6.5: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "feat(deps): switch gasless support to kona-1.2.13 backport branches

- kona/op-alloy/alloy-op-evm: single source = GitLab optimism fork
  branch xl/gasless-kona-1.2.13-proof (author backport + proof wiring)
- drop GitLab evm fork and its patch redirects (no more API shims)
- op-revm: keep okx/revm gasless branch, pinned per semantic-diff check

No .rs changes in op-succinct."
```

---

### Task 7: gasless devnet（xlayer-toolkit）

**Files:**
- Modify: `$TOOLKIT/devnet/example.env`、`$TOOLKIT/devnet/config-op/*`（链配置与 genesis）

- [ ] **Step 7.1: 配置 reth sequencer 用作者的 gasless 栈**

`$TOOLKIT/devnet/example.env` 设置：

```bash
SEQ_TYPE=reth
SKIP_OP_RETH_BUILD=false
OP_RETH_LOCAL_DIRECTORY=/Users/jimmyshi/code/xlayer-reth
OP_RETH_BRANCH=po/gasless_v1
OP_SUCCINCT_ENABLE=false        # 先手动跑验证，不起 proposer 服务
```

- [ ] **Step 7.2: 设链 id 为 195 并预置白名单合约**

检查 `$TOOLKIT/devnet/config-op/` 的 L2 chain id 配置项，设为 `195`（使 `xlayer_gasless_contract(195)` 命中 devnet predeploy 地址 `0x4200000000000000000000000000000000000700`）。
在 genesis alloc 中预置 GaslessWhitelist 合约 code 到该地址。runtime bytecode 来源（二选一）：
- 作者的 e2e 注入方式：`/Users/jimmyshi/code/xlayer-reth` 仓库 `git show origin/po/gasless_v1 -- crates/tests/e2e-tests/` 中的 gasless 测试（搜 `0700`/`GaslessWhitelist`），照搬其 bytecode 与初始 storage（含白名单条目的写法）；
- 或从 `$OPT` 仓库 `git show okx/po/gasless_v1:packages/contracts-xlayer/GaslessWhitelist/src/GaslessWhitelist.sol` 用 forge 编译取 deployedBytecode。

- [ ] **Step 7.3: 起链**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/xlayer-toolkit/devnet
./clean.sh && ./init.sh && ./0-all.sh
```

Expected: L1 + L2（gasless xlayer-reth sequencer）+ rollup node 全部健康；记录三个 RPC 端点（L1_RPC / L2_RPC / L2_NODE_RPC，从 docker-compose 端口映射读取）。

- [ ] **Step 7.4: 配置白名单并发送 gasless 交易**

按 GaslessWhitelist 合约 ABI（参考 e2e 测试的调用方式）把一个目标合约/地址加入白名单（若 genesis storage 已预置则跳过），然后：

```bash
# 零 gas price 交易（cast 以 legacy 0 价发送；TARGET/PK 用 devnet 预置账户）
cast send $TARGET --gas-price 0 --priority-gas-price 0 --legacy \
  --private-key $PK --rpc-url $L2_RPC --value 0
cast receipt <txhash> --rpc-url $L2_RPC | grep -E "status|effectiveGasPrice|blockNumber"
```

Expected: `status 1`、`effectiveGasPrice 0`，记下 `blockNumber`（记为 `$GB`）。
对照：发送方余额不变（`cast balance` 前后一致）。

---

### Task 8: witness + zkVM 验证

**Files:**
- Create: `$OPS/.env.gasless-devnet`（RPC 端点配置，不 commit）

- [ ] **Step 8.1: 配置 host 环境**

`$OPS/.env.gasless-devnet`：

```bash
L1_RPC=<Task 7.3 记录的 L1 端点>
L1_BEACON_RPC=<同上（toolkit L1 为 geth dev 模式时按其文档取 beacon mock 端点）>
L2_RPC=<L2 执行层端点>
L2_NODE_RPC=<rollup node 端点>
```

- [ ] **Step 8.2: 跑 witness 生成 + range program 原生执行（cost_estimator）**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct
RUST_LOG=info cargo run --release --bin cost_estimator -- \
  --env-file .env.gasless-devnet --start $((GB-2)) --end $((GB+2))
```

Expected: 跑通无 panic / 无 state-root mismatch；输出报告含 cycle 数。
判定：witness 生成（host 原生重放，覆盖验证关 3）+ range program sp1 执行（覆盖验证关 4）同时通过。

- [ ] **Step 8.3: cycle 数对照**

对一段**不含** gasless 交易的同规模区间再跑一次 cost_estimator，两次 cycle 数同数量级（白名单系统调用只增加一次合约调用的开销）。记录两组数字到 notes。

- [ ] **Step 8.4: 负向用例（共识对齐抽查）**

```bash
# (a) 零价 + 未白名单目标：应被 mempool 拒绝（节点侧规则）
cast send $NON_WHITELISTED --gas-price 0 --legacy --private-key $PK --rpc-url $L2_RPC
# Expected: 报错（mempool reject），交易不进块
# (b) 白名单 + gas_limit 超合约限额：同样被拒
cast send $TARGET --gas-price 0 --legacy --gas-limit 30000000 --private-key $PK --rpc-url $L2_RPC
```

说明：恶意 batcher 强塞此类交易的全路径（绕过 mempool）在 devnet 上不可构造；执行层的一致性由「proof 与节点共用同一份 executor 代码」结构性保证（设计 §3），以及 Task 2.5 已通过的作者单测覆盖。把以上结论记入 notes。

- [ ] **Step 8.5: op-succinct 回归（集成测试）**

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct
cargo test -p fault-proof --test integration
cargo test -p validity
```

Expected: 与切换依赖前同样的通过集合。

- [ ] **Step 8.6: 记录验证结果**

把 Task 7/8 的端点、区块号、cycle 数、负向用例结论补进 `docs/superpowers/plans/notes/gasless-verification-results.md` 并 commit：

```bash
git add docs/superpowers/plans/notes/gasless-verification-results.md
git commit -m "docs: record gasless backport verification results"
```

---

### Task 9: 上行 MR 与收尾

- [ ] **Step 9.1: 给作者准备两个上行 MR（okx/optimism po/gasless_v1）**

把 B1、B2 两个 commit 适配到作者基线（他的 `core.rs`/`factory.rs` 与 v1.2.13 几乎同构，预期零冲突 cherry-pick）：

```bash
cd /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/optimism-fork
git checkout -b po/gasless_v1-proof-wiring okx/po/gasless_v1
git cherry-pick <B1-hash> <B2-hash>
cd rust && cargo check -p kona-client -p kona-executor
git push okx po/gasless_v1-proof-wiring   # 推到 okx/optimism 需要权限；无权限则推到我们的 GitHub fork 后开 PR
```

PR 描述要点：po/gasless_v1 当前 kona-client 因 `XLayerGaslessFeeHookFactory` bound 编译失败；proof 路径缺 `with_gasless_contract` 注入——附本计划验证结果。

- [ ] **Step 9.2: 更新设计文档状态**

`docs/superpowers/specs/2026-06-12-gasless-kona-backport-design.md` 状态改为「已实施」，附分支/commit 清单与验证结果链接；commit。

- [ ] **Step 9.3: 旧分支封存说明**

在 GitLab fork 的 `feat/xlayer-gasless-kona-client` 分支不删除；op-succinct 侧确认无任何引用残留：

```bash
grep -rn "feat/xlayer-gasless-kona-client\|gitlab.okg.com/github/evm" /Users/jimmyshi/meili/jimmy.shi_dacs_at_okg.com/117/Documents/code/op-succinct/Cargo.toml
```

Expected: 空输出。

---

## 风险与回退

- 任何 Task 失败不影响 main：op-succinct 的改动只有 Task 6 一个 commit，`git revert` 即回到现状（现状 = 旧 720a9e4 方案，可编译）。
- Task 2.3 的冲突若超预期（0.26.3 executor 结构差异过大），升级处理：把 `execute_transaction_without_commit` 的 0.26.3 版本整体对照作者版本重写该函数，保持 hunk 语义清单逐项落位，不引入清单外改动。
- Task 8.2 若 state root mismatch：优先比对 `is_gasless` 判定路径（在 host 原生模式打日志），其次回查 Task 1 的语义 diff 结论。
