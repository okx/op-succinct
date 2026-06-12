# op-revm Gasless 语义 Diff 检查记录

> gasless kona backport (N1) — Task 1 前置检查。
> 目的：确认「新」vendored op-revm 改动（revm 38 基线）与「旧」okx/revm 分支（revm 34 基线，op-succinct 将通过 `[patch.crates-io]` 引用）语义一致，否则 proof 与生产节点行为分歧。

## 1. Diff 来源

| | 新（vendored，optimism monorepo） | 旧（okx/revm 分支） |
|---|---|---|
| Repo | github.com/okx/optimism（本地 `optimism-fork`，remote `okx`） | github.com/okx/revm（本地 `revm-fork`，remote `github`） |
| 区间 | `bac34a117ab25fcc634a23c650cb75ae818faa31` .. `okx/po/gasless_v1` (`0c5c46201eddbc2cf0b1b09d0d42355209c4ab70`) | `github/xl/xl0.0.5.1` (`50405a27f57f80a96ab9d91e93180bca22217a3a`) .. `github/xl/gasless_xl0.0.5.1_base` (`5f843535e2fadec1e922a9ec2b5617b9e7d698cc`) |
| 路径 | `rust/op-revm/` | `crates/op-revm/` |
| 基线 | revm 38 时代 | revm 34 时代（kona v1.2.13 兼容） |
| 涉及文件 | `handler.rs`、`transaction/abstraction.rs`（两边相同，无其他文件） | 同左 |

导出命令：

```bash
cd .../optimism-fork
git diff bac34a11..okx/po/gasless_v1 -- rust/op-revm/ > .../op-succinct/.omc/new-op-revm.diff
cd .../revm-fork
git diff github/xl/xl0.0.5.1..github/xl/gasless_xl0.0.5.1_base -- crates/op-revm/ > .../op-succinct/.omc/old-op-revm.diff
```

比对原则：两边基线不同（revm 34 vs 38），只比语义——同一交易输入在两个实现下的状态变化 / 费用 / gas 记账行为必须一致。

## 2. 检查单逐项比对

| # | 语义点 | 结论 | 说明 |
|---|--------|------|------|
| 1 | `OpTransaction.is_gasless` 字段 + `OpTxTr::is_gasless()`（默认 false） | 一致 | 见 2.1 |
| 2 | `effective_gas_price()` gasless 时恒返回 0 | 一致 | 见 2.2 |
| 3 | gasless 时跳过 L1BlockInfo 加载 | 一致 | 见 2.3 |
| 4 | gasless 时跳过 L1/operator 费用扣除 | 一致 | 见 2.4 |
| 5 | gasless 时余额仅校验 `>= tx.value()` | 一致 | 见 2.5 |
| 6 | gas refund 记账（EIP-3529 / EIP-7702） | **有差异** | 见 2.6（关键发现） |
| 7 | gasless 时跳过 `reimburse_caller` | 一致 | 见 2.7 |
| 8 | gasless 时跳过 `reward_beneficiary` | 一致 | 见 2.8 |
| 9 | basefee 检查依赖外部 `disable_base_fee` | 一致 | 见 2.9 |

### 2.1 `is_gasless` 字段与 trait 方法 — 一致

两边在 `transaction/abstraction.rs` 中改动等价：

- `OpTxTr::is_gasless()` 默认实现返回 `false`（两边逐字相同）。
- `OpTransaction<T>` 新增 `pub is_gasless: bool` 字段，`new()` / `Default` / builder（`gasless(bool)` 方法、`build_fill`、`build`）均初始化为 `false`，`OpTxTr for OpTransaction` 实现返回 `self.is_gasless`（两边等价）。

非语义差别：旧分支字段带 `#[cfg_attr(feature = "serde", serde(default))]`（反序列化兼容），新分支无此属性。仅影响 serde 反序列化兼容性，不影响执行语义。

### 2.2 `effective_gas_price()` — 一致

两边均在函数开头、deposit 分支之前插入逐字相同的代码：

```rust
fn effective_gas_price(&self, base_fee: u128) -> u128 {
    if self.is_gasless {
        return 0;
    }
    // Deposit transactions use gas_price directly
    ...
```

- 新：`rust/op-revm/src/transaction/abstraction.rs`（diff hunk `@@ -167,6 +191,10`）
- 旧：`crates/op-revm/src/transaction/abstraction.rs`（diff hunk `@@ -173,6 +189,10`）

### 2.3 跳过 L1BlockInfo 加载 — 一致

两边 `handler.rs` `validate_against_state_and_deduct_caller` 中条件等价：

```rust
let is_gasless = tx.is_gasless();
if !is_gasless && chain.l2_block != Some(block.number()) {
    *chain = L1BlockInfo::try_fetch(journal.db_mut(), block.number(), spec)?;
}
```

- 新：hunk `@@ -143,9 +143,11`；旧：hunk `@@ -141,9 +141,13`。逻辑逐字相同。

### 2.4 跳过 L1/operator 费用扣除 — 一致

两边均把 enveloped-tx 附加成本（L1 fee + operator fee）扣费分支从 `if !cfg.is_fee_charge_disabled()` 改为：

```rust
if !is_gasless && !cfg.is_fee_charge_disabled() {
    let Some(additional_cost) = chain.tx_cost_with_tx(tx, spec) else { ...error... };
    ...
    balance = new_balance
}
```

- 新：hunk `@@ -154,10 +156,10`；旧：hunk `@@ -155,7 +159,7`。
- 分支内错误类型不同（新 `OpTransactionError::MissingEnvelopedTx`，旧 `ERROR::from_string("[OPTIMISM] Failed to load enveloped transaction.")`）属两边基线本身的差异，且 gasless 时该分支整体被跳过，不构成 gasless 语义差异。

### 2.5 gasless 余额仅校验 `>= tx.value()` — 一致

两边替换 `calculate_caller_fee` 的代码逐字相同：

```rust
let balance = if is_gasless {
    if !cfg.is_balance_check_disabled() && balance < tx.value() {
        return Err(InvalidTransaction::LackOfFundForMaxFee {
            fee: Box::new(tx.value()),
            balance: Box::new(balance),
        }
        .into());
    }
    balance
} else {
    calculate_caller_fee(balance, tx, block, cfg)?
};
```

- 新：hunk `@@ -171,7 +173,18`；旧：hunk `@@ -171,7 +175,18`。
- 均保留 `cfg.is_balance_check_disabled()` 开关、相同错误变体、相同判断顺序。
- 两边测试 `test_gasless_validate_against_state_does_not_deduct_fees` 断言一致（balance 7 不变、nonce +1）。

### 2.6 gas refund 记账 — **有差异（关键）**

**旧分支（okx/revm，op-succinct 将引用的一侧）：gasless 仍正常记账 gas refund。**

`crates/op-revm/src/handler.rs`：

- `last_frame_result`（成功路径）**无条件**保留：
  ```rust
  gas.erase_cost(remaining);
  // Gasless txs are not charged or reimbursed fees, but gas accounting
  // (including the EIP-3529 gas refund) must still be applied so that the
  // reported gas usage is correct.
  gas.record_refund(refunded);
  ```
- `refund()` **无条件**执行（仅加注释）：
  ```rust
  // Gasless txs still apply gas refunds (only fee charge/reimbursement is skipped),
  // so the reported gas usage matches a normal tx.
  frame_result.gas_mut().record_refund(eip7702_refund);
  ... set_final_refund(...)
  ```
- 测试佐证：`test_gasless_consume_gas_applies_gas_refund` 断言 `gas.refunded() == 2`（min(20, 10/5)，与普通 tx 相同）；`test_gasless_refund_applies_eip7702_refund` 断言 `refunded() == 10`。

**新分支（vendored，okx/optimism po/gasless_v1）：gasless 完全不记 refund。**

`rust/op-revm/src/handler.rs`：

- `last_frame_result`（成功路径）：
  ```rust
  gas.erase_cost(remaining);
  if !is_gasless {
      gas.record_refund(refunded);
  }
  ```
- `refund()` 整体跳过（EIP-7702 refund 记录 + `set_final_refund` 都不执行）：
  ```rust
  if evm.ctx().tx().is_gasless() {
      return;
  }
  frame_result.gas_mut().record_refund(eip7702_refund);
  ...
  ```
- 测试佐证：`test_gasless_consume_gas_without_refund` 断言 `gas.refunded() == 0`。

**影响分析：** `gas.refunded()` 直接进入最终 `gas_used = spent - refunded`，进而影响 receipt 的 `gasUsed` / `cumulativeGasUsed`（receipts root）与区块头 `gasUsed`。对同一笔带 SSTORE 清零等产生 refund 的 gasless 交易：

- 旧分支（proof 侧）：报告的 gasUsed 较小（refund 生效，与普通 tx 相同口径）。
- 新分支（vendored 侧）：报告的 gasUsed 较大（refund 被吞掉）。

→ 两边推导出的 output root 必然分歧。这不是上下文/签名差异，而是**实打实的状态承诺分歧**。

注：gasless 本身跳过 `reimburse_caller` / `reward_beneficiary`，因此该差异**不影响任何账户余额**，只影响 gas 记账与 receipts/区块头。

另注：检查单第 6 项的预期语义（"refund 仍记录但不退款"）与**旧分支**行为吻合；**新分支偏离了该预期**。

### 2.7 跳过 `reimburse_caller` — 一致

两边 `reimburse_caller` 开头均为：

```rust
if evm.ctx().tx().is_gasless() {
    return Ok(());
}
```

- 新：hunk `@@ -263,6 +279`；旧：hunk `@@ -250,6 +268`。其余函数体（operator fee refund 计算）为基线差异（`let mut` vs `let-else` 风格），行为相同。
- 两边测试 `test_gasless_reimburse_and_reward_are_noops` 断言一致（caller/beneficiary 余额均为 0）。

### 2.8 跳过 `reward_beneficiary` — 一致

两边逐字相同：

```rust
let (is_deposit, is_gasless) = {
    let ctx = evm.ctx();
    let tx = ctx.tx();
    (tx.tx_type() == DEPOSIT_TRANSACTION_TYPE, tx.is_gasless())
};
if is_deposit || is_gasless {
    return Ok(());
}
```

- 新：hunk `@@ -300,10 +324`；旧：hunk `@@ -294,10 +318`。

### 2.9 basefee 检查 — 一致

两边 diff 均**未改动** `validate_env`：gasless 的 `gas_price=0 < basefee` 放行均依赖外部设置 `cfg.disable_base_fee`（Hook/调用方负责），op-revm 内不做 gasless 特判。

- 旧分支用测试明确锁定该契约：`test_gasless_cfgdisablebasefeecheck_rejected`（不开 `disable_base_fee` 时 gasless tx 报 `GasPriceLessThanBasefee`）与 `test_gasless_cfgdisablebasefeecheck_succeed`（开了则通过，`optional_no_base_fee` feature 下）。
- 新分支无对应测试，但同样没有在 `validate_env` 中加 gasless 旁路，契约一致。

## 3. 检查单之外的语义观察

逐 hunk 过完两份 diff，新 diff 中**没有**检查单之外的新增执行语义（无新的跳过项、无新字段语义）。非语义差别记录如下：

1. **serde 属性**：旧分支 `is_gasless` 字段带 `serde(default)`，新分支没有。仅影响带 serde feature 时对旧序列化数据的反序列化兼容，不影响执行。
2. **文档注释**：新分支字段 doc 明确写了 "suppresses the gas refund"，与新分支代码一致（也佐证 2.6 的差异是新分支有意为之，不是手误）。
3. **测试覆盖差**：旧分支多 `validate_env` 两个测试与 EIP-7702 refund 测试；新分支测试断言 refund 为 0。测试本身不构成语义，但断言方向相反，进一步确认 2.6。
4. 新基线 `last_frame_result` 中出现 `reservoir` / `state_gas_spent`（revm 38 的 gas reservoir 机制），属基线差异，gasless diff 未触碰。

## 4. 结论与决策

**结论：9 项中 8 项一致，第 6 项（gas refund 记账）存在真实语义差异 → 决策为「需修复」。**

不能直接 pin `5f843535e2fadec1e922a9ec2b5617b9e7d698cc` 后认为与 vendored 实现等价；必须先对齐 refund 语义，否则 gasless 交易（凡产生 EIP-3529/EIP-7702 refund 的）在 proof 侧与 vendored 侧会得出不同的 receipts root / 区块头 gasUsed，output root 分歧。

### 4.1 前置待确认（决定修哪一边）

两个实现方向相反，**必须以 X Layer 生产执行客户端（Go 侧 op-geth gasless 实现）的 refund 行为为准**：

- 若生产节点 gasless tx **不记 refund**（gasUsed 不扣 refund）→ 修旧分支（patch 见 4.2）。
- 若生产节点 gasless tx **仍记 refund**（与普通 tx 同口径）→ 旧分支是对的，反而需要修 vendored 新分支（在 monorepo 提 fix）。

旧分支注释（"so that the reported gas usage is correct"）与新分支注释（"suppresses the gas refund"）都声称有意为之，作者前后两次实现自相矛盾，需要作者/Go 实现裁决。

### 4.2 若以新分支为准：旧分支最小 patch（仅记录，不在本任务实施）

目标 repo/分支：github.com/okx/revm `xl/gasless_xl0.0.5.1_base`，文件 `crates/op-revm/src/handler.rs`。

1. `last_frame_result`：在函数头部取 `let is_gasless = tx.is_gasless();`，成功路径中把
   ```rust
   gas.record_refund(refunded);
   ```
   改为
   ```rust
   if !is_gasless {
       gas.record_refund(refunded);
   }
   ```
2. `refund()`：函数开头加
   ```rust
   if evm.ctx().tx().is_gasless() {
       return;
   }
   ```
3. 同步反转两个测试断言：
   - `test_gasless_consume_gas_applies_gas_refund` → 期望 `refunded() == 0`（并更名为 `..._without_refund`）;
   - `test_gasless_refund_applies_eip7702_refund` → 期望 `refunded() == 0`。

patch 落地后需重新 pin 新的分支 tip rev（不再是 `5f843535e2fadec1e922a9ec2b5617b9e7d698cc`）。

### 4.3 若以旧分支为准

旧分支可直接 pin `5f843535e2fadec1e922a9ec2b5617b9e7d698cc`，但需向 monorepo `po/gasless_v1` 提 fix（去掉 `last_frame_result` 的 `!is_gasless` 门控与 `refund()` 的早退），否则两套 Rust 实现仍不一致。

### 4.4 对后续任务的影响

在 4.1 裁决落地之前，后续「op-succinct 通过 `[patch.crates-io]` 引用 okx/revm」的任务**可以继续做引用接线**，但不得宣称语义对齐完成；上线前必须用裁决后的 rev 重跑本检查。
