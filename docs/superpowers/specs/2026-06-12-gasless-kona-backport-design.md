# 设计：X Layer Gasless 交易的 op-succinct proof 支持（N1 backport 方案）

日期：2026-06-12
状态：待评审
方案代号：N1（backport 到 kona v1.2.13 基线）

## 1. 背景

X Layer 的 gasless 功能（零 gas price 交易 + 链上白名单合约授权）改变了区块执行语义，
op-succinct 的 proof 程序（基于 kona）必须实现完全相同的状态转移函数，否则在含 gasless
交易的区块上 state root 不一致，proof 失败。

### 1.1 gasless 作者的最新方案（po/gasless_v1）

gasless 作者已将整个节点栈统一到 optimism monorepo 血缘（解决了早期"xlayer-reth 走
standalone alloy-op-evm、kona 走 monorepo vendor 拷贝"的血缘分裂问题）：

| 仓库 | 分支 | 内容 |
|------|------|------|
| `github.com/okx/optimism` | `po/gasless_v1` | gasless 唯一来源：vendored `rust/op-revm`（费用语义，+213 行）、vendored `rust/alloy-op-evm`（白名单检测 + GaslessFeeHook，~470 行）、`rust/op-reth`（sequencer 接线）、`rust/kona/bin/client/src/fpvm_evm/tx.rs`（set_gasless）、`packages/contracts-xlayer/GaslessWhitelist`（白名单合约） |
| `github.com/okx/reth` | `po/gasless_v1` | reth v2.1.0 + 1 个 mempool basefee patch |
| `github.com/okx/xlayer-reth` | `po/gasless_v1` | 以 `deps/optimism` path 形式 vendor okx/optimism |
| `github.com/okx/revm` | `xl/gasless_xl0.0.5.1_base` | 旧的 op-revm gasless 分支（revm 34 / op-revm 15 基线），monorepo vendor op-revm 之前的产物 |

### 1.2 gasless 检测规则（共识规则）

一笔交易是 gasless 当且仅当（在 block executor 内执行期判定）：

1. 非 deposit 交易；
2. `max_fee_per_gas == 0`（覆盖 legacy `gas_price == 0` 与 1559 双零）；
3. 白名单合约 `getGaslessAllowance(to, input)` 系统调用（不 commit、gas 不计入
   gasUsed）返回 `allowed == true`；
4. `tx.gas_limit <= 合约返回的 gasLimit`。

is_gasless = true 时 op-revm handler：跳过 L1 块信息加载、跳过 L1/operator 费用扣除、
余额仅校验 `>= tx.value()`、`effective_gas_price` 恒为 0、不退款、不奖励 beneficiary；
gas 计量（含 EIP-3529 refund 记录）照常以保证 gasUsed 正确。basefee 检查由
`XLayerGaslessFeeHook` 在单笔交易作用域内临时设置 `cfg.disable_base_fee` 绕过。

合约地址按 chain_id 推导：devnet 195 → `0x4200...0700`（predeploy）、
testnet 1952 / mainnet 196 → `0x19787404b0c70021b4752028f7e3a92313885B27`。

### 1.3 作者方案在 proof 路径上的两个缺口（本设计要补的）

逐行验证过 `po/gasless_v1`：

1. **`FpvmOpEvmFactory` 未实现 `XLayerGaslessFeeHookFactory`**，而新的
   `BlockExecutorFactory` impl 对 `EvmF` 强制要求该 bound（
   `rust/alloy-op-evm/src/xlayer/gasless.rs:59` 只为 reth 的 `OpEvmFactory` 实现了）
   → kona-client 在该分支上编译不过。`GaslessFeeHook` 的 impl 对 precompile provider
   `P` 是泛型的，补 ~5 行 trait impl 即可。
2. **kona 的 `StatelessL2Builder` 创建 `OpBlockExecutorFactory` 后无人调用
   `.with_gasless_contract(...)`**（全分支搜索：注入点只在 `rust/op-reth/crates/evm/`）
   → 即使编译通过，proof 路径 `gasless_contract = None`，gasless 区块的 proof 必然失败。
   补 ~3 行，照抄 op-reth 的 chain_id 推导逻辑。

### 1.4 版本鸿沟（为什么不直接引用 po/gasless_v1）

| | op-succinct（上游 v4.4.0 / 本 fork） | 作者分支基线 |
|---|---|---|
| kona | `kona-client/v1.2.13`（= commit `348e129`）/ 上游 main 为 v1.2.14 | ~v1.17.0 era monorepo（2026-05 sync） |
| vendored alloy-op-evm | 0.26.3 | 0.31.0 |
| revm | 34 | 38 |

上游 succinctlabs/op-succinct 的 kona 升级节奏保守（2026-01 才到 v1.2.7，现在 v1.2.14，
无大版本升级 PR 在途）。直接吃作者的基线 = op-succinct 独自领先上游、无限期自维护，
本阶段不做（记为 N2，见 §7）。

### 1.5 量化依据（N1 可行性）

- kona v1.2.13 → po/gasless_v1 基线，op-succinct 重度使用的 crate 几乎没动：
  `crates/proof/executor` +17/-24、`crates/proof/proof` +36/-27、`crates/host` 0、
  `crates/protocol/driver` 0、`crates/mpt` 0。
- 作者的 alloy-op-evm gasless 代码按 monorepo vendor API 风格编写（`ExecutableTx` /
  `OpTxResult` / `into_parts`），v1.2.13 的 vendor 拷贝已具备同族 API，backport 冲突预期小。
- revm 38 precompile 锁定的 crypto crate（substrate-bn 0.6.0 / k256 0.13.4 /
  sha2 0.10.9）与 op-succinct 现有 sp1-patches 目标完全相同（该结论主要服务于 N2）。

## 2. 目标与非目标

**目标**
1. op-succinct 在含 gasless 交易的区块上能正确生成 witness 和 proof（state root /
   output root 与节点一致）。
2. proof 路径与 reth 节点跑同一套检测代码（白名单系统调用），无无状态捷径，
   恶意 batch 构造的边缘交易（零价未白名单 / 超 gas 限额）在两边行为一致。
3. op-succinct 仓库本身只改 `Cargo.toml`（0 个 .rs 改动）。
4. 我们的改动与作者的改动在分支上物理隔离，便于 review 与跟踪上游。

**非目标**
- 不升级 op-succinct 的 kona / revm / alloy 版本线（那是 N2）。
- 不动 hokulea / hana（kona 版本不变，它们继续可用）。
- 不引入自有的 revm 层 basefee bypass 变体（跟随作者的 Hook 设计）。

## 3. 总体结构（终态依赖图）

```
op-succinct（只改 Cargo.toml）
│
├── kona-* / op-alloy-* ──→ GitLab optimism fork，分支 B（见 §4）
│                            └── rust/alloy-op-evm/（vendor）← gasless 检测 + hook
│
├── [patch.crates-io] op-revm / revm-* ──→ okx/revm `xl/gasless_xl0.0.5.1_base`
│                            （revm 34 线，作者已有分支，直接引用；见 §5 前置检查）
│
└── 删除：GitLab evm fork 依赖及其 patch 重定向段、
          旧 evm fork 上的全部兼容 shim commit（OpTxError / phantom Tx / 版本 bump）
```

依赖源从 3 个降到 2 个；所有 API shim 消失。

## 4. 分支策略（两层隔离）

```
348e129（= kona-client/v1.2.13 tag）
   │
   ▼
分支 A：po/gasless_v1_kona-1.2.13            ← 只含作者的改动（cherry-pick + 版本适配）
   │   A1. backport(alloy-op-evm)：xlayer_gasless_contract.rs（193 行）、
   │       xlayer/gasless.rs（167 行）、block/mod.rs executor 集成（~100 行），
   │       适配 0.26.3 vendor API；commit message 注明 adapted-from 原 hash
   │   A2. backport(kona)：bin/client tx.rs 的 set_gasless + struct literal 补字段
   │       （用作者的版本，与其主线逐字一致）
   ▼
分支 B：xl/gasless-kona-1.2.13-proof          ← 只含我们的改动，op-succinct 指向这里
       B1. kona：impl XLayerGaslessFeeHookFactory for FpvmOpEvmFactory（~5 行）
       B2. kona：StatelessL2Builder 注入
           .with_gasless_contract(xlayer_gasless_contract(chain_id).map(GaslessContract::new))
           （~3 行，与 op-reth 的推导逻辑一致）
```

约定：
- `git diff A..B` 恒等于"我们的净增改动"。
- cherry-pick 的冲突解决 / API 适配属于作者改动的一部分，留在 A。
- 作者主线更新时：重做 A 的 cherry-pick，B rebase 到新 A。
- 旧分支 `feat/xlayer-gasless-kona-client` 与 GitLab evm fork 分支废弃（保留不删，
  历史参考）。

**明确不 backport 的内容**：
- 作者的 `rust/op-reth/*` 改动（sequencer/mempool 侧，proof 不需要）；
- 旧分支上的 `gas_price == 0` decoder 检测（commit 5698231，被白名单检测取代，
  存在共识分歧攻击面）；
- jimmy 的 revm v2 `validate_env` bypass commit（作者设计用 Hook 处理 basefee，
  不引入变体）。

## 5. op-revm 层（前置检查）

v1.2.13 monorepo 不 vendor op-revm（op-revm 15.0.0 来自 crates.io），维持现状：
`[patch.crates-io]` 指向 okx/revm `xl/gasless_xl0.0.5.1_base`（revm 34 / op-revm 15，
与 op-succinct 需求版本完全匹配）。

**前置检查（实现的第一步）**：对作者新的 vendored op-revm 改动（handler.rs +157 /
abstraction.rs +56，revm 38 基线）与旧 okx/revm 分支做语义 diff：
- 语义一致 → 直接引用旧分支（pin 到 rev）；
- 有演进（如字段/跳过逻辑变化）→ 把差异作为最小 commit 提 MR 到 okx/revm 分支，
  与作者确认合入。

## 6. 给作者的上行 MR

把 B1、B2 的内容同时以 MR 形式提给 okx/optimism `po/gasless_v1`（§1.3 的两个缺口），
让作者主线变成 proof-complete。这不阻塞 N1 主线，但为 N2 铺路、并避免作者后续重构
破坏 proof 路径而不自知。

## 7. 验证方案（完成标准）

1. **编译关**：`cargo fmt --check`、`typos`、`cargo check --workspace --all-targets
   --all-features`、`cargo clippy -- -D warnings`、`cargo nextest run --all-features`；
   range ELF 构建成功。
2. **devnet 关**：用作者 po/gasless_v1 栈起本地 gasless devnet（chain_id 195，
   白名单合约 predeploy `0x4200...0700`，作者提供了 mock whitelist 合约），
   发送 gasless 交易（零 gas price + 白名单目标）并出块。
3. **witness 关**：op-succinct host 对含 gasless 交易的区块跑 witness 生成
   （native 模式），与节点 state root 一致；确认白名单合约 storage 经 TrieDB 进入
   witness（host 侧零改动的设计预期）。
4. **zkVM 关**：range program `sp1 execute`（不出证明）跑过含 gasless 交易的区间，
   output root 一致；cycle 数与同规模普通区块对比无数量级异常。
5. **负向用例**：(a) 零价但未白名单的交易；(b) 白名单但 gas_limit 超限额的交易——
   两者在节点与 proof 程序上行为一致（同被拒绝/同样非 gasless 执行）。
6. **回归**：`cargo test -p fault-proof --test integration`、`cargo test -p validity`。

**完成标准**：第 3、4 关在含 gasless 交易的区块上通过（解决"正确性未验证"）；
改动面 = 一个 fork 两个分支共 4 个 commit + op-succinct Cargo.toml（解决"改动太大"）。

## 8. 风险与对策

| 风险 | 对策 |
|------|------|
| 旧 okx/revm 分支与作者新 vendored op-revm 语义漂移 | §5 前置语义 diff，差异以最小 MR 上行 |
| 0.26.3 vendor API 适配引入行为偏差 | §7 devnet/witness/zkVM 三关 + 负向用例兜底 |
| 作者主线继续演进（合约地址、检测规则变化） | op-succinct pin rev 而非 branch；A/B 分支重建流程已定义（§4） |
| backport 是语义拷贝，长期与生产线漂移 | 上行 MR（§6）让作者主线 proof-complete；终态走 N2 收敛 |

## 9. 演进路线（N2，本期不做）

当出现以下任一条件时启动 N2（op-succinct 全栈升级到作者 monorepo 线）：
- 上游 succinctlabs/op-succinct 升级 kona 至接近作者基线的版本；
- gasless 主线与 backport 分支的同步成本明显超过一次性升级成本。

N2 时：kona-*/op-alloy-*/alloy-op-evm/op-revm 全部指向 okx/optimism 单一源，删除
okx/revm patch 13 项与本 backport 分支，砍掉 hokulea/hana（X Layer 只用 ethereum DA，
`default = ["ethereum"]` 已验证），op-succinct 约 36 个文件做 API 适配。届时 §6 的
上行 MR 与本期的 devnet 验证设施全部复用。

## 10. 决策记录

- 否决「无状态 `gas_price == 0` 检测」（旧方案）：与 reth 共识规则在"零价未白名单/
  超限额"交易上分歧，恶意 batch 可构造 state root 分歧，对 fault-proof 系统是
  soundness 漏洞。
- 否决「kona 直接依赖 okx/evm standalone 分支」（旧 A1）：alloy-evm core 0.26/0.27
  版本冲突 + vendor/standalone API 分叉，必然带来版本 bump 与 shim，且引入
  vendor↔standalone 行为漂移风险。
- 否决「立即 N2」：上游 op-succinct 停在 kona v1.2.14 且无升级迹象，N2 意味着无限期
  独自领先上游；N1 工作量约为 N2 的 1/2~1/3 且全部验证设施可复用。
