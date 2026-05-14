---
name: "prediction-market"
description: "TradeZone 预测市场业务规则：市场生命周期、撮合方式、NegRisk、订单类型、STP、状态机、代理授权——ZK 证明必须正确执行的链上业务逻辑"
source: "tradezone/context-kg/business/prediction-market.md"
---
# 预测市场业务规则 — ZK 证明参考

> **视角说明**：本文描述 TradeZone L2 的预测市场业务逻辑。对 op-succinct 而言，这是 `process_block()` 必须正确执行的链上规则——Guest Client 的执行结果必须与这些规则完全一致，ZK 证明才有意义。

## 什么是预测市场（Prediction Market）

> 一句话：像 Polymarket 一样，让你用真金白银押注"某件事会不会发生"，价格就是市场对概率的共识。

预测市场是一种用交易来预测事件结果的金融工具。比如"明天比特币能否突破 10 万美元？"，参与者通过买卖 YES/NO 代币来表达观点，价格反映市场对事件发生概率的共识。

**核心机制：**

- 每个市场有两种结算代币：YES token 和 NO token
- 价格范围 (0, 1)，代表概率。YES@0.60 意味着市场认为有 60% 概率发生
- YES 价格 + NO 价格 = 1（互补关系）。如果 YES@0.60，那 NO 等价于 @0.40
- 结算时，赢的一方 token 价值 = 1 USDC，输的一方 = 0

## Governance 治理操作（对应 CASE-00-00）

> 一句话：平台管理员的"控制面板"，用来调整全局运行参数，类似 Polymarket 后台调整结算延迟或链上桥接配置。

Governance 是 Operator（平台运营方）专用的管理动作，用于热更新链级全局参数，无需重启服务。可调参数（与 `governance.rs:19-60` 字段一一对应）：

**预测市场相关：**

- **prediction_resolve_delay_ms**：NegRisk 市场从 report → resolve 的等待延迟（毫秒）。类似 Polymarket 的 UMA 争议窗口期——结果公布后留出一段时间供社区质疑，防止错误结算造成不可逆损失。Report 后市场仍保持 Active 状态可交易，延迟期满后 Resolve 才冻结交易并结算。

**链级运行参数：**

- **app_hash_interval**：每隔多少个区块计算一次状态哈希，用于节点间一致性校验。
- **state_clean_interval**：每隔多少个区块做一次状态清理（slab 空闲列表整理、生成快照）。
- **bridge_cursor**：链上桥接事件扫描的游标（block_number / tx_index / event_index）。控制从哪个区块开始扫描 L1 上的充值/提现事件，类似重置同步进度条。

**费用与限流：**

- **fee_recipient**：主手续费收款地址（必须非零）。
- **withdraw_fee**：提现手续费（USDC 微单位，存储在 Bridge）。
- **limits**：全局限流参数的部分更新（Action 权重、TPS 等），仅 `Some` 字段会被应用。
- **user_open_orders_limits**：按用户粒度覆写 `UserState.open_orders_limit`。

**用户限流定向干预 / 显式重置：**

- **[Rule] user_granted_actions**：按用户粒度增发 action-limit 单位（additive）。完整公式：`action_limit = initial_action_limit + compute_volume_bonus(vlm) + purchased_actions + granted_actions`（`limits.rs:240-244, 354-358`）。`granted_actions = 0` 表示清除（存为 `None`），`> 0` 表示设定值；写入后会发出 `GovernanceParam::UserGrantedActions { user, old, new }` 事件（`event/meta.rs:84-92`）。
- **[Rule] reset_limits**：把 `Limits` 中任意子集的 9 个标量字段（`InitialActionLimit` / `ThrottleIntervalMs` / `CancelLimitAdd` / `RequestWeightPrice` / `InitOpenOrdersLimit` / `VolumePerExtraOrder` / `MaxOpenOrdersLimit` / `DailyCancelAllLimit` / `PredictionVolumeMultiplier`）显式重置为 `None`，回退到对应硬编码 `DEFAULT_*`（`limits.rs:120-153`）。**冲突规则**：同一字段不能同时出现在 `limits`（set）和 `reset_limits`（reset）中，否则 validate 拒绝并返回 `"cannot both set and reset limit field {LimitField}"`（`governance.rs:64-78`）。
- **[Rule] remove_action_weights**：从 `action_weights` 映射中删除指定 key，删除后该 Action 回退到 `DEFAULT_ACTION_WEIGHT`（`governance.rs:305-308`）。**校验**：key 必须是合法的 `Action::TYPE_NAMES`；同一 key 不能既在 `limits.action_weights`（set）又在 `remove_action_weights`（remove）中，否则 validate 拒绝（`governance.rs:80-95`）。

测试验证：

1. Operator 修改 resolve_delay_ms → 查询确认生效
2. Operator 修改 bridge_cursor → 查询确认更新
3. 非 Operator 发送 Governance → 被拒绝（只有管理员能改系统参数）

## 市场生命周期（对应 CASE-00-01）

> 一句话：一个预测市场从出生到结束的完整流程——创建、开放交易、铸造/销毁代币、宣布结果、兑奖。

```
创建市场 → 初始化 → 暂停(paused) → 激活(active) → 交易 → 结算(settled) → 赎回
```

### 1. 创建与初始化

> 一句话：在链上注册一个新的"押注问题"，并配置好用什么币做抵押、精度多少。

- **CreatePredictionMarket**：注册一个新市场，绑定 oracle（预言机）、condition token 等链上合约地址
- **InitPredictionMarket**：设置抵押品（USDC）、精度（token_decimal=2，即最小交易单位 0.01）。**[Constraint]** 测试网 / Dev 链上 `market_id` 必须 < **90 000**（`TESTNET_MARKET_ID_CAP`，`init_prediction_market.rs:28-30`，原值 100 000）；主网 `market_id` 从 90 000 起步以避免与中台 `asset_id` 冲突，Mainnet 路径无此上限。
- **[Rule]** 市场初始状态为 **Active（创建后默认可交易）**。

### 2. 激活交易

> 一句话：管理员开放交易，用户充钱进来准备押注。

- **ChangePredictionMarketStatus(Unpause)**：开放交易
- 用户先通过 Deposit 充入 USDC

### 3. Split（拆分）— 铸造代币

> 一句话：花 1 块钱铸造出 1 个 YES + 1 个 NO，就像买一张双面彩票，无论哪面中奖你都能兑 1 块。

> 用户花 5 USDC → 获得 5 YES + 5 NO

这是预测市场的核心操作。1 USDC 永远可以拆分为 1 YES + 1 NO，因为无论结果如何，YES+NO 的总价值恒等于 1 USDC。这保证了系统的资金守恒。

### 4. Merge（合并）— 销毁代币

> 一句话：Split 的反向操作——把一对 YES+NO 交回去，换回 USDC。

> 用户交出 2 YES + 2 NO → 取回 2 USDC

任何时候都可以把等量的 YES+NO 合并回 USDC。

### 5. Resolve（结算）

> 一句话：事件结束了，管理员宣布"YES 赢了"或"NO 赢了"。

- 运营方（Operator）调用 ResolvePredictionMarket，宣布结果
- `payouts: [1, 0]` 表示 YES 赢、NO 输

### 6. Redeem（赎回）

> 一句话：拿着中奖的代币去兑换 USDC，输家的代币自动归零。

> 用户持有 3 YES（赢方）→ 赎回 3 USDC
> 用户持有的 NO（输方）→ 价值归零

## NegRisk 多结果市场（对应 CASE-00-02）

> 一句话：像 Polymarket 的"谁当选总统？"——一个问题有多个互斥答案，最多只有一个 YES 能赢。

NegRisk（负风险）是更复杂的场景：一个事件有多个互斥结果。

```
Event: "谁当选？"
  Market 0: 候选人 A → YES/NO
  Market 1: 候选人 B → YES/NO
  Market 2: 候选人 C → YES/NO
```

**[Invariant] 核心约束**：同一 Event 内最多只有 **1 个 YES** 能赢。

**[Rule] 结算流程（per-instance，可分阶段执行）：**

1. **Report**：Operator 调用 `ReportPredictionMarket` 录入 `payouts` 与 `reported_at`，对应市场仍保持 `Active` 可交易（status 不变，仅 `reported_at.is_some()`）。每个子市场独立 report，互不依赖。
2. **Resolve**：每个子市场只要满足"自身已 report + 等待 `prediction_resolve_delay_ms`"即可被单独 resolve；**不要求**同 Event 下所有子市场都 reported 之后才能开始 resolve（即支持交替/部分 resolve）。代码路径见 `resolve_prediction_market.rs:240-247` 的 per-instance gate；显式断言见 `test_negrisk_partial_resolve`（同文件 1368 行）。

**[Invariant] 互斥保证（`determined` 不变量）：**

"同一 Event 最多 1 个 YES" 这条铁律由 `Event.determined` 字段守护，而非由"全部 reported 后才 resolve"守护。任何一个子市场以 `payouts == [1, 0]` 成功 resolve 后，Event 上的 `determined` 被置位（`resolve_prediction_market.rs:124-130`）；之后无论是普通路径还是 emergency 路径，再尝试以 YES 解析同 Event 下任何其它子市场都会立即被拒绝（`AlreadyExists` 错误）。这意味着：

- A 赢了 → B、C 不需要先各自 report 才能 resolve；只要它们 report 了 NO（`[0, 1]`）即可任意时刻 resolve。
- 没有 report 的子市场可以保持 Active 继续交易，等 oracle 结果到达再独立 report+resolve。

额外操作：**Convert**（跨市场转换）— 将 source 市场的 NO token 转换为 target 市场的 YES token，用于对冲。类似"我不看好 A 和 B，所以把他俩的 NO 换成 C 的 YES"。

## Event ↔ Market 关系（NegRisk 多元市场的容器）

> 一句话：Event 是一个"问题组"容器，把多个互斥的子市场绑定到一起；同一 Event 内的 `determined` 状态保证最多只有一个 YES 能赢。

NegRisk 多结果市场不是一个孤立的 Market，而是一个 **Event 聚合多个 Market**：

- **Event** = 问题组（"谁当选？"），由 Relayer 在响应 L1 事件时通过 `CreatePredictionEvent` 创建。
- **Market** = 单个互斥候选项（"候选人 A → YES/NO"）。
- 二者通过 `RegisterPredictionMarket` 在链上建立关联：Relayer 把已 `Init` 的占位市场（key 为 `requestId = hash(desc)`）替换为 NegRisk 真实 marketId（来自 L1 `MarketPrepared` 事件），并写入该 market 在 Event 中的 `index`。
- 同一 Event 下的所有 Market 共享 wrap-collateral 与 `determined` 标记位；`determined` 一旦在 resolve 阶段被置为某个 YES，本 Event 内其它 Market 就不再可能再判出第二个 YES（`resolve_prediction_market.rs:124-130`）。

## Relayer / Operator 后台 Action（链上桥接面）

> 一句话：以下 Action 不由终端用户直接调用，而由 Relayer 或 Operator 响应 L1 事件 / 后端指令提交，是预测市场链上桥接面的主要入口。

| Action | 调用方 | 用途 |
|---|---|---|
| **CreatePredictionEvent** | Relayer（Operator-only） | 响应 L1 事件，创建一个预测事件（问题组），绑定 `adapter` + `original_event_id` + `ancillary_data`（标题/描述）。 |
| **CreatePredictionMarket** | Relayer | 创建市场模板并绑定 oracle、condition token 等链上合约地址。 |
| **InitPredictionMarket** | Relayer | 初始化市场：设置抵押品（USDC）、精度（`token_decimal`）。 |
| **RegisterPredictionMarket** | Relayer | 把已创建的市场模板登记到指定 Event，建立 event → market 的关联（NegRisk 必备）。`index` 上限 10 000 防 OOM。 |
| **ReportPredictionMarket** | Operator | 录入 `payouts` 与 `reported_at`；market 仍保持 `Active` 可交易。|
| **ResolvePredictionMarket** | Operator | 冻结交易并结算；NegRisk 子市场可在自身 `reported_at` 满足 `resolve_delay_ms` 后单独 resolve。 |
| **ChangePredictionMarketStatus** | Operator | 在 Paused ↔ Active 切换；以及 normal ↔ flagged 的独立标记。 |
| **UpdatePredictionMarket** | Relayer | 更新市场模板的 `ancillary_data` 等元数据字段（不改交易状态）。 |
| **UpdatePredictionMarketFeeRate** | PM 后端 | 更新指定市场实例的 maker / taker 费率，至少提供其一；费率非负且不超过 100%。 |

## 紧急结算（Emergency Resolve）

> 一句话：当某个市场陷入争议或卡死时，Admin 可标记 Flagged → 等待延迟期 → 用 `emergency=true` 旁路结算，仅处理被 Flagged 的实例，不影响其它正常市场。

**[Rule]** `ResolvePredictionMarket` 的 `emergency` 字段决定走哪条结算路径（`resolve_prediction_market.rs:30-40`）：

- `emergency = false`（普通路径）：只处理 **非 Flagged** 的实例。Binary 要求 `status == Active`，NegRisk 要求 `reported_at.is_some()`。
- `emergency = true`（紧急路径）：只处理 **Flagged** 的实例（Admin 兜底）。

**典型流程：**

1. Admin 通过 `ChangePredictionMarketStatus` 把 `flag_status` 设为 `Flagged`，并写入 `flagged_at` 时间戳。
2. 等待 `flagged_at + prediction_resolve_delay_ms` 延迟期满（与普通结算共用同一延迟参数，提供争议窗口）。
3. Admin 提交 `ResolvePredictionMarket{ emergency: true, payouts, source_tx_hash: None }`：
   - 遍历该 Event/Market 下的实例，**仅** 选取 `flag_status == Flagged` 的实例（`resolve_prediction_market.rs:236-246`）。
   - 与普通路径共享同一个 `determined` 不变量检查 — 即便走 emergency，"同 Event 最多 1 个 YES" 仍然守得住（`resolve_prediction_market.rs:124-130` 注释明示"determined 字段被普通和紧急路径共用"）。
4. 紧急结算时 `source_tx_hash` 可为 `None`（无链上来源交易），其它字段约束与普通结算一致。

**用途：** 处理 oracle 失效、L1 上报错乱、争议窗口内被运营方质疑等需要 Admin 接管的边界情形。普通路径与紧急路径互斥（按 `flag_status` 分流），不会重复结算。

## BatchRedeem（运营方批量赎回）

> 一句话：Operator 一次性帮一批用户赎回已 Settled 市场的中奖代币，用于灾备/迁移场景下的 gas 摊销。

- **[Rule] 调用权限**：仅 Operator（`is_operator(ctx.user())`）
- **入参**：`market_id`（必须是 Settled 状态）+ `count`（>0，本次最多赎回多少个用户）
- **行为**：在该市场上为 `count` 个未赎回的用户依次执行赎回，逐用户产生与单用户 `PredictionRedeem` 兼容的事件流；返回实际赎回的用户数 `redeemed_count`。
- **[Constraint] 校验**：market 必须已 Settled；`quote_wei_decimals` 不超过 `Decimal::MAX_SCALE`。

## 撮合结算方式（对应 CASE-00-05）

> 一句话：预测市场撮合引擎的三种核心结算路径——系统根据买卖双方持仓自动选择最优方式。YES 和 NO 侧的 Transfer 分别独立验证。

### ① Split 撮合（拆分结算）

> 一句话：一个看多、一个看空，系统把两人的钱凑一起铸币分给各自——市场从无到有创造流动性。

```
A: 买 YES@0.55，出价 0.55 USDC
B: 买 NO@0.45，出价 0.45 USDC
→ 合计 0.55+0.45 = 1 USDC → 系统铸造 1 YES 给 A，1 NO 给 B
```

### ② Transfer 撮合（转让结算）

> 一句话：和股票交易一样，一手交钱一手交货，代币从卖方转给买方。

```
A: 卖 YES@0.60（A 已持有 YES）
B: 买 YES@0.60
→ A 的 YES 转给 B，B 的 USDC 转给 A
```

### ③ Merge 撮合（合并结算）

> 一句话：两人分别卖出 YES 和 NO，系统收回一对代币销毁并释放 USDC——市场流动性被回收。

```
A: 卖 YES@0.60（出售 YES）
B: 卖 NO@0.40（出售 NO）
→ 系统收回 1 YES + 1 NO → 销毁并释放 1 USDC → 分给两人
```

## 订单类型（对应 CASE-00-06、07）

> 一句话：和传统交易所一样的限价单类型，控制"成交不了怎么办"的策略。

- **GTC（Good Till Cancel）** — 挂单直到手动取消

- **IOC（Immediate Or Cancel）** — 立即成交，未成交部分自动取消

  > 卖盘只有 3 个，买单要 5 个 → 成交 3 个，剩余 2 个自动取消

- **FOK（Fill Or Kill）** — 全部成交或全部取消

  > 卖盘只有 1 个，买单要 5 个 → 无法全部满足 → 整单取消，0 成交

- **ALO（Add Liquidity Only / Post-Only）** — 只做 maker，不吃单

  > 如果会立即成交则拒绝，只有能挂到盘口才接受——用于做市商避免被动吃单

- **GTD（Good Till Date）** — 带过期时间的挂单

  > 下单时指定 expiry_time → 到时自动取消 → USDC 返还

## STP 自成交防护（对应 CASE-00-08、09）

> 一句话：防止同一个用户左手卖给右手——做市商常见的防刷单机制。

STP（Self-Trade Prevention）：防止同一个用户的买单和卖单互相成交。

### 场景 1：只有自己的挂单（CASE-00-08）

```
A: GTC 买 YES@0.50（挂单）
A: FOK 卖 YES@0.50（吃单）
→ STP 检测到同一用户 → 跳过自己的买单
→ 没有其他卖家 → FOK 全单取消
→ GTC 买单保留在盘口
```

### 场景 2：有第三方挂单（CASE-00-09）

```
A: GTC 买 YES@0.60（挂单）
B: GTC 买 YES@0.60（挂单）
A: FOK 卖 YES@0.60（吃单）
→ STP 跳过 A 自己的买单 → 匹配到 B 的买单 → 成交
→ A 的 GTC 买单被 STP 取消（释放 USDC）
```

## USDC 守恒（对应 CASE-00-10）

> 一句话：不管怎么交易，系统里的总钱数永远不变——预测市场的"能量守恒定律"。

**[Invariant]** 这是预测市场的核心不变量：

> 所有用户的 USDC + 所有 YES 代币价值 + 所有 NO 代币价值 = 总充值额

无论经过多少次 Split、Merge、交易，系统中的总价值不会凭空增减。

- YES 总量永远等于 NO 总量（因为它们总是成对铸造和销毁）。

## 价格精度（对应 CASE-00-11）

> 一句话：价格有最小刻度（tick），超精度的报价会被拒绝——和股票最小价格变动单位一个道理。

`token_decimal=2` 意味着最小交易单位是 0.01。内部用 `price_scale = 10^(6-2) = 10000` 放大价格：

- 价格 0.55 → 内部存储 5500
- 最小 tick = 0.0001（内部 = 1）
- **[Rule]** 0.12345 有 5 位小数，超过 4 位精度限制 → 会被拒绝（CASE-00-11 已验证）

## 状态机（对应 CASE-00-04）

> 一句话：市场的生老病死——暂停、激活、上报结果、结算，加上可随时标记/取消争议的独立状态。

```
paused ←──→ active ──→ settled
                │
                │ Report（记录 payouts，status 保持 Active）
                │ Resolve（冻结 + 结算 → Settled）
                ▼

flag_status: normal ←──→ flagged（独立于 market status）
```

- **paused ↔ active**：暂停/开放交易，可反复切换
- **active → settled**：Binary 市场直接 Resolve 结算
- **active(reported) → settled**：NegRisk 市场先 Report（status 不变，`reported_at` 有值），延迟期满后 Resolve 结算
- **flagged**：管理员标记争议，独立于交易状态
- **注意**：Report 不是独立的 status 值（与 L1 合约对齐），通过 `reported_at.is_some()` 判断
- **兼容性**：`PredictionMarketStatus::Reported` 变体仍以 `#[deprecated]` 形式保留在枚举中（`instance.rs:25`），仅供旧快照 serde 反序列化兼容；新代码禁止 `match` 该变体。
- **Binary Unflag 时间窗口**：Binary 市场 Flag 后，如果 `resolve_delay_ms` 窗口已过期，Unflag 会被拒绝（TRDZN-377）。这是因为窗口过期意味着可以直接 Resolve，不应再 Unflag
- **NegRisk Unflag 无时间限制**：NegRisk 市场的 Flag/Unflag 不受 `resolve_delay_ms` 限制，Unflag 始终可以成功

## ApproveAgent 代理授权（对应 CASE-AA-01、AA-03）

> 一句话：用户授权第三方地址（如交易机器人）代替自己操作，类似 CEX 的 API Key 机制，但在链上实现。

ApproveAgent 允许用户授权一个或多个代理地址（Agent），代理可以在授权有效期内代替用户执行操作。

**核心机制：**

- 每个代理有 name（可选）、address、expires_after（有效期，默认 90 天）
- 授权、撤销、替换、续期均通过链上交易完成
- 撤销后有**宽限期**（~2s），宽限期内不可授权新代理（防止抢注）
- 同名不同地址 → 替换旧代理；同名同地址 → 续期（更新有效期）
- name 支持 trim（前后空格自动去除）

**[Constraint] 硬性上限**（`approve_agent.rs:25-31`）：

- 每个用户最多 **5** 个代理（`MAX_AGENTS = 5`）
- 代理 name 长度上限 **16** 字符（`MAX_AGENT_NAME_LEN = 16`）
- 单次授权有效期上限 **365 天**（`MAX_VALIDITY_MS = 365 * ONE_DAY_MS`）
- 撤销宽限期 **2000 ms**（`PENDING_AGENT_REMOVAL_MS = 2000`）

**[Rule] 地址级拒绝规则**（`approve_agent.rs:130-135, 182-194, 197-210`）：

- 不能授权自己（`agent_address == user`）
- 不能用一个**已经存在的用户地址**作为代理（防止用户身份与代理身份混用）
- 同一代理地址不可被多个用户同时授权（地址全局唯一占用）

### CASE-AA-01：完整生命周期

```
授权 agent_a (无名, 默认90天) → 授权 agent_b (name=bot1, 7天)
→ 撤销无名代理 → 宽限期内授权被阻塞
→ 宽限期后授权 bot2 成功 → 撤销 bot1
```

### CASE-AA-03：同名替换 + 续期 + name trim

```
授权 agent_a (name=bot) → 授权 agent_b (name=bot) → bot 指向 agent_b（替换）
→ 再次授权 agent_b (name=bot, 新有效期) → validUntil 更新（续期）
→ 授权 agent_c (name="  trimmed  ") → name 自动 trim 为 "trimmed"
```

## 覆盖的 16 个场景总结

| 编号 | 测试 | 验证内容 |
|------|------|----------|
| 00 | governance | Governance 治理操作：resolve_delay、bridge_cursor、非 Operator 拒绝 |
| 01 | binary_lifecycle | 完整生命周期：拆分→合并→结算→赎回 |
| 02 | negrisk_lifecycle | NegRisk 多结果市场：Event→N 市场→Split→Convert→Report ALL→Resolve ALL→Redeem |
| 03 | update_and_fee | 修改市场元数据和手续费率 |
| 04 | status_transitions | 状态机切换：Binary（暂停↔激活、Flag→Unflag 被 resolve_delay 窗口拒绝）+ NegRisk（Flag↔Unflag 无时间限制） |
| 05 | placeorder_matching | 五种撮合场景：Split/Transfer-YES/Transfer-NO/Merge/OpenOrder |
| 06 | placeorder_advanced | 高级订单：IOC 部分成交、FOK 全拒、ALO、Cancel、Cancel by CLOID、CLOID 重复使用拒绝 |
| 07 | placeorder_p2_p3 | 多档扫单、同价多 maker、GTD、价格边界、SizeType::Quote、暂停拒绝 |
| 08 | fok_stp_no_other | STP + FOK：无第三方→全拒 |
| 09 | fok_stp_with_third_party | STP + FOK：有第三方→撮合 |
| 10 | usdc_conservation | USDC 资金守恒验证 |
| 11 | price_precision | 精度校验：sub-tick 价格被正确拒绝（0.12345、0.00001），资金不被锁定 |
| 12 | gtd_expiry | GTD 到期自动取消，资金返还 |
| 16 | settled_reject | 已结算市场应拒绝新订单 |
| AA-01 | approve_agent_lifecycle | 代理授权完整生命周期：授权→查询→撤销→宽限期阻塞→恢复 |
| AA-03 | approve_agent_replace_renew | 同名替换、续期、name trim 验证 |
