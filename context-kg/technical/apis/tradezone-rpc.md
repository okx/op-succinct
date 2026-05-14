---
name: tradezone-rpc
description: TradeZone (tz) L2 链 REST API 完整接口文档。ZKP/Proposer/Challenger 集成时的数据源接口规范。涵盖所有 Chain/Business/TEE/Internal 端点的 Request/Response 详细定义。
sources:
  - "tradezone/specs/business/prediction/architecture/008-TradeZone-Prediction-RPC接口设计.md"
  - "tradezone/crates/chain/src/rpc/routes/*.rs"
  - "tradezone/crates/chain/src/rpc/handlers/*.rs"
  - "tradezone/crates/chain/src/rpc/response.rs"
updated_at: "2026-05-14"
---

# TradeZone REST API 接口文档

TradeZone 是自定义 L2 链（非 EVM），通过 HTTP REST API 暴露链状态和业务查询。本文档覆盖所有 RPC 端点，按路由模块分类。

---

## 通用规则

### 协议与基础信息

- **协议**：HTTP/HTTPS
- **风格**：RESTful
- **Content-Type**：`application/json`
- **Accept**：`application/json`

### 统一响应结构（Envelope）

所有接口返回统一 envelope，方便下游通用处理：

```json
{
  "code": 0,
  "message": "OK",
  "block": {
    "height": 19876543,
    "time": 1710000000000
  },
  "data": { ... }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| code | i32 | `0` 表示成功；非 0 表示业务错误 |
| message | string | 可读提示信息 |
| block | object / null | 部分接口返回当前状态对应的区块信息（height + time），无则省略 |
| data | T / null | 接口实际返回数据，错误时为 `null` |

### HTTP 状态码约定

| 状态码 | 含义 |
|--------|------|
| 200 | 成功（包含业务失败也使用 200 + code!=0 处理） |
| 401/403 | 未鉴权/无权限 |
| 404 | 请求路径不存在 |
| 429 | 限流 |
| 503 | 当前节点非 Leader（仅写入接口） |
| 5xx | 服务端异常 |

### 错误码

| code | 含义 | message 示例 | 处理建议 |
|------|------|--------------|----------|
| 0 | 成功 | "OK" | - |
| 10001 | 参数不合法 | "invalid address: ..." / "rejected: ..." | 检查 query/body 参数 |
| 10004 | 数据对象不存在 | "user 0x... not found" / "market 42 not found" | 检查传入的 ID/address |
| 10005 | 当前节点非 Leader | "no leader: this node is a follower" | 将请求转发至 Leader 节点 |
| 10006 | 重复交易 | "duplicate transaction: 0x..." | 交易已提交，无需重试 |
| 20001 | 服务内部错误 | "internal server error" | Trade Zone 服务内部异常 |

---

## 一、Chain API

Chain API 提供链核心原语：交易提交、区块事件查询、链高度、共识确认（appHash）。

路由前缀：无（直接挂载在根路径）

---

### 1.1 发送交易

#### POST /transaction

**功能描述**：发送单笔交易。Gateway 收到交易后转发给 Sequencer 进行打包，转发成功后返回交易哈希。仅 Leader 节点接受写入请求。

**Request Header**

| Header | 说明 |
|--------|------|
| Content-Type | application/json |
| x-cached-sender | （可选）Gateway 预验证的发送者地址，跳过 ECDSA 恢复 |

**Request Body**

```json
{
  "action": {
    "type": "predictionSplit",
    "nonce": 1708929600000,
    "marketId": "1",
    "size": "100000000"
  },
  "nonce": 1708929600000,
  "user": "0x12345.....",
  "expiresAfter": 1708929660000,
  "signature": {
    "type": "ecdsa",
    "signature": "0x..."
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| action | object | Y | 交易动作，type 决定具体类型 |
| nonce | u64 | Y | 交易 nonce |
| user | string(Address) | Y | 用户地址，0x 开头 |
| expiresAfter | u64 | N | 过期时间戳（毫秒） |
| signature | object | Y | 签名信息 |

**Response**

```json
// 成功
{
  "code": 0,
  "message": "OK",
  "data": {
    "txHash": "0x82f25c6d21c276c5acc8788da5b8ebe8f6a6e99c1ae6af22205397dba922fcd5"
  }
}

// 失败 — 参数不合法
{
  "code": 10001,
  "message": "rejected: <具体原因>",
  "data": null
}

// 失败 — 重复交易
{
  "code": 10006,
  "message": "duplicate transaction: 0x...",
  "data": null
}

// 失败 — 非 Leader
{
  "code": 10005,
  "message": "no leader: this node is a follower",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| txHash | string(H256) | 交易哈希，0x 前缀 |

---

### 1.2 批量发送交易

#### POST /transactions/batch

**功能描述**：批量提交多笔交易。每笔交易独立进入 mempool，部分成功是正常情况。调用方须检查每个 result 的 `code` 字段。仅 Leader 节点接受。

**Request Body**

JSON 数组，每个元素与 `POST /transaction` 的 body 格式相同：

```json
[
  {
    "action": { "type": "predictionSplit", ... },
    "nonce": 1708929600000,
    "user": "0x12345...",
    "signature": { "type": "ecdsa", "signature": "0x..." }
  },
  {
    "action": { "type": "predictionMerge", ... },
    "nonce": 1708929600001,
    "user": "0x12345...",
    "signature": { "type": "ecdsa", "signature": "0x..." }
  }
]
```

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "data": {
    "total": 2,
    "results": [
      {
        "index": 0,
        "code": 0,
        "message": "OK",
        "txHash": "0xaaa..."
      },
      {
        "index": 1,
        "code": 10001,
        "message": "rejected: insufficient balance",
        "txHash": null
      }
    ]
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| total | u32 | 批次内交易总数 |
| results[] | array | 每笔交易的结果 |
| results[].index | u32 | 交易在批次中的索引（从 0 开始） |
| results[].code | i32 | 0=成功, 10001=参数错误, 10006=重复交易 |
| results[].message | string | 可读提示 |
| results[].txHash | string / null | 成功时返回交易哈希，失败时为 null |

---

### 1.3 根据 TX Hash 查询交易 Receipt

#### GET /transaction/{txHash}/inclusion

**功能描述**：根据 tx hash 获取交易被打包的 Receipt 信息，用于判断交易是否已被打包上链以及交易是否成功。如果 tx hash 不存在，返回 10004 错误码。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| txHash | string | Y | 交易 hash，0x 开头 |

**Response**

```json
// 交易被打包 — 成功
{
  "code": 0,
  "message": "OK",
  "data": {
    "txHash": "0x82f25c6d21c276c5acc8788da5b8ebe8f6a6e99c1ae6af22205397dba922fcd5",
    "blockHeight": 12,
    "blockHash": "0x668c1e64ad4a2527ea4b8ead58c9bf0407a9bffe4cef4a7bc4a739b1bbc8bb1e",
    "txIndex": 0,
    "status": "ok"
  }
}

// 交易被打包 — 执行失败
{
  "code": 0,
  "message": "OK",
  "data": {
    "txHash": "0x...",
    "blockHeight": 12,
    "blockHash": "0x...",
    "txIndex": 1,
    "status": "err",
    "response": {
      "code": 30004,
      "message": "insufficient balance"
    }
  }
}

// 交易不存在
{
  "code": 10004,
  "message": "tx 0x... not found",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| txHash | string(H256) | 交易哈希 |
| blockHeight | u64 | 交易被打包所在的区块高度 |
| blockHash | string(H256) | 所在区块哈希（0x 前缀） |
| txIndex | u64 | 交易在区块内的索引（从 0 开始） |
| status | string | `"ok"` 或 `"err"`，通过 serde tag 序列化 |
| response | object / null | 成功时可选返回业务数据；失败时返回 `{code, message}` |

---

### 1.4 根据区块高度查询事件列表

#### GET /block/{height}/events

**功能描述**：查询指定区块高度内所有交易执行产生的事件列表，按交易顺序排列。

> **注意**：event 只能查近 2 天数据，节点不保留全部历史数据。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| height | u64 | Y | 区块高度 |

**Query Params**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| eventType | string | N | - | 按事件类型过滤（如 fill、order_status、ledger_update） |

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "data": {
    "blockHeight": 19876543,
    "blockHash": "0xabcdef...",
    "blockTime": 1710000000000,
    "totalEvents": 2,
    "events": [
      {
        "hash": "0x5555...",
        "txIndex": 3,
        "eventIndex": 4,
        "subIndex": null,
        "ledgerUpdate": {
          "users": ["0xeee..."],
          "delta": {
            "deposit": {
              "tokenAddress": "0xfff...",
              "tokenId": 0,
              "originalTokenId": null,
              "originalTxHash": "0x000...",
              "amount": "500"
            }
          }
        }
      },
      {
        "hash": "0x6666...",
        "txIndex": null,
        "eventIndex": 5,
        "subIndex": null,
        "predictionUpdate": {
          "predictionMarketInitialized": {
            "originalEventId": "0xaaa...",
            "index": 0,
            "originalMarketId": "0xbbb...",
            "marketId": 10,
            "assetIds": [1, 2],
            "tokenIds": [3, 4],
            "originalConditionId": "0xccc...",
            "originalQuestionId": "0xddd...",
            "quoteTokenId": 0
          }
        }
      }
    ]
  }
}

// 区块不存在
{
  "code": 10004,
  "message": "block 19876543 not found",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| blockHeight | u64 | 区块高度 |
| blockHash | string | 区块哈希，0x 开头 |
| blockTime | u64 | 区块时间戳（毫秒） |
| totalEvents | u32 | 该区块内事件总数 |
| events[] | array | 事件列表，按 eventIndex 排序 |

events[] 每个元素：

| 字段 | 类型 | 说明 |
|------|------|------|
| hash | string / null | 交易哈希 |
| txIndex | u64 / null | 交易在区块中的顺序（从 0 开始） |
| eventIndex | u64 | 事件在区块中的全局顺序 |
| subIndex | u64 / null | 子交易序号 |
| (事件类型字段) | object | 具体事件数据，如 ledgerUpdate、predictionUpdate 等 |

---

### 1.5 获取最新高度

#### GET /chain/latest_height

**功能描述**：获取 TradeZone 链最新的区块高度、哈希和时间戳。纯内存只读接口，无参数。

**Query Params**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "data": {
    "blockHeight": 19876543,
    "blockHash": "0xabcdef...",
    "blockTime": 1710000000000
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| blockHeight | u64 | 当前最新区块高度 |
| blockHash | string | 当前最新区块哈希，0x 前缀 |
| blockTime | u64 | 区块时间戳（毫秒） |

---

### 1.6 获取最新确认的 appHash 和 block

#### GET /chain/confirmed_block_info

**功能描述**：获取最近一次确认的 appHash 及其对应区块信息。纯内存只读接口，无参数。appHash 是异步计算的，因此返回的高度总是落后于链的最新高度。

> 例如：如果在第 2000 这个高度计算 apphash，但计算完成时链已到 2009 高度，返回的是 2000 的 apphash + 2000 的 block hash。如果 2000 的 apphash 尚未算出，返回最近一次已计算的（如 1900 的）。

**Query Params**：无

**Response**

```json
// 有确认记录
{
  "code": 0,
  "message": "OK",
  "data": {
    "height": 2000,
    "appHash": "0xaa...",
    "blockHash": "0xbb..."
  }
}

// 无确认记录（初始状态）
{
  "code": 0,
  "message": "OK",
  "data": {
    "height": null,
    "appHash": null,
    "blockHash": null
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| height | u64 / null | appHash 计算时的区块高度，无确认记录时为 null |
| appHash | string / null | appHash 值（0x 前缀），无确认记录时为 null |
| blockHash | string / null | 该高度的区块哈希（0x 前缀），无确认记录时为 null |

**Notes**：此接口是 op-succinct ZKP 集成的关键接口，Proposer 使用它获取已确认的状态根。

---

## 二、Business API

Business API 提供面向下游业务消费者的查询端点：用户余额、预测市场元数据、订单簿快照、资产元数据、Bridge 状态、用户授权查询。

路由前缀：无（直接挂载在根路径）

---

### 2.1 查询用户余额

#### GET /user/{address}/balance/{token_id}

**功能描述**：查询用户指定 token 的总资产和可用余额信息。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| address | string | Y | 用户地址，0x 开头 |
| token_id | u64 | Y | 代币 ID |

**Response**

```json
// 成功
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "blockHeight": 19876543,
    "blockTime": 1710000000000,
    "tokenId": 101,
    "count": "100.00",
    "available": "80.50"
  }
}

// 用户不存在
{
  "code": 10004,
  "message": "user 0x... not found",
  "data": null
}

// token 不存在
{
  "code": 10004,
  "message": "token 101 not found",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| blockHeight | u64 | 当前状态对应的区块高度 |
| blockTime | u64 | 区块时间戳（毫秒） |
| tokenId | u64 | 代币 ID |
| count | Decimal(string) | 该 token 总持有量（包含挂单冻结数量），经 wei_decimals 精度转换后的十进制值 |
| available | Decimal(string) | 该 token 可用余额 = count - 挂单锁定量 |

---

### 2.2 按 marketId 查询市场元数据

#### GET /market/{market_id}

**功能描述**：通过 marketId 查询预测市场元数据，包括市场状态、手续费率、结算信息等。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| market_id | u64 | Y | TZ 链上的 marketId |

**Response**

```json
// 正常返回
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "marketId": 42,
    "eventId": "0xdef...",
    "conditionId": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
    "ancillaryData": "q: title: Will BTC exceed 100k by 2025-12-31?",
    "outcomeTokenIds": [101, 102],
    "assetIds": [1, 2],
    "quoteTokenId": 0,
    "makerFeeRate": "0.001",
    "takerFeeRate": "0.002",
    "oracle": "0x9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
    "status": "Active",
    "flagStatus": "Normal",
    "payouts": null,
    "sourceTxHash": "0xaaaa...bbbb",
    "resolvedBy": null,
    "creator": "0x5678...ef01",
    "reserve": null,
    "createdAt": 1710000000000,
    "updatedAt": 1710050000000
  }
}

// market 不存在
{
  "code": 10004,
  "message": "market 42 not found",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| marketId | u64 | 内部市场 ID |
| eventId | string(H256) / null | 关联事件 ID（original_event_id），可为空 |
| conditionId | string(H256) | CTF conditionId |
| ancillaryData | string | 市场描述/问题文本 |
| outcomeTokenIds | u64[2] | 各 outcome 对应的代币 ID（[YES, NO]） |
| assetIds | AssetId[2] | 对应 YES/NO token 的 assetId |
| quoteTokenId | u64 | 报价代币 ID（如 USDT = 0） |
| makerFeeRate | string(Decimal) | Maker 手续费率，如 "0.001" = 0.1% |
| takerFeeRate | string(Decimal) | Taker 手续费率 |
| oracle | string(Address) | Oracle 合约地址 |
| status | string | 市场状态枚举（见下表） |
| flagStatus | string | 标记状态："Normal" 或 "Flagged" |
| payouts | u64[2] / null | 结算赔付权重（仅 Settled 状态有值） |
| sourceTxHash | string(H256) / null | 创建市场的交易哈希 |
| resolvedBy | string(Address) / null | 结算执行者地址 |
| creator | string(Address) | 创建者地址 |
| reserve | Decimal / null | 锁定的结算资产总量（当前未实现，始终为 null） |
| createdAt | u64 | 创建时间戳（毫秒） |
| updatedAt | u64 | 最后更新时间戳（毫秒） |

**市场状态（status）枚举**

状态流转：Paused -> Active -> Paused（可暂停再恢复）；Active -> Settled（终态）

| status | 说明 | 可交易 | 可结算 |
|--------|------|--------|--------|
| Paused | 暂停（创建默认状态） | 否 | 否 |
| Active | 活跃（可交易） | 是 | 否 |
| Settled | 已结算（可 Redeem） | 否 | 是 |

---

### 2.3 查询预测市场全量元数据

#### GET /prediction/meta

**功能描述**：获取预测市场全量元数据快照，包括所有事件（Event）、市场模板（Market Template）和市场实例（Market Instance），以及全局 resolve 延迟配置。纯内存只读接口，无参数。

**Query Params**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "blockHeight": 19876543,
    "blockTime": 1710000000000,
    "events": [
      {
        "compositeKey": "0xabc...",
        "originalEventId": "0xdef...",
        "adapter": "0x1234...5678",
        "ancillaryData": "q: title: Will BTC exceed 100k by 2025-12-31?",
        "marketKeys": ["0xaaa...", "0xbbb..."],
        "determined": false,
        "determinedIndex": null,
        "payoutDenominator": null,
        "remainingYesWeight": null,
        "knownOutcomeCount": 2,
        "createdAt": 1710000000000
      }
    ],
    "markets": [
      {
        "compositeKey": "0xaaa...",
        "originalMarketId": "0xbbb...",
        "adapter": "0x1234...5678",
        "compositeEventKey": "0xabc...",
        "ancillaryData": "q: title: Will BTC exceed 100k by 2025-12-31?",
        "ancillaryDataUpdates": [],
        "conditionId": "0xccc...",
        "conditionTokenAddress": "0x9999...aaaa",
        "oracle": "0x9a9a...9a9a",
        "creator": "0x5678...ef01",
        "createdAt": 1710000000000,
        "updatedAt": 1710050000000
      }
    ],
    "marketInstances": [
      {
        "marketId": 42,
        "originalMarketId": "0xbbb...",
        "compositeMarketKey": "0xaaa...",
        "quoteTokenId": 0,
        "basePrice": "1.000000",
        "wrapCollateralToken": null,
        "makerFeeRate": "0.001",
        "takerFeeRate": "0.002",
        "outcomeTokenIds": [101, 102],
        "assetIds": [1, 2],
        "status": "Active",
        "flagStatus": "Normal",
        "reportedAt": null,
        "flaggedAt": null,
        "payouts": null,
        "sourceTxHash": "0xaaaa...bbbb",
        "resolvedBy": null,
        "createdAt": 1710000000000,
        "updatedAt": 1710050000000
      }
    ],
    "resolveDelayMs": 3600000
  }
}
```

**字段说明 — 顶层**

| 字段 | 类型 | 说明 |
|------|------|------|
| blockHeight | u64 | 当前状态对应的区块高度 |
| blockTime | u64 | 区块时间戳（毫秒） |
| events | array | 事件列表 |
| markets | array | 市场模板列表 |
| marketInstances | array | 市场实例列表（已分配 marketId） |
| resolveDelayMs | u64 | 全局 resolve 延迟（毫秒） |

**events[] 每个元素**

| 字段 | 类型 | 说明 |
|------|------|------|
| compositeKey | string(H256) | 事件唯一键（adapter + originalEventId 哈希） |
| originalEventId | string(H256) | XLayer polymarket 事件 ID |
| adapter | string(Address) | 适配器合约地址 |
| ancillaryData | string | 事件描述/问题文本 |
| marketKeys | string(H256)[] | 关联的市场模板 key 列表 |
| determined | bool | 是否已确定结果 |
| determinedIndex | u64 / null | 确定的 outcome 索引 |
| payoutDenominator | u64 / null | 赔付分母 |
| remainingYesWeight | u64 / null | 剩余 YES 权重 |
| knownOutcomeCount | u64 | 已知的 outcome 数量 |
| createdAt | u64 | 创建时间戳（毫秒） |

**markets[] 每个元素**

| 字段 | 类型 | 说明 |
|------|------|------|
| compositeKey | string(H256) | 市场模板唯一键 |
| originalMarketId | string(H256) | XLayer polymarket 市场 ID |
| adapter | string(Address) | 适配器合约地址 |
| compositeEventKey | string(H256) / null | 关联的事件 key |
| ancillaryData | string | 市场描述/问题文本 |
| ancillaryDataUpdates | string[] | 描述更新历史 |
| conditionId | string(H256) | CTF conditionId |
| conditionTokenAddress | string(Address) | condition token 合约地址 |
| oracle | string(Address) | Oracle 合约地址 |
| creator | string(Address) | 创建者地址 |
| createdAt | u64 | 创建时间戳（毫秒） |
| updatedAt | u64 | 最后更新时间戳（毫秒） |

**marketInstances[] 每个元素**

| 字段 | 类型 | 说明 |
|------|------|------|
| marketId | u64 | 内部市场 ID |
| originalMarketId | string(H256) | XLayer polymarket 市场 ID |
| compositeMarketKey | string(H256) | 关联的市场模板 key |
| quoteTokenId | u64 | 报价代币 ID（如 USDT = 0） |
| basePrice | Decimal(string) | 基础价格（经精度转换） |
| wrapCollateralToken | string(Address) / null | 包装抵押代币地址 |
| makerFeeRate | string(Decimal) | Maker 手续费率 |
| takerFeeRate | string(Decimal) | Taker 手续费率 |
| outcomeTokenIds | u64[2] | 各 outcome 对应的代币 ID |
| assetIds | AssetId[2] | 对应 YES/NO token 的 assetId |
| status | string | 市场状态（Paused / Active / Settled） |
| flagStatus | string | 标记状态（Normal / Flagged） |
| reportedAt | u64 / null | Oracle 报告时间戳 |
| flaggedAt | u64 / null | 被标记时间戳 |
| payouts | u64[2] / null | 结算赔付权重（仅 Settled 有值） |
| sourceTxHash | string(H256) / null | 创建市场的交易哈希 |
| resolvedBy | string(Address) / null | 结算执行者地址 |
| createdAt | u64 | 创建时间戳（毫秒） |
| updatedAt | u64 | 最后更新时间戳（毫秒） |

---

### 2.4 获取全量订单簿数据（L4 快照）

#### GET /orderbook/l4_snapshot

**功能描述**：获取所有交易对的订单簿全量 L4 快照数据（逐笔订单粒度），同时返回当前区块高度和 spot 元数据，供调用方做状态一致性校验。

> 只会在服务重启时调用，不会常规调用，可以接受接口慢。只能查询最新全量 orderbook，不能指定高度。

**Query Params**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "block": { "height": 1569396, "time": 1774512470952 },
  "data": {
    "blockHeight": 1569396,
    "blockTime": 1774512470952,
    "spotMeta": {
      "tokens": [
        {
          "tokenId": 1,
          "name": "PT",
          "sizeDecimals": 6,
          "weiDecimals": 6,
          "flag": 7,
          "evmContract": {
            "type": "Erc20",
            "address": "0x964c08a41effafe50afff995be0f91c932997675",
            "evmWeiDecimal": 6
          }
        },
        {
          "tokenId": 2,
          "name": "o1YES",
          "sizeDecimals": 2,
          "weiDecimals": 6,
          "flag": 1,
          "evmContract": {
            "type": "Erc1155",
            "address": "0xffe721200dc888827dc2677172a4fd04b67c9152",
            "tokenId": "0x136181cd924ad73215ed21bd922e46f098b583f1b67b7cfc97c532a8cb962947"
          },
          "totalSupply": "0.00"
        }
      ],
      "assets": [
        {
          "assetId": 0,
          "baseTokenId": 2,
          "quoteTokenId": 1,
          "deployTime": 1774357496652
        }
      ]
    },
    "orderbooks": [
      {
        "assetId": { "type": "prediction", "marketId": 1, "outcomeIndex": 0 },
        "marketType": "prediction",
        "predictionInfo": {
          "basePrice": "1",
          "reverseAssetId": { "type": "prediction", "marketId": 1, "outcomeIndex": 1 }
        },
        "bids": [
          {
            "orderId": 17,
            "user": "0x7e972273e1275397b18f9d91ad99e4bbe9f5f457",
            "price": "0.5000",
            "size": "10.00",
            "filledSize": "0.00",
            "remainingSize": "10.00",
            "side": "buy",
            "tif": "Gtc",
            "reduceOnly": false,
            "isReverse": false
          }
        ],
        "asks": []
      }
    ]
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| blockHeight | u64 | 快照对应的区块高度 |
| blockTime | u64 | 区块时间戳（毫秒） |
| spotMeta | object | 包含 tokens 和 assets 元数据（与 /spot/meta 结构相同） |
| orderbooks[] | array | 所有交易对的订单簿列表 |

orderbooks[] 每个元素：

| 字段 | 类型 | 说明 |
|------|------|------|
| assetId | AssetId | 交易对 ID（复合类型：spot 或 prediction） |
| marketType | string | "spot" 或 "prediction" |
| predictionInfo | object / null | 预测市场专有信息（仅 prediction 类型） |
| predictionInfo.basePrice | Decimal | 基础价格 |
| predictionInfo.reverseAssetId | AssetId | 镜像交易对 ID（NO 侧） |
| bids[] | array | 买单列表，按价格降序；同价按时间优先（FIFO） |
| asks[] | array | 卖单列表，按价格升序；同价按时间优先（FIFO） |

bids[]/asks[] 每个元素：

| 字段 | 类型 | 说明 |
|------|------|------|
| orderId | u64 | 订单 ID |
| user | string(Address) | 下单用户地址 |
| price | Decimal(string) | 挂单价格 |
| size | Decimal(string) | 原始订单数量 |
| filledSize | Decimal(string) | 已成交数量 |
| remainingSize | Decimal(string) | 剩余未成交数量 |
| side | string | "buy" 或 "sell" |
| tif | string | 订单有效期类型 |
| reduceOnly | bool | 是否仅减仓订单 |
| isReverse | bool | 是否为镜像单（预测市场 NO 侧） |

**订单有效期（tif）枚举**

| tif | 说明 |
|-----|------|
| Gtc | Good-Til-Cancelled，挂单直到成交或手动取消 |
| Ioc | Immediate-Or-Cancel，立即成交否则取消 |
| Fok | Fill-Or-Kill，全部成交否则取消 |
| Alo | Add-Liquidity-Only，仅做 Maker |
| Gtd | Good-Til-Date |

---

### 2.5 查询 Spot 元数据

#### GET /spot/meta

**功能描述**：获取 spot 全量元数据，包括所有已注册的 Token 列表和交易对（Asset）列表。纯内存只读接口，无参数。

> 该接口返回全量数据，适用于服务启动时初始化或数据校验场景，不建议高频调用。

**Query Params**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "blockHeight": 19876543,
    "blockTime": 1710000000000,
    "tokens": [
      {
        "tokenId": 0,
        "name": "USDC",
        "sizeDecimals": 2,
        "weiDecimals": 6,
        "flag": 7,
        "evmContract": {
          "type": "Erc20",
          "address": "0xA0A0...A0A0",
          "evmWeiDecimal": 6
        }
      },
      {
        "tokenId": 101,
        "name": "YES",
        "sizeDecimals": 2,
        "weiDecimals": 6,
        "flag": 0,
        "evmContract": {
          "type": "Erc1155",
          "address": "0xB0B0...B0B0",
          "tokenId": "0x0101...0101"
        },
        "totalSupply": "500000.00"
      }
    ],
    "assets": [
      {
        "assetId": 0,
        "baseTokenId": 101,
        "quoteTokenId": 0,
        "deployTime": 1710000000000
      }
    ]
  }
}
```

**字段说明**

tokens[] 每个元素：

| 字段 | 类型 | 是否允许为空 | 说明 |
|------|------|-------------|------|
| tokenId | u64 | 否 | 代币 ID |
| name | string | 否 | 代币名称（如 "USDC"、"YES"、"NO"） |
| sizeDecimals | i8 | 否 | 下单最小单位精度 |
| weiDecimals | i8 | 否 | 链上存储精度 |
| flag | u8 | 否 | 功能标志位（bit0=deposit, bit1=withdraw, bit2=transfer） |
| evmContract | object | 是 | EVM 合约信息，无合约时省略 |
| totalSupply | Decimal / null | 是 | 当前总供应量，不跟踪 supply 的 token 时省略 |

evmContract 对象 — ERC-20 类型：

| 字段 | 类型 | 说明 |
|------|------|------|
| type | string | 固定值 "Erc20" |
| address | string(Address) | ERC-20 合约地址 |
| evmWeiDecimal | u8 | EVM 链上 wei 精度 |

evmContract 对象 — ERC-1155 类型：

| 字段 | 类型 | 说明 |
|------|------|------|
| type | string | 固定值 "Erc1155" |
| address | string(Address) | ERC-1155 合约地址 |
| tokenId | string(H256) | ERC-1155 positionId |

assets[] 每个元素：

| 字段 | 类型 | 说明 |
|------|------|------|
| assetId | AssetId | 交易对 ID |
| baseTokenId | u64 | 基础代币 ID（outcome token） |
| quoteTokenId | u64 | 报价代币 ID（如 USDT = 0） |
| deployTime | u64 | 交易对上线时间戳（毫秒） |

---

### 2.6 获取 Bridge 最新状态

#### GET /bridge/status

**功能描述**：获取 Bridge 模块的当前聚合状态。纯内存只读接口，无参数。

**Query Params**：无

**Response**

```json
// 正常状态
{
  "code": 0,
  "message": "OK",
  "block": { "height": 42, "time": 1710000000000 },
  "data": {
    "blockHeight": 42,
    "balances": { "0": "5000000" },
    "eventNonce": 1,
    "eventCursor": {
      "blockNumber": 100,
      "txIndex": 0,
      "eventIndex": 0
    }
  }
}

// 初始状态
{
  "code": 0,
  "message": "OK",
  "block": { "height": 1, "time": 0 },
  "data": {
    "blockHeight": 1,
    "balances": {},
    "eventNonce": null,
    "eventCursor": null
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| blockHeight | u64 | 当前状态对应的区块高度 |
| balances | Map<string, string> | 每个 token 的 Bridge 锁仓余额，key = token_id, value = 十进制字符串(U256) |
| eventNonce | u64 / null | 最后处理的全局事件 nonce，null 表示尚未处理任何 L1 事件 |
| eventCursor | object / null | 最后处理的 L1 事件位置 |
| eventCursor.blockNumber | u64 | L1 区块号 |
| eventCursor.txIndex | u64 | 该区块内的交易索引 |
| eventCursor.eventIndex | u64 | 该交易内的事件索引 |

---

### 2.7 查询用户授权信息（Agent/Owner）

#### GET /user/{address}/authorizations

**功能描述**：获取有权操作该用户交易的地址列表（包括 agent 和 owner）。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| address | string | Y | 用户地址，0x 开头 |

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "address": "0x...",
    "agents": [
      {
        "name": "agent1",
        "address": "0x123...",
        "expiresAfter": 1773572106,
        "expired": false
      }
    ],
    "owners": [
      {
        "address": "0x456...",
        "expiresAfter": 1773572106,
        "expired": false
      }
    ]
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| address | string(Address) | 查询的用户地址 |
| agents[] | array | agent 列表 |
| agents[].name | string | agent 名称，可为空字符串 |
| agents[].address | string(Address) | agent 地址 |
| agents[].expiresAfter | u64 | agent 有效期时间戳 |
| agents[].expired | bool | 是否已过期 |
| owners[] | array | owner 列表 |
| owners[].address | string(Address) | owner 地址 |
| owners[].expiresAfter | u64 / null | owner 有效期时间戳 |
| owners[].expired | bool | 是否已过期 |

---

### 2.8 查询用户限制（Rate Limits）

#### GET /user/{address}/limits

**功能描述**：查询指定用户的速率限制状态，包括 action 配额、取消豁免、挂单限制等。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| address | string | Y | 用户地址，0x 开头 |

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "actionLimit": {
      "initial": 100,
      "earned": 50,
      "purchased": 20,
      "granted": 10,
      "used": 30,
      "remaining": 150,
      "isThrottled": false,
      "throttleIntervalMs": 1000
    },
    "cancelExemption": {
      "limit": 200,
      "remaining": 170
    },
    "cancelAll": {
      "todayUsed": 1,
      "dailyLimit": 5,
      "remaining": 4
    },
    "openOrders": {
      "current": 10,
      "limit": 100,
      "userOverride": null
    },
    "withdrawFee": "1000000"
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| actionLimit.initial | u64 | 初始 action 配额 |
| actionLimit.earned | u64 | 通过交易量获得的额外配额 |
| actionLimit.purchased | u64 | 购买的额外配额 |
| actionLimit.granted | u64 | 授予的额外配额 |
| actionLimit.used | u64 | 已使用配额 |
| actionLimit.remaining | u64 | 剩余可用配额 |
| actionLimit.isThrottled | bool | 是否被限流 |
| actionLimit.throttleIntervalMs | u64 | 限流间隔（毫秒） |
| cancelExemption.limit | u64 | 取消免收费上限 |
| cancelExemption.remaining | u64 | 剩余免收费次数 |
| cancelAll.todayUsed | u64 | 今日已使用的 cancelAll 次数 |
| cancelAll.dailyLimit | u64 | 每日 cancelAll 上限 |
| cancelAll.remaining | u64 | 剩余 cancelAll 次数 |
| openOrders.current | u64 | 当前挂单数 |
| openOrders.limit | u64 | 挂单上限 |
| openOrders.userOverride | u64 / null | 用户个性化挂单上限覆盖，null=使用系统默认 |
| withdrawFee | string | 提现手续费（十进制字符串） |

---

### 2.9 查询全局限制参数

#### GET /chain/limits

**功能描述**：获取全局速率限制参数配置。纯内存只读接口，无参数。

**Query Params**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "initialActionLimit": 100,
    "throttleIntervalMs": 1000,
    "cancelLimitAdd": 100,
    "requestWeightPrice": 1000000,
    "initOpenOrdersLimit": 50,
    "volumePerExtraOrder": 100000,
    "maxOpenOrdersLimit": 500,
    "dailyCancelAllLimit": 5,
    "predictionVolumeMultiplier": 10,
    "actionWeights": {
      "placeOrder": 1,
      "cancelOrder": 1,
      "cancelAll": 10
    },
    "withdrawFee": 1000000
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| initialActionLimit | u64 | 初始 action 配额 |
| throttleIntervalMs | u64 | 限流间隔（毫秒） |
| cancelLimitAdd | u64 | 取消豁免附加值 |
| requestWeightPrice | u64 | 请求权重单价 |
| initOpenOrdersLimit | u64 | 初始挂单上限 |
| volumePerExtraOrder | u64 | 每增加一个挂单位所需交易量 |
| maxOpenOrdersLimit | u64 | 挂单数硬上限 |
| dailyCancelAllLimit | u64 | 每日 cancelAll 次数上限 |
| predictionVolumeMultiplier | u64 | 预测市场交易量乘数 |
| actionWeights | Map<string, u64> | 各操作类型的权重映射 |
| withdrawFee | u64 | 提现手续费 |

---

## 三、TEE API

TEE API 仅在节点以 `tee-prover` 模式运行时存在。TEE Prover 是一类特殊 RPC 节点，除正常 RPC 能力外，还提供 TEE 证明任务管理接口供 op-challenger 调用。

路由前缀：无

---

### 3.1 查看 TEE Enclave 状态

#### GET /tee/info

**功能描述**：查询 TEE Enclave 的状态信息，返回证明文件、TEE 的 EOA 公钥、Enclave 启动时间和编译哈希。

**Query Params**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "data": {
    "attestationDoc": "hEShATgioFkRiL9pb...<base64编码>...",
    "commit": "9c1655552020858283f93b81877abdde2f2db488",
    "launchTime": "2026-03-26T10:57:55.946628+00:00",
    "pubKey": "04e1debe4244397c37b32d42dad0915c38ccdf97be4c631bed4bf0a4f7a2657779d36d0dbd81d3fef1855c9fd1f38d16170bdc631d41a8278010bc1ecaa5dd2d0e"
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| attestationDoc | string | AWS Nitro Attestation 证明文件（base64 编码） |
| commit | string | TEE Enclave 编译时的 git commit 哈希 |
| launchTime | string(ISO-8601) | Enclave 启动时间 |
| pubKey | string(hex) | TEE EOA 的未压缩公钥（04 前缀，130 字符 hex） |

**Notes**：此接口仅在启用 `tee` feature 的节点上可用。

---

### 3.2 创建 TEE 证明任务

#### POST /tee/task

**功能描述**：向 TEE Enclave 提交一个证明任务，指定待证明的区块范围及对应的哈希/状态哈希。成功后返回全局唯一的 `taskId`。TEE Prover 同一时间只能处理一个任务，若当前有任务正在运行，创建新任务会报错。

**Request Body**

```json
{
  "startBlkHeight": 1000,
  "endBlkHeight": 2000,
  "startBlkHash": "0xabc...001",
  "endBlkHash": "0xdef...002",
  "startBlkStateHash": "0x111...003",
  "endBlkStateHash": "0x222...004",
  "teeProofVerifierAddr": "0x111...111",
  "chainId": 1,
  "validation": false
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| startBlkHeight | u64 | Y | 起始区块高度（含） |
| endBlkHeight | u64 | Y | 结束区块高度（含） |
| startBlkHash | string(H256) | Y | 起始区块哈希，0x 前缀 |
| endBlkHash | string(H256) | Y | 结束区块哈希，0x 前缀 |
| startBlkStateHash | string(H256) | Y | 起始区块执行后的状态哈希（appHash） |
| endBlkStateHash | string(H256) | Y | 结束区块执行后的状态哈希（appHash） |
| teeProofVerifierAddr | string(Address) | N | TeeProofVerifier 合约地址。省略则使用系统配置的地址 |
| chainId | u64 | N | EIP-712 domain chain ID，默认 1（ETH 主网） |
| validation | bool | N | 是否运行 host 侧状态哈希验证，默认 false |

**Response**

```json
// 成功
{
  "code": 0,
  "message": "OK",
  "data": {
    "taskId": "550e8400-e29b-41d4-a716-446655440000"
  }
}

// 失败 — 当前有任务在运行
{
  "code": 10001,
  "message": "a task is already running",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| taskId | string(UUID) | 任务唯一 ID，用于后续查询或删除 |

---

### 3.3 删除 TEE 任务

#### DELETE /tee/task/{task_id}

**功能描述**：终止并删除指定 TEE 任务。若任务正在运行，会向 Enclave 发送中止信号后删除；若 taskId 不存在，返回 10001 错误码。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| task_id | string | Y | 由创建接口返回的任务 UUID |

**Response**

```json
// 成功
{
  "code": 0,
  "message": "OK",
  "data": {
    "taskId": "550e8400-e29b-41d4-a716-446655440000"
  }
}

// 任务不存在
{
  "code": 10001,
  "message": "task 550e8400-... not found",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| taskId | string(UUID) | 被删除的任务 ID |

---

### 3.4 查询 TEE 任务状态

#### GET /tee/task/{task_id}

**功能描述**：查询指定任务的当前状态。若任务已完成，`proofBytes` 字段包含 ABI 编码的 EVM 可验证证明字节；运行中或失败时该字段为空字符串。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| task_id | string | Y | 由创建接口返回的任务 UUID |

**Response**

```json
// 任务运行中
{
  "code": 0,
  "message": "OK",
  "data": {
    "status": "Running",
    "proofBytes": "",
    "detail": {
      "taskId": "550e8400-e29b-41d4-a716-446655440000",
      "args": {
        "startBlkHeight": 1000,
        "endBlkHeight": 2000,
        "startBlkHash": "0xabc...001",
        "endBlkHash": "0xdef...002",
        "startBlkStateHash": "0x111...003",
        "endBlkStateHash": "0x222...004"
      },
      "status": { "Running": "enclave accepted" },
      "startTime": "2025-03-18T10:00:00Z",
      "endTime": null,
      "enclaveResponse": {
        "taskId": "550e8400-e29b-41d4-a716-446655440000",
        "status": { "Running": "processing" },
        "startTime": "2025-03-18T10:00:01Z",
        "startBlkHeight": 1000,
        "endBlkHeight": 2000
      }
    }
  }
}

// 任务已完成
{
  "code": 0,
  "message": "OK",
  "data": {
    "status": "Finished",
    "proofBytes": "0x<ABI编码的证明字节>",
    "detail": {
      "taskId": "550e8400-e29b-41d4-a716-446655440000",
      "args": { "..." : "..." },
      "status": {
        "Finished": {
          "endTime": "2025-03-18T10:05:00Z",
          "duration": "300s",
          "batchDigestHex": "0xaabbcc...",
          "signatureHex": "0x<65-byte ECDSA sig>",
          "startStateInfo": {
            "blkHeight": 1000,
            "blkHash": "0xabc...001",
            "stateHash": "0x111...003"
          },
          "endStateInfo": {
            "blkHeight": 2000,
            "blkHash": "0xdef...002",
            "stateHash": "0x222...004"
          }
        }
      },
      "startTime": "2025-03-18T10:00:00Z",
      "endTime": "2025-03-18T10:05:00Z",
      "enclaveResponse": { "..." : "..." }
    }
  }
}

// 任务失败
{
  "code": 0,
  "message": "OK",
  "data": {
    "status": "Failed",
    "proofBytes": "",
    "detail": {
      "status": { "Failed": "block hash mismatch at height 1500" },
      "..."  : "..."
    }
  }
}

// 任务不存在
{
  "code": 10004,
  "message": "task 550e8400-... not found",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| status | string | 任务状态枚举（见下表） |
| proofBytes | string | ABI 编码的 EVM 可验证证明，0x 前缀。预期作为 `TeeDisputeGame.prove(bytes calldata proofBytes)` 的参数。非 Finished 状态时为空字符串 |
| detail | object | TEE 任务详细信息，建议上游打到日志方便调试 |

**status 枚举**

| status | 说明 |
|--------|------|
| Running | Enclave 正在执行证明计算 |
| Finished | 证明计算完成，proofBytes 有效 |
| Failed | 计算失败，detail.status.Failed 包含原因 |

**Notes**：此接口是 op-succinct Challenger 集成的关键接口，用于获取 TEE 证明并提交到 L1 合约。

---

## 四、Internal API

Internal API 不对外暴露给下游消费者，可能随时变更或移除。包括调试/检查、集群管理、状态同步等功能。

路由前缀：无

---

### 4.1 查询用户完整状态

#### GET /user/{address}/state

**功能描述**：获取用户的完整交易状态，包括所有投资组合（portfolio）的保证金余额、持仓和挂单信息。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| address | string | Y | 用户地址，0x 开头 |

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "address": "0x7e972273e1275397b18f9d91ad99e4bbe9f5f457",
    "nonce": 0,
    "portfolios": [
      {
        "collateralTokenId": 0,
        "collateralBalance": "10000.00",
        "positions": [
          {
            "assetId": { "type": "perps", "index": 0 },
            "size": "5.00",
            "entryPrice": "45000.00",
            "entryCost": "225000.00",
            "leverage": 10,
            "isCross": true
          }
        ],
        "orders": [
          {
            "orderId": 42,
            "assetId": { "type": "perps", "index": 0 },
            "side": "buy",
            "price": "44000.00",
            "size": "2.00",
            "filledSize": "0.00",
            "status": "Pending"
          }
        ]
      }
    ]
  }
}

// 用户不存在
{
  "code": 10004,
  "message": "user 0x... not found",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| address | string(Address) | 用户地址 |
| nonce | u64 | 用户 nonce |
| portfolios[] | array | 投资组合列表 |
| portfolios[].collateralTokenId | u64 | 保证金代币 ID |
| portfolios[].collateralBalance | Decimal | 保证金余额 |
| portfolios[].positions[] | array | 持仓列表 |
| portfolios[].positions[].assetId | AssetId | 交易对 ID |
| portfolios[].positions[].size | Decimal | 持仓大小（正=多，负=空） |
| portfolios[].positions[].entryPrice | Decimal | 开仓均价 |
| portfolios[].positions[].entryCost | Decimal | 开仓成本 |
| portfolios[].positions[].leverage | u8 | 杠杆倍数 |
| portfolios[].positions[].isCross | bool | 是否全仓（true=全仓, false=逐仓） |
| portfolios[].positions[].isolatedCollateral | Decimal / null | 逐仓保证金（仅 isCross=false 时有值） |
| portfolios[].orders[] | array | 挂单列表 |
| portfolios[].orders[].orderId | u64 | 订单 ID |
| portfolios[].orders[].assetId | AssetId | 交易对 ID |
| portfolios[].orders[].side | string | "buy" 或 "sell" |
| portfolios[].orders[].price | Decimal | 挂单价格 |
| portfolios[].orders[].size | Decimal | 订单大小 |
| portfolios[].orders[].filledSize | Decimal | 已成交大小 |
| portfolios[].orders[].status | string | 订单状态：Pending / PartiallyFilled / Filled |

---

### 4.2 查询用户子账号

#### GET /user/{address}/subaccounts

**功能描述**：获取指定用户的所有子账号信息。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| address | string | Y | 用户地址，0x 开头 |

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": [
    {
      "user": "0xaaa...",
      "name": "sub-account-1",
      "master": "0x7e97..."
    }
  ]
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| user | string(Address) | 子账号地址 |
| name | string | 子账号名称 |
| master | string(Address) | 主账号地址 |

---

### 4.3 查询永续合约资产列表

#### GET /assets

**功能描述**：获取所有永续合约 (perps) 交易资产的元数据列表。

**Query Params**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "assets": [
      {
        "assetId": { "type": "perps", "index": 0 },
        "name": "BTC-PERP",
        "sizeDecimals": 4,
        "marginTableId": 0
      },
      {
        "assetId": { "type": "perps", "index": 1 },
        "name": "ETH-PERP",
        "sizeDecimals": 3,
        "marginTableId": 1
      }
    ]
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| assets[].assetId | AssetId | 资产 ID（复合类型：perps + index） |
| assets[].name | string | 资产名称 |
| assets[].sizeDecimals | i8 | 下单精度 |
| assets[].marginTableId | u64 | 保证金表 ID |

---

### 4.4 查询所有 Vault

#### GET /vaults

**功能描述**：获取所有 Vault（池化交易账户）的完整信息。

**Query Params**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "vaults": {
      "0x1234...5678": {
        "name": "Alpha Vault",
        "description": "Momentum trading strategy",
        "createTime": 1710000000000,
        "vaultUser": "0xaaaa...bbbb",
        "leader": "0x1234...5678",
        "userStates": {},
        "leaderCommission": 0.1,
        "isClosed": false,
        "lockupDuration": 86400000,
        "allowDeposits": true,
        "relationship": "...",
        "alwaysCloseOnWithdraw": false
      }
    }
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| vaults | Map<Address, Vault> | key=vault 管理者地址，value=Vault 详情 |
| vault.name | string | Vault 名称 |
| vault.description | string | 描述/策略说明 |
| vault.createTime | u64 | 创建时间戳（毫秒） |
| vault.vaultUser | Address | Vault 账户地址 |
| vault.leader | Address | 管理者地址 |
| vault.userStates | Map<Address, VaultUserState> | 用户状态映射 |
| vault.leaderCommission | f64 | 管理者佣金率（0.0 - 0.5） |
| vault.isClosed | bool | 是否已关闭 |
| vault.lockupDuration | u64 | 最短锁定期（毫秒） |
| vault.allowDeposits | bool | 是否允许存入 |
| vault.alwaysCloseOnWithdraw | bool | 提现时是否强制平仓 |

---

### 4.5 查询单个 Vault

#### GET /vaults/{address}

**功能描述**：按地址查询单个 Vault 详情。

**Path Params**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| address | string | Y | Vault 地址，0x 开头 |

**Response**

```json
// 成功
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "name": "Alpha Vault",
    "description": "Momentum trading strategy",
    "createTime": 1710000000000,
    "vaultUser": "0xaaaa...bbbb",
    "leader": "0x1234...5678",
    "userStates": {},
    "leaderCommission": 0.1,
    "isClosed": false,
    "lockupDuration": 86400000,
    "allowDeposits": true,
    "relationship": "...",
    "alwaysCloseOnWithdraw": false
  }
}

// 不存在
{
  "code": 10004,
  "message": "vault 0x... not found",
  "data": null
}
```

---

### 4.6 查询 Sequencer Leader 状态

#### GET /sequencer/leader

**功能描述**：查询当前节点是否为 Sequencer Leader。

**Query Params**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "data": {
    "leader": true
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| leader | bool | 当前节点是否为 leader |

---

### 4.7 查询 Sequencer Leader 信息

#### GET /sequencer/leader-info

**功能描述**：获取当前 Leader 节点的 ID 和 RPC 地址。

**Query Params**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "data": {
    "nodeId": 1,
    "rpcUrl": "http://10.0.0.1:10000"
  }
}

// 尚无 leader
{
  "code": 0,
  "message": "OK",
  "data": {
    "nodeId": null,
    "rpcUrl": null
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| nodeId | u64 / null | Leader 节点 ID |
| rpcUrl | string / null | Leader 节点的 RPC 地址 |

---

### 4.8 停止 Sequencer

#### POST /sequencer/stop

**功能描述**：停止当前节点的 Sequencer 选举。禁用心跳和选举，使 follower 超时后选举新 Leader。仅 Leader 可调用。

**Request Body**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "data": {
    "stopped": true
  }
}

// 非 Leader 节点
{
  "code": 10005,
  "message": "no leader: this node is a follower",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| stopped | bool | 是否成功停止 |

---

### 4.9 启动 Sequencer

#### POST /sequencer/start

**功能描述**：重新启用之前被停止的节点的 Raft 心跳和选举。节点将重新加入 Leader 选举。

**Request Body**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "data": {
    "started": true
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| started | bool | 是否成功启动 |

---

### 4.10 设置停止区块高度

#### POST /node/stop_at_block

**功能描述**：设置一个目标区块高度，节点到达该高度后停止出块/消费。节点本身保持运行，RPC 仍可查询。HA 模式下会广播到所有 peer 节点。

**Query Params**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| broadcast | bool | N | true | 是否广播到 peer 节点。设为 false 跳过广播（避免循环） |

**Request Body**

```json
{
  "block_number": 2000000
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| block_number | u64 | Y | 目标停止高度。必须 >0，必须是 10000 的倍数，必须比当前高度至少高 2000 |

**Response**

```json
// 成功
{
  "code": 0,
  "message": "OK",
  "data": {
    "blockNumber": 2000000,
    "peerCount": 2
  }
}

// 参数校验失败
{
  "code": 10001,
  "message": "block_number (1500000) must be a multiple of 10000",
  "data": null
}

// 广播失败
{
  "code": 20001,
  "message": "Failed to broadcast stop_at_block to 1 peer(s): ...",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| blockNumber | u64 | 已设置的停止目标高度 |
| peerCount | usize | 集群中 peer 节点数量（不含自身） |

---

### 4.11 获取状态快照元数据

#### GET /state/metadata

**功能描述**：获取状态快照的元数据信息（高度和 SHA-256 哈希），用于节点间状态同步前的一致性校验。

> **注意**：此接口不返回标准 ApiResponse 信封，直接返回 JSON 对象。HTTP 错误码表示状态：404=快照不存在，503=state store 不可用。

**Query Params**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| height | u64 | N | - | 指定高度。省略则返回最新快照 |

**Response**

```json
{
  "height": 19876543,
  "sha256": "a1b2c3d4e5f6..."
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| height | u64 | 快照高度 |
| sha256 | string | 序列化状态的 SHA-256 哈希（hex） |

---

### 4.12 下载状态快照

#### GET /state/snapshot

**功能描述**：下载指定高度（或最新）的状态快照二进制文件，用于节点间状态同步。返回 MessagePack 格式的序列化数据。

> **注意**：此接口不返回 JSON，返回 `application/octet-stream` 二进制数据。HTTP 错误码表示状态。

**Query Params**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| height | u64 | N | - | 指定高度。省略则返回最新快照 |

**Response**

- Content-Type: `application/octet-stream`
- Body: MessagePack 序列化的 DexState 二进制数据

**HTTP 错误码**

| 状态码 | 含义 |
|--------|------|
| 200 | 成功 |
| 404 | 指定高度无快照 |
| 500 | 加载/序列化失败 |
| 503 | State store 不可用 |

---

### 4.13 通用状态查询

#### GET /state

**功能描述**：通过 JSON Pointer 路径查询 DexState 的任意子字段。全量状态序列化后按路径定位，无需硬编码字段名。

> **注意**：省略 path 参数会返回完整 DexState，数据量极大，请谨慎使用。

**Query Params**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| path | string | N | - | 点分隔的字段路径，如 `exchange.spot_market.meta`。省略返回完整状态 |

**Response**

```json
// 查询 ?path=exchange.spot_market.meta
{
  "code": 0,
  "message": "OK",
  "block": { "height": 19876543, "time": 1710000000000 },
  "data": {
    "tokens": [ ... ],
    "assets": [ ... ],
    "prediction": { ... }
  }
}

// 字段不存在
{
  "code": 10004,
  "message": "field not found: exchange.nonexistent",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| data | any | 对应路径下的 JSON 数据，结构取决于查询路径 |

---

### 4.14 查询版本信息

#### GET /version

**功能描述**：返回构建时元数据，CI 管道可用于验证运行的二进制与最新编译代码一致。

**Query Params**：无

**Response**

```json
{
  "code": 0,
  "message": "OK",
  "data": {
    "service": "sequencer-rpc",
    "version": "0.1.0",
    "gitHash": "a1b2c3d4",
    "gitBranch": "main",
    "gitDate": "2026-05-10",
    "buildTime": "2026-05-10T12:00:00Z",
    "buildTarget": "x86_64-unknown-linux-gnu",
    "rustcVersion": "1.80.0"
  }
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| service | string | 服务名称，固定 "sequencer-rpc" |
| version | string | 版本号 |
| gitHash | string | Git commit 哈希 |
| gitBranch | string | Git 分支名 |
| gitDate | string | Git commit 日期 |
| buildTime | string | 构建时间 |
| buildTarget | string | 编译目标平台 |
| rustcVersion | string | Rust 编译器版本 |

---

### 4.15 Explorer 数据重推（需启用 explorer feature）

#### POST /explorer/republish

**功能描述**：重推指定区间的区块数据到 Kafka。仅在启用 `explorer` feature 时存在。

> **注意**：此接口有并发限制，同时只能执行一个重推任务。

**Request Body**

```json
{
  "start_height": 1000,
  "end_height": 2000
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| start_height | u64 | Y | 起始高度（含） |
| end_height | u64 | Y | 结束高度（含） |

**Response**

```json
// 成功
{
  "code": 0,
  "message": "OK",
  "data": {
    "startHeight": 1000,
    "endHeight": 2000,
    "totalBlocks": 1001,
    "totalRecords": 5005,
    "costMs": 3200
  }
}

// 并发限制
{
  "code": 10001,
  "message": "republish concurrency limit reached, try again later",
  "data": null
}
```

**字段说明**

| 字段 | 类型 | 说明 |
|------|------|------|
| startHeight | u64 | 起始高度 |
| endHeight | u64 | 结束高度 |
| totalBlocks | u64 | 处理的区块总数 |
| totalRecords | u64 | 推送的记录总数 |
| costMs | u64 | 耗时（毫秒） |

---

## ZKP 集成关键接口汇总

以下是 op-succinct（ZKP Proposer/Challenger）集成 TradeZone 时最关键的接口汇总：

| 用途 | 接口 | 方法 | 关键字段 |
|------|------|------|----------|
| 获取最新链高度 | `/chain/latest_height` | GET | blockHeight, blockHash, blockTime |
| 获取已确认 appHash | `/chain/confirmed_block_info` | GET | height, appHash, blockHash |
| 查询区块事件 | `/block/{height}/events` | GET | events[] (含交易结果) |
| 查询交易打包状态 | `/transaction/{txHash}/inclusion` | GET | blockHeight, status, txIndex |
| 提交交易 | `/transaction` | POST | txHash |
| TEE 创建证明任务 | `/tee/task` | POST | taskId |
| TEE 查询任务状态 | `/tee/task/{taskId}` | GET | status, proofBytes |
| TEE 删除任务 | `/tee/task/{taskId}` | DELETE | taskId |
| TEE 节点信息 | `/tee/info` | GET | attestationDoc, pubKey, commit |
| Bridge 状态 | `/bridge/status` | GET | balances, eventNonce, eventCursor |
| 状态快照元数据 | `/state/metadata` | GET | height, sha256 |
| 状态快照下载 | `/state/snapshot` | GET | (binary MessagePack) |

### 典型集成流程

1. **Proposer** 定期调用 `GET /chain/confirmed_block_info` 获取已确认的 appHash
2. **Proposer** 调用 `GET /chain/latest_height` 确认链最新高度
3. **Proposer** 通过 `GET /block/{height}/events` 获取区块事件用于状态转换验证
4. **Challenger** 调用 `POST /tee/task` 创建 TEE 证明任务
5. **Challenger** 轮询 `GET /tee/task/{taskId}` 等待证明完成
6. **Challenger** 获取 `proofBytes` 后提交到 L1 合约的 `TeeDisputeGame.prove()`

### AssetId 复合类型说明

AssetId 在 JSON 中根据市场类型有不同序列化形式：

- **Spot**: `{ "type": "spot", "index": 0 }` 或简单数字 `0`
- **Prediction**: `{ "type": "prediction", "marketId": 1, "outcomeIndex": 0 }`
- **Perps**: `{ "type": "perps", "index": 0 }`
