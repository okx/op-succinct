# gen-tradezone-rpc — 从 TradeZone 代码仓库生成 RPC 接口知识库文档

## 用途

为 op-succinct 项目生成 TradeZone L2 链的完整 REST API 知识库文档（`context-kg/technical/apis/tradezone-rpc.md`），使 AI 编码助手在开发 ZKP/Proposer/Challenger 集成代码时能正确调用 TradeZone 接口。

---

## 前置：获取 TradeZone 源码

TradeZone 代码不在 op-succinct 仓库内，需先克隆：

```bash
# 克隆 tradezone 仓库（需要 GitLab 权限）
git clone https://gitlab.okg.com/xlayer-dex/tradezone.git /tmp/tradezone

# 或者如果本地已有，直接使用
# TRADEZONE_ROOT=/path/to/your/tradezone
```

后续步骤中 `{TRADEZONE_ROOT}` 指代 tradezone 仓库根目录。

---

## 数据源

| 数据源 | 路径（相对于 TRADEZONE_ROOT） | 作用 |
|--------|-------------------------------|------|
| 路由注册文件 | `crates/chain/src/rpc/routes/{chain,business,tee,internal}.rs` | 发现全部端点（Method + Path） |
| RPC 接口设计文档 | `specs/business/prediction/architecture/008-TradeZone-Prediction-RPC接口设计.md` | 主要业务接口的 Request/Response 详细定义 |
| Handler 实现代码 | `crates/chain/src/rpc/handlers/*.rs`（约 19 个文件） | 补全 specs 未覆盖的接口定义 |
| 统一响应类型 | `crates/chain/src/rpc/response.rs` | ApiResponse envelope 结构 |
| 路由模块入口 | `crates/chain/src/rpc/routes/mod.rs` | 路由分类规则和 feature gate |

---

## 执行步骤

### Step 0: 克隆 TradeZone 仓库

```bash
git clone https://gitlab.okg.com/xlayer-dex/tradezone.git /tmp/tradezone
TRADEZONE_ROOT=/tmp/tradezone
```

### Step 1: 发现所有路由端点

读取 4 个路由文件，提取完整端点列表：

```bash
cat $TRADEZONE_ROOT/crates/chain/src/rpc/routes/chain.rs
cat $TRADEZONE_ROOT/crates/chain/src/rpc/routes/business.rs
cat $TRADEZONE_ROOT/crates/chain/src/rpc/routes/tee.rs
cat $TRADEZONE_ROOT/crates/chain/src/rpc/routes/internal.rs
```

从 `Router::new().route(path, method(handler))` 提取端点清单。当前已知 30 个端点：

| 模块 | 端点数 | 示例 |
|------|--------|------|
| Chain | 6 | `/transaction`, `/chain/latest_height`, `/chain/confirmed_block_info` |
| Business | 9 | `/user/{address}/balance/{token_id}`, `/market/{market_id}`, `/prediction/meta` |
| TEE | 4 | `/tee/task` (POST/GET/DELETE), `/tee/info` |
| Internal | 11+ | `/state/snapshot`, `/sequencer/leader`, `/assets`, `/vaults` |

注意 `tee.rs` 有 `#[cfg(feature = "tee")]` 门控。

### Step 2: 读取 specs 文档

```bash
cat $TRADEZONE_ROOT/specs/business/prediction/architecture/008-TradeZone-Prediction-RPC接口设计.md
```

此文档覆盖约 12 个主要业务接口的详细 Request/Response 定义。优先采用 specs 中的定义（更准确、有示例）。

### Step 3: 从 Handler 代码补全

对 specs 未覆盖的端点（batch transaction、limits、state sync、sequencer control、version 等），逐一读取 handler 文件：

```bash
# 读取所有 handler 文件
ls $TRADEZONE_ROOT/crates/chain/src/rpc/handlers/*.rs
# 约 19 个文件：transaction.rs, tx_inclusion.rs, event.rs, chain.rs,
#   balance.rs, market.rs, orderbook.rs, bridge.rs, account.rs, spot.rs,
#   limits.rs, tee.rs, state_sync.rs, state_query.rs, sequencer.rs,
#   node.rs, version.rs, vault.rs, asset.rs
```

从每个 handler 提取：
1. **Request 类型**：函数签名中的 `Path<T>`、`Query<T>`、`Json<T>` 参数
2. **Response 类型**：`ApiResult<T>` 中的 T 结构体
3. **错误场景**：`Err(ApiError::...)` 分支

### Step 4: 读取统一响应结构

```bash
cat $TRADEZONE_ROOT/crates/chain/src/rpc/response.rs
```

提取 `ApiResponse<T>` envelope 结构：`{ code, message, block: { height, time }, data: T }`

### Step 5: 生成知识库文档

将以上信息整合，按以下结构写入 `context-kg/technical/apis/tradezone-rpc.md`：

```markdown
---
name: tradezone-rpc
description: TradeZone (tz) L2 链 REST API 完整接口文档。
sources: [specs, routes, handlers, response.rs]
updated_at: "{date}"
---

# TradeZone REST API 接口文档

## 通用规则
（envelope、错误码、HTTP 状态码）

## 一、Chain API
（每个端点：Method+Path、功能描述、参数表、Request Body、Response 示例、字段说明）

## 二、Business API
...

## 三、TEE API
...

## 四、Internal API
...

## ZKP 集成关键接口汇总
（op-succinct 需要调用的接口子集）
```

### Step 6: 质量检查

- [ ] 路由文件中注册的每个端点都有对应章节（30/30）
- [ ] 每个端点有：Method + Path、功能描述、参数表、Request Body（POST）、Response JSON 示例、字段说明表
- [ ] 错误场景覆盖（参数错误、数据不存在、非 Leader、服务异常）
- [ ] 统一响应结构（envelope）已说明
- [ ] 错误码表完整（0, 10001, 10004, 10005, 10006, 20001）
- [ ] TEE 接口标注 `仅 tee feature 启用时可用`
- [ ] Internal 接口标注 `不对外暴露，可能随时变更`
- [ ] ZKP 集成汇总表包含 confirmed_block_info、state/snapshot、state/metadata

---

## 输出要求

### 每个端点必须包含

| 要素 | 说明 | 缺失后果 |
|------|------|----------|
| Method + Path | `GET /chain/confirmed_block_info` | AI 无法构造请求 |
| 功能描述 | 一句话说明用途 | AI 不知道何时该调用此接口 |
| Path/Query Params | 参数名、类型、是否必填、说明 | AI 生成的 URL 参数错误 |
| Request Body | JSON 示例 + 字段表（POST/PUT） | AI 构造的请求体格式不对 |
| Response 成功示例 | 完整 JSON（含 envelope） | AI 无法正确解析响应 |
| Response 失败示例 | 至少 1 个错误场景 | AI 缺少错误处理逻辑 |
| 字段说明表 | 字段名、类型、含义 | AI 对字段语义理解错误 |

### 不要做

- 不要只写端点标题和一行描述（AI 无法据此生成代码）
- 不要省略 Response 中嵌套对象的字段说明
- 不要遗漏 feature-gated 接口（TEE）
- 不要把 Internal 接口和公开接口混在一起（分开章节）

---

## 清理

生成完成后，如果是临时克隆的 tradezone 仓库：

```bash
rm -rf /tmp/tradezone
```

生成的知识库文档位于 op-succinct 仓库内（`context-kg/technical/apis/tradezone-rpc.md`），会随 op-succinct 一起提交。
