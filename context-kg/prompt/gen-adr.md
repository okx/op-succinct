---
name: "gen-adr"
description: "生成 prompt：从 git history 和代码结构中蒸馏架构决策记录（ADR），输出到 context-kg/technical/decisions/"
---

# gen-adr — 从代码仓库蒸馏架构决策记录

## 用途

为任意后端项目从 git history、代码结构和已有文档中提取关键架构决策，生成符合 tradezone 规范的 ADR 文件，输出到 `context-kg/technical/decisions/`。

## 前置条件

- 项目已有 `context-kg/technical/` 目录（至少有 knowledge-base.md）
- 可访问完整 git history

## 执行步骤

### Phase 1: 候选决策发现

从以下三个维度并行收集候选 ADR 主题：

**1.1 Git History 扫描**

```bash
# 统计总 commit 数
git log --oneline --all | wc -l

# 提取关键架构变更（feat/refactor/breaking/migration/perf）
git log --oneline --all | grep -iE "(feat|fix|refactor|breaking|migration|upgrade|perf)" | head -50

# 提取文档类 commit（可能包含设计说明）
git log --oneline --all --diff-filter=A -- "*.md" | head -30

# 查找设计相关 commit
git log --oneline --all | grep -iE "(decision|adr|why|rationale|design|arch)" | head -20
```

**1.2 代码结构分析**

识别以下模式所隐含的架构决策：
- `cfg_if!` / `#[cfg(feature = ...)]` → 编译期选择决策
- `[patch.crates-io]` → fork/patch 策略
- `Arc<Mutex<...>>` / `Arc<RwLock<...>>` → 并发控制决策
- 独立的 Dockerfile 变体 → 容器化策略
- 多个 `migrations/` 文件 → 存储选型决策
- `enum { ... }` 用于模式分发 → 多模式支持决策
- `include_bytes!` → 嵌入策略

**1.3 已有知识库交叉引用**

读取以下文件，识别"有规则但无决策记录"的条目：
- `knowledge-base.md` 中的 [Rule] 标记 → 每条硬性规则背后通常有一个架构决策
- `pitfalls/*.md` 中的 [Pitfall] 标记 → 踩坑通常源于某个设计取舍
- `conventions/*.md` 中的 [Convention] 标记 → 约定通常源于某个架构选择

### Phase 2: 深度提取（并行 sub-agent）

对每个候选 ADR 主题，派一个 sub-agent 读取相关代码和 commit，提取：

1. **Decision**: 做了什么选择
2. **Context**: 解决什么问题
3. **Alternatives**: 考虑过哪些方案（从代码注释、commit message、PR 讨论中提取）
4. **Consequences**: 正面/负面/中性后果
5. **Code locations**: 关键文件路径、函数/struct/trait 名

**sub-agent prompt 模板：**

```
读取 {repo_path} 中与 {topic} 相关的代码。

需要回答：
1. 做了什么决策？
2. 解决什么问题？为什么需要这个决策？
3. 考虑过哪些替代方案？为什么被否决？
4. 这个决策带来哪些后果？（正面/负面/中性）
5. 关键代码在哪里？（文件路径 + 函数/struct 名，不要行号）

相关文件提示：{file_hints}
相关 commit 提示：{commit_hints}
```

建议每 5 个 ADR 一批并行提取，避免上下文过大。

### Phase 3: ADR 撰写

每个 ADR 严格遵循以下格式（与 tradezone ADR 一致）：

```markdown
---
name: "ADR-{NNN}-{kebab-case-title}"
description: "ADR: {一句话摘要，对 AI Agent 有用的决策描述}"
---

# ADR-{NNN}: {标题}

## Status

{Accepted | In Progress | Deprecated}

## Context

{问题背景，为什么需要做这个决策。引用相关文件路径和函数名。}

## Decision

{具体决策。包含关键代码片段（仅展示 struct/trait 签名或核心模式，不展示完整实现）。}

## Alternatives Considered

| 方案 | 优点 | 缺点 | 结论 |
|------|------|------|------|
| ... | ... | ... | **采纳** / **否决** |

## Consequences

- **正面**: ...
- **负面**: ...
- **中性**: ...
```

### Phase 4: 验证

对每个 ADR 中引用的代码锚点做 spot check：

```bash
# 验证文件存在
ls {referenced_file_path}

# 验证 struct/function 存在
grep "{struct_or_fn_name}" {file_path}

# 验证 feature/patch 存在
grep "{feature_name}" Cargo.toml
```

### Phase 5: 索引更新

更新 `context-kg/technical/README.md`，在文件表中添加 `decisions/` 行。
更新 `context-kg/README.md`，在技术域描述中提及 decisions。

### Phase 6: 全局验证（必须执行）

所有 ADR 撰写完成后，逐个验证每个 ADR 中引用的文件路径、struct/函数名、feature、[Rule]/[Pitfall] 等是否与当前代码库一致。发现过时的立即修正，无法修正的直接删除该 ADR。验证通过后才可提交。

## 质量规则

### 必须遵守

- [Rule] 不写行号 — 使用文件路径 + 函数/struct/trait 名作为稳定锚点
- [Rule] 不写 commit hash 作为证据 — commit hash 对 AI 编码无帮助
- [Rule] main 分支不存在的代码不写 ADR — 未合并的 feature 分支内容跳过
- [Rule] 每个 ADR 必须有 YAML frontmatter（name + description）
- [Rule] description 字段必须对 AI Agent 有用（不是给人看的标题，而是帮助 Agent 判断是否需要读这个文件的一句话）
- [Rule] Alternatives Considered 必须是表格，不能纯文字
- [Rule] Consequences 必须分正面/负面/中性三类

### 应当遵守

- [Convention] 代码片段只展示 struct 定义、trait 签名、关键 dispatch 逻辑，不展示完整实现
- [Convention] 引用已有知识库文档时使用 [Rule]/[Pitfall] 标记而非路径+行号
- [Convention] 如果决策是外部约束（如第三方协议），在 Context 中明确说明"这不是可选择的架构决策"
- [Convention] Status 为 In Progress 时，说明在哪个分支上

### 不应做的

- [Pitfall] 不要为每个 module 都写 ADR — 只有涉及"为什么这样设计而非那样"的取舍才需要 ADR
- [Pitfall] 不要在 ADR 中重复 modules/*.md 已有的内容 — ADR 关注 why，modules 关注 what
- [Pitfall] 不要创建"决策者"字段 — ADR 是团队共识
- [Pitfall] 不要用中文写 Status/Section 标题 — 保持 Status/Context/Decision/Alternatives Considered/Consequences 英文标题，与 tradezone 一致

## 输出示例

参考 `context-kg/technical/decisions/ADR-001-validity-fault-proof-separation.md` 到 `ADR-010-aggregation-proof-chaining.md`。
