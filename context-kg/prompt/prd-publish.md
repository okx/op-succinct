---
name: "prd-publish"
description: "PRD publish configuration for op-succinct"
---

# prd-publish — project config for op-succinct

## Publish targets

| Target | Enabled |
|--------|---------|
| Jira | yes |
| Lark Wiki | yes |
| Specs submodule | no |

## Jira config

| Key | Value |
|-----|-------|
| `project_key` | `PRF` |
| `base_url` | `https://okcoin.atlassian.net/browse` |

## Lark config

| Key | Value |
|-----|-------|
| `doc_title_format` | `{JIRA_ISSUE} - {short_description}` |
| `short_description_lang` | Chinese, 6-20 characters |

### Wiki node classification table

| Category | parent_node_token | Trigger keywords |
|----------|-------------------|------------------|
| Proof (default) | `LrAuw4SyDi5V8YkNZQhl7OFkgpc` | all PRDs |
