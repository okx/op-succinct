# prd-publish — project config for op-succinct

## Publish targets

| Target | Enabled | Notes |
|--------|---------|-------|
| Jira | yes | Project key: PRF |
| Lark Wiki | yes | Import to personal space, then move to the Proof wiki node |
| Specs submodule | no | Not used in this project |

---

## Jira workflow

- **project_key**: `PRF`
- **base_url**: `https://okcoin.atlassian.net/browse`

1. If the user provides a Jira key:
   - Use `/jira-ops` to confirm it exists
   - Record `JIRA_ISSUE`
   - Check whether the Jira title and description already cover the required modules
   - If missing, fill from existing PRD content; do not overwrite valid user-provided information
   - If the user has not authorized Jira updates, only mention the missing items in the final report

2. If the user asks to create a Jira:
   - Use `/jira-ops` to create in project `PRF`
   - Title: extract from the PRD title
   - Description modules: background and goals, technical solution, impact scope, acceptance criteria, risk assessment
   - If the PRD does not provide an implementation plan, write "Technical solution to be filled in during the TD stage"
   - Type: feature/optimization → Story or Task; bug → Bug

3. After Jira succeeds, insert at the top of `{prefix}_prd.md`:

```markdown
> **Jira**: [PRF-xxx](https://okcoin.atlassian.net/browse/PRF-xxx)
```

---

## Lark workflow

### Naming conventions

- **Lark doc title**: `{JIRA_ISSUE} - {short_description}`
  - Left: Jira issue key, e.g. `PRF-456`
  - Right: short description in Chinese, 6-20 characters
  - Separator: ` - ` (space-hyphen-space)
  - No `.md` / `.docx` suffix

### Wiki node classification table

All PRDs in this project go to a single wiki node (no keyword-based routing).

| Category | parent_node_token | Trigger keywords |
|----------|-------------------|------------------|
| Proof (default) | `LrAuw4SyDi5V8YkNZQhl7OFkgpc` | all PRDs — single target, no keyword matching needed |

Classification rule: always use the Proof node. No fallback needed.

### Iron rules

- **The import call must NOT include folder_token / wiki space / parent_node**: always land in personal space root first; wiki move is a separate step.
- Import or move failure does not trigger retry-overwrite: keep local drafts and let the user decide next action.

### Import steps

1. Require an existing `JIRA_ISSUE` (used as the doc title prefix).

2. Prepare the final Markdown content:
   - Read the full `{prefix}_prd.md` (Part A + Part B).
   - If Jira workflow already succeeded, confirm the `> **Jira**: ...` link is in the header.

3. Call the import API — the docx lands in personal space:

```
lark_drive_import_document(
  file_name: "{JIRA_ISSUE} - {short_description}.md",
  content:   <full Markdown content of {prefix}_prd.md>,
  type:      "docx"
)
```

   - Do NOT pass mount_key / folder / wiki / space parameters.

4. Capture two values from the response:
   - Document URL (e.g. `https://*.larksuite.com/docx/<token>`)
   - Document `obj_token` (the token after `/docx/` in the URL)

5. Target wiki node: always `LrAuw4SyDi5V8YkNZQhl7OFkgpc` (Proof node).

6. **Capability detection**: search the currently loaded MCP tools for a write tool whose semantics are "move a Drive document into a wiki parent node." Common name patterns:
   - `*move_docs_to_wiki*`
   - `*wiki*add_node*`
   - `*wiki*node*create*` (that accepts `obj_token` / `obj_type` parameters)

   Reference Lark Open API: `POST /open-apis/wiki/v2/spaces/{space_id}/nodes/move_docs_to_wiki`.

7. Execute one of two paths:

   **7-A — Wiki move tool available (preferred)**:

   ```
   lark_wiki_move_docs_to_wiki(
     parent_node_token: "LrAuw4SyDi5V8YkNZQhl7OFkgpc",
     obj_type:          "docx",
     obj_token:         <docx token from step 4>
   )
   ```

   - If the tool requires `space_id`, obtain it via `lark_wiki_get_node(token="LrAuw4SyDi5V8YkNZQhl7OFkgpc")`. Do not ask the user.
   - On success, prefer the wiki URL for write-back.

   **7-B — No wiki move tool in current MCP (degradation)**:

   Do not retry, do not fabricate a call:

   - Call `lark_wiki_get_node(token="LrAuw4SyDi5V8YkNZQhl7OFkgpc")` to verify the target node exists and obtain `space_id` / node title.
   - Set Lark mode to `skipped (mcp-missing)`.
   - Report: docx URL, target wiki node token, node title, `space_id`, and a manual instruction: "Please drag the doc to the Proof node in the Lark UI."
   - Do NOT auto-clean local drafts.

8. Write the Lark link back to the local PRD — insert below the Jira link (or at line 1 if no Jira line):

```markdown
> **Lark Doc**: <wiki_url or docx_url>
```

### Output fields for Lark

- **Lark**: mode (imported / moved / `skipped (mcp-missing)` / skipped / failed) + doc title + docx URL + wiki URL (if available) + target wiki node token + node title + `space_id`

### Forbidden actions (Lark-specific)

- Passing folder_token / wiki space / parent_node to `lark_drive_import_document`
- Moving the docx to a wiki node other than `LrAuw4SyDi5V8YkNZQhl7OFkgpc`
- Fabricating a successful wiki move when no wiki-move tool exists
- Cleaning up local drafts when Lark mode is `skipped (mcp-missing)`
