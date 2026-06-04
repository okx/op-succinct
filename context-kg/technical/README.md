---
name: "README"
description: "Directory index and reading guide for the op-succinct technical knowledge base"
---
# context-kg/technical — Knowledge Base

op-succinct is a multi-crate Rust workspace for proving OP Stack L2 state transitions with SP1 zkVM. It contains a validity proposer service, a fault-dispute proposer/challenger pair, zkVM client+host utilities, three DA-layer adapters (Ethereum/Celestia/EigenDA), and a remote-signer abstraction.

## Files and Directories

| Path | Description |
|------|-------------|
| `knowledge-base.md` | **Highest authority** — all Skills defer to this on conflicts |
| `terminology.md` | Glossary of domain and code terms |
| `arch/architecture-overview.md` | Layer definitions and per-module responsibilities |
| `arch/dependency.md` | Crate dependency map + storage/external services |
| `apis/rest-api-conventions.md` | API conventions (n/a — service has no public REST surface) |
| `apis/error-codes.md` | Error registration conventions |
| `conventions/feature-types.md` | DA feature flags, ELF embedding, build patterns |
| `conventions/service-patterns.md` | Signer dispatch, witness collection, polling, retries |
| `conventions/common-tools.md` | Reusable components & traits |
| `modules/*.md` | Per-crate design notes (one file per workspace member) |
| `core-flows/*.md` | End-to-end flow documentation |
| `pitfalls/*.md` | Known traps and historical lessons |
| `decisions/ADR-*.md` | Architecture Decision Records — design rationale and alternatives |
| `guides/*.md` | Developer guides — quick start, adding DA layers, debugging, testing |

## How to Read This Knowledge Base

1. **Knowledge base is the highest authority** — defer to it over general AI knowledge.
2. **Locate the specific module** — read `modules/{crate}.md` before starting work in that crate.
3. **Check pitfalls and core flows first** — most issues hit here are documented.
4. **Produce a constraint checklist** — explicitly declare if no relevant content was found.
5. **Cross-validate during work** — correct violations immediately.

## Workspace Members (24)

`utils/{client,host,build,proof,signer,elfs}`,
`utils/celestia/{client,host}`, `utils/eigenda/{client,host}`, `utils/ethereum/{client,host}`,
`programs/range/{celestia,eigenda,ethereum,utils}`, `programs/aggregation`,
`scripts/{prove,utils}`, `validity`, `fault-proof`, `fault-proof/tee/{types,enclave}`, `bindings`.
