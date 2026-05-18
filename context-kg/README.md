---
name: "README"
description: "Root index for the op-succinct context-kg knowledge base — three-domain structure"
---
# context-kg — Knowledge Base

op-succinct is a Rust workspace that proves OP Stack L2 state transitions with SP1 zkVM and operates as both validity proposer and fault-dispute proposer/challenger.

## Domain Structure

| Domain | Path | Description |
|--------|------|-------------|
| Technical | `technical/` | Architecture, modules, APIs, conventions, core flows, pitfalls, decisions (ADR) |
| Business | `business/` | Business rules, product flows, domain policies (placeholder) |
| Quality | `quality/` | Test strategies, quality gates, coverage requirements (placeholder) |

## Quick Start

Load the technical knowledge base before starting development work:
```
/backend-context-kg-loader developing
```
