---
name: "README"
description: "Root index for the op-succinct context-kg knowledge base — three-domain structure"
---

# Context Knowledge Graph

This directory is the context knowledge base for the op-succinct project — a Rust workspace that proves OP Stack L2 state transitions with SP1 zkVM, operating as both validity proposer and fault-dispute proposer/challenger.

## Directory Guide

- `technical/knowledge-base.md`: Highest-authority rules and global constraints
- `technical/terminology.md`: Domain term glossary and naming conventions
- `technical/arch/`: Architecture design (layer definitions, crate dependency map)
- `technical/modules/`: Per-crate design documentation (validity, fault-proof, utils-signer, utils-proof, DA adapters, programs, scripts, bindings — 22 crates)
- `technical/core-flows/`: End-to-end flow documentation (validity proposer loop, fault-proof proposer/challenger, aggregation proof, range program execution, witness generation, XLayer remote signing)
- `technical/apis/`: API specifications (error codes, REST conventions, TradeZone RPC interface)
- `technical/decisions/`: Architecture Decision Records (service separation, compile-time DA selection, SignerLock nonce safety, SP1 fork strategy, XLayer signer protocol, cluster/network dual modes, Postgres request lifecycle, ELF embedding, aggregation proof chaining)
- `technical/conventions/`: Reusable patterns and components (common tools, DA feature types, service patterns, environment variables)
- `technical/pitfalls/`: Cross-module pitfall records (concurrency, DA witness, dependencies, proof lifecycle, signer)
- `technical/guides/`: Developer guides (quick start, adding new DA layer, debugging, testing)
- `business/`: Business knowledge domain (TradeZone prediction market rules, ZK hybrid proof architecture)
- `quality/`: Quality knowledge domain (planned)
