---
name: "precompile-correctness"
description: "zkVM precompile correctness pitfalls — gas accounting, status classification, proof/L1 parity"
---
# Precompile Correctness Pitfalls

## Status-Based Result Classification

[Pitfall] `utils/client/src/precompiles/mod.rs`: `OpZkvmPrecompiles::run` uses a status-based result model (revm 38 / op-revm). Four outcome categories must all be mapped: (1) `is_success_or_revert() && !is_revert()` → `InstructionResult::Return`, (2) `is_revert()` → `InstructionResult::Revert`, (3) halt + `is_oog()` → `InstructionResult::PrecompileOOG`, (4) halt + `!is_oog()` → `InstructionResult::PrecompileError`. Missing any branch silently breaks proof correctness — the zkVM guest proof must reproduce the exact same state root as L1 execution. Trigger: future revm upgrade that adds new status categories. Correct approach: exhaustively match all status branches and add parity tests against `OpPrecompiles` for every `OpSpecId` variant.
- **Module**: `utils/client/src/precompiles/mod.rs`
- **Date**: 2026-06-29
- **Hit count**: 1
