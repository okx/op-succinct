---
name: "debugging-guide"
description: "Debugging reference — log configuration, common errors, diagnostic commands for proof failures"
---

# Debugging Guide

## Log Configuration

Set `RUST_LOG` to control log verbosity. The services apply default suppressions (see `utils/host/src/logger.rs` `setup_logger()`), but `RUST_LOG` overrides them.

```bash
# Verbose for a specific module
RUST_LOG=op_succinct_validity=debug,op_succinct_host_utils=debug

# Trace proving
RUST_LOG=op_succinct_proof_utils=trace

# Trace signer operations
RUST_LOG=op_succinct_signer_utils=debug
```

## Common Errors

### Proof-Related

| Error | Cause | Fix |
|-------|-------|-----|
| `missing trie node` | L1 archive node incomplete | Wait for full sync or use a different RPC |
| `L2 block validation failed` | L1 head too close to batch posting | Increase L1 head offset (50-150 blocks during congestion) |
| `SP1ProofMode mismatch` | Range and aggregation use different modes | Ensure consistent mode (Compressed for range, Plonk/Groth16 for aggregation) |
| `multi_block_vkey mismatch` | Range ELF updated but aggregation still uses old vkey | Rebuild both ELFs and redeploy |
| `Cluster proof polling failed 3 times` | Cluster backend unreachable | Check SP1 cluster health; `MAX_CONSECUTIVE_POLL_FAILURES = 3` in validity proposer |

### Signer-Related

| Error | Cause | Fix |
|-------|-------|-----|
| `Secret key must be 16, 24 or 32 bytes` | XLayer AES key length wrong | Check `XLAYER_SECRET_KEY` env var |
| `nonce too low` | Concurrent tx submission without SignerLock | Ensure all sends go through `SignerLock` |
| `transaction underpriced` | Gas price too low for L1 | Increase gas multiplier or wait for lower gas |

### Database-Related

| Error | Cause | Fix |
|-------|-------|-----|
| `sqlx migration failed` | Schema conflict or corrupted DB | Check `validity/migrations/` for manual reconciliation |
| `chain lock held by another instance` | Another proposer is running | Stop the other instance or use different chain IDs |

## Diagnostic Commands

```bash
# Check verification key hashes
just vkeys

# Cost estimation for a block range
just cost-estimator --start <N> --end <M>

# Preflight validation
cargo run --bin preflight --release

# Run single block proof (mock)
just run-single <l2_block_num> prove=false

# Run single block proof (real)
just run-single <l2_block_num> prove=true
```

## Proof Failure Decision Tree

1. **Witness generation failed?** → Check L1/L2 RPC connectivity and archive state
2. **zkVM execution failed?** → Check if rollup config hash matches between host and guest
3. **Proof generation timed out?** → Check cluster/network prover health; increase timeout
4. **Aggregation failed?** → Verify all range proofs use same `multi_block_vkey`; check L2 block continuity (no gaps)
5. **On-chain submission failed?** → Check nonce, gas, and contract state (L2OO or DGF)
