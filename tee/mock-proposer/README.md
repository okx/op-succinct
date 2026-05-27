# xlayer-tee-mock-proposer

Local-dev proposer mock. **Not** part of the production proposer; sits next
to `xlayer-tee-host` for E2E testing against a real OP Stack devnet while
the real op-succinct fault-proof proposer is being modified.

## What it does

1. Reads L1 / L2 / rollup-node RPC URLs from CLI (or env).
2. Splits `[--start-block, --end-block]` into contiguous chunks of size
   `--chunk-size`. Each chunk becomes its own TEE task.
3. For each chunk:
   - Uses op-succinct's `OPSuccinctDataFetcher` + `SingleChainOPSuccinctHost`
     to fetch the rollup config, compute an L1 head, and produce a real
     `DefaultWitnessData` (preimage store + 4844 blobs + boot info,
     usually MB-scale).
   - rkyv-serializes the witness, POSTs it to `xlayer-tee-host`, then polls
     `GET /tee/task/{id}` until `Finished`/`Failed`.
4. Optionally drives the SP1 aggregation guest on the resulting
   `Vec<(BootInfo, signature)>` — `execute` for sanity / cycle counts, or
   `prove` for a real compressed SNARK.

The aggregation guest pins every leaf to a single attestation-derived
signer, so all chunks **must** be sent to the same enclave session (i.e.
the same `xlayer-tee-host` instance, not restarted mid-run).

## Prerequisites

A running OP Stack devnet exposing:

- L1 execution RPC (anvil / reth / geth)
- L1 beacon RPC (required only when generating witnesses for ranges that
  span blob-carrying L1 blocks)
- L2 execution RPC (op-reth / op-geth)
- L2 rollup node RPC (`op-node`)

And a `xlayer-tee-host` listening on `http://127.0.0.1:18080` (default).

## Modes

### 1. TEE-only (chunking + per-chunk proofs, no aggregation)

```bash
cargo run -p xlayer-tee-mock-proposer --release -- \
  --l1-rpc        http://127.0.0.1:8545 \
  --l1-beacon-rpc http://127.0.0.1:3500 \
  --l2-rpc        http://127.0.0.1:9545 \
  --l2-node-rpc   http://127.0.0.1:7545 \
  --start-block   1000 \
  --end-block     1010 \
  --chunk-size    5 \
  --tee-host      http://127.0.0.1:18080
```

Default `--agg-mode skip` prints each chunk's `proofBytes` (ABI-encoded
`(RangeJournal, signature)`) and stops.

### 2. TEE + aggregation execute (no SNARK)

```bash
cargo run -p xlayer-tee-mock-proposer --release -- \
  ... (RPCs and range as above) ...
  --agg-mode      execute \
  --prover-address 0xYourAddress
```

Useful for measuring guest cycles and verifying that
`AggregationOutputs` ABI-decodes cleanly before paying for a real prove.

### 3. TEE + aggregation prove (CPU prover)

```bash
cargo run -p xlayer-tee-mock-proposer --release -- \
  ... (RPCs and range as above) ...
  --agg-mode      prove \
  --prover-address 0xYourAddress
```

Slow on a laptop; suitable for small ranges to verify the end-to-end path.

### 4. TEE → cache → replay on SP1 cluster

Step 1 — run the TEE flow once, dump every chunk's proof + the enclave's
attestation doc to JSON:

```bash
cargo run -p xlayer-tee-mock-proposer --release -- \
  ... (RPCs and range) ... \
  --save-proofs-file /tmp/tee-proofs.json \
  --agg-mode skip
```

Step 2 — replay aggregation against a self-hosted SP1 cluster (skipping the
entire TEE flow: no chunking, no witness gen, no POST, no polling):

```bash
SP1_PROVER=cluster \
CLI_CLUSTER_RPC=http://127.0.0.1:50051 \
CLI_REDIS_NODES="redis://127.0.0.1:6379/0" \
RUST_LOG=info \
cargo run -p xlayer-tee-mock-proposer --release -- \
  --l1-rpc       http://127.0.0.1:8545 \
  --l2-rpc       http://127.0.0.1:9545 \
  --l2-node-rpc  http://127.0.0.1:7545 \
  --proofs-file  /tmp/tee-proofs.json \
  --agg-mode     prove \
  --cluster-timeout 14400 \
  --prover-address 0xYourAddress
```

Notes:

- `--l1-rpc/--l2-rpc/--l2-node-rpc` are still required in replay — the
  fetcher fetches the rollup config and L1 header preimages used by the
  aggregation guest. `--l1-beacon-rpc` is **not** needed (no witness gen).
- `run_prove` auto-detects `SP1_PROVER=cluster` and dispatches to
  `cluster_agg_proof()`. Without that env var it falls back to the CPU
  prover.
- For ranges that exceed Redis's 4-hour artifact TTL, swap to S3:
  `CLI_S3_BUCKET=... CLI_S3_REGION=...` instead of `CLI_REDIS_NODES`.
  Set exactly one — both or neither will panic.
- See [`book/advanced/self-hosted-cluster.md`](../../book/advanced/self-hosted-cluster.md)
  for cluster setup.

## CLI flags

| Flag | Default | Meaning |
|---|---|---|
| `--l1-rpc` / `--l2-rpc` / `--l2-node-rpc` | env | RPC URLs (env: `L1_RPC` / `L2_RPC` / `L2_NODE_RPC`) |
| `--l1-beacon-rpc` | env `L1_BEACON_RPC` | L1 beacon RPC (witness gen only) |
| `--start-block` / `--end-block` | — | required unless `--proofs-file` is set |
| `--chunk-size` | `500` | half-open contiguous chunk size |
| `--max-concurrent-witness` | `4` | parallel witness-gen workers |
| `--tee-host` | `http://127.0.0.1:18080` | host base URL |
| `--poll-secs` | `2` | `GET /tee/task/{id}` polling interval |
| `--poll-timeout-secs` | `600` | per-chunk poll deadline |
| `--safe-db-fallback` | `true` | fall back to timestamp-based L1 head when SafeDB is unavailable |
| `--l1-head` | (auto) | override the derivation L1 head (devnet escape hatch) |
| `--agg-mode` | `skip` | `skip` / `execute` / `prove` |
| `--prover-address` | `0x0…0` | committed into `AggregationOutputs.proverAddress` |
| `--proofs-file` | — | replay aggregation from a previously-saved cache; skips the TEE flow |
| `--save-proofs-file` | — | after a successful TEE run, dump every chunk's proof + attestation to this path |
| `--cluster-timeout` | `14400` | seconds; only consulted when `SP1_PROVER=cluster` |

## Cache format (`--save-proofs-file` / `--proofs-file`)

JSON:

```json
{
  "chunks": [
    { "start": 1000, "end": 1005, "proof_bytes_hex": "0x..." },
    { "start": 1005, "end": 1010, "proof_bytes_hex": "0x..." }
  ],
  "attestation_b64": "..."
}
```

- `proof_bytes_hex` is the same ABI-encoded `(RangeJournal, signature)`
  blob that `GET /tee/task/{id}` returns under `data.proofBytes`.
- `attestation_b64` is the COSE_Sign1 NSM document encoded with base64
  standard alphabet — same encoding as `/tee/info`'s `data.attestationDoc`.

## Tracing

```bash
RUST_LOG=info,xlayer_tee_mock_proposer=debug,op_succinct_host_utils=info \
  cargo run -p xlayer-tee-mock-proposer ...
```

## Out of scope

This binary is for local dev only. It does not:

- speak the production proposer contract / dispute-game state
- persist cluster handles or resume mid-run
- talk to the Succinct prover network (use `SP1_PROVER=cluster` against a
  self-hosted cluster instead, or rely on the CPU fallback)

It will be retired once the production op-succinct proposer can drive
`/tee/task` directly.
