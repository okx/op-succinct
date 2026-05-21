# xlayer-tee-mock-proposer

Local-dev proposer mock. **Not** part of the production proposer; sits next to
`xlayer-tee-host` for E2E testing against a real OP Stack devnet while the
real op-succinct fault-proof proposer is being modified.

## What it does

1. Reads L1 + L2 + rollup-node RPC URLs from CLI (or env).
2. Uses `op-succinct` `OPSuccinctDataFetcher` + `SingleChainOPSuccinctHost` to
   - fetch the rollup config from the L2 node,
   - compute an L1-head hash that covers the requested L2 range,
   - run `host.run(args)` to produce a real `DefaultWitnessData` (preimage
     store + 4844 blobs + boot info — usually MB-scale).
3. rkyv-serializes the witness and POSTs to `xlayer-tee-host`.
4. Polls `GET /tee/task/{id}` until Finished/Failed and prints the response.

Replaces the throwaway `gen_dev_witness` (which only emits an 8-field 224-byte
`DevWitness` placeholder) when you need to exercise the real derivation path.

## Prerequisites

A running OP Stack devnet exposing:

- L1 execution RPC (anvil / reth / geth)
- **L1 beacon RPC** if your range spans blob-carrying L1 blocks (4844)
- L2 execution RPC (op-reth / op-geth)
- L2 rollup node RPC (`op-node`)

And the tee-host running on `http://127.0.0.1:18080` (default).

## Run

```bash
# From the workspace root:
cd optimism/rust/xlayer-tee-prover

cargo run -p xlayer-tee-mock-proposer -- \
    --l1-rpc        http://127.0.0.1:8545 \
    --l1-beacon-rpc http://127.0.0.1:5052 \
    --l2-rpc        http://127.0.0.1:9545 \
    --l2-node-rpc   http://127.0.0.1:7545 \
    --start-block   1000 \
    --end-block     1010 \
    --tee-host      http://127.0.0.1:18080
```

All RPC flags also accept env-var fallback (`L1_RPC`, `L1_BEACON_RPC`,
`L2_RPC`, `L2_NODE_RPC`). The block range should be small (single-digit blocks)
when iterating locally; witness generation cost grows roughly linearly.

Tracing:

```bash
RUST_LOG=info,xlayer_tee_mock_proposer=debug,op_succinct_host_utils=info \
  cargo run -p xlayer-tee-mock-proposer -- ...
```

## Why this is not in the spec

Per the SPEC, the production caller is the op-succinct fault-proof proposer
(after its TEE-path modification). This mock is a temporary local stand-in
intended to unblock host integration testing — it will be retired the moment
the real proposer can POST to `/tee/task`. It deliberately stays inside
`xlayer-tee-prover/crates/` (private), is not referenced from SPEC_TEE_HOST.md,
and is not part of any deployment artifact.
