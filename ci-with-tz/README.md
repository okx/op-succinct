# ci-with-tz

End-to-end CI script for the TradeZone fault-proof flow. It spins up a local L1 (Anvil), deploys the dispute contracts, starts the TradeZone L2, runs the `tz-proposer`, raises a challenge on the first game that appears, and asserts that the game resolves successfully — all in a single shell session.

## What it does

1. Start Anvil as the L1 node (block time = 1 s)
2. Deploy `DisputeGameFactory` + `AnchorStateRegistry` via `DeployOPSuccintLiteTzAll.s.sol`
3. Render `.env.tz-proposer` from the template with the deployed addresses
4. Start the TradeZone L2 via `$TZ_PROJ_PATH/dev/scripts/ci-env/start.sh ci-single --zkvm`
5. Build and start the `tz-proposer` binary (mock mode by default)
6. Wait up to 5 minutes for the first dispute game to appear on-chain
7. Call `challenge()` on that game and verify the tx succeeds
8. Poll up to 5 minutes for the game to reach `Resolved` status
9. Exit 0 on success, non-zero on any timeout or unexpected state

All background processes are cleaned up automatically on exit via a `trap` — including Anvil, the proposer, and the L2 stack.

## Prerequisites

| Tool | Purpose |
|------|---------|
| `anvil` | Local L1 node (Foundry) |
| `forge` | Contract deployment (Foundry) |
| `cast` | Chain queries and tx sending (Foundry) |
| `cargo` | Build `tz-proposer` |
| `jq` | Parse transaction receipts |

Install Foundry: https://getfoundry.sh

The TradeZone project must be cloned separately and its own CI-env prerequisites satisfied (Docker or native, depending on the `ci-single` topology).

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TZ_PROJ_PATH` | yes | Absolute path to the TradeZone project root |

All other configuration comes from `example.env.tz-proposer`, which is rendered automatically into `.env.tz-proposer` by `start.sh`. Edit the template if you need to change RPC endpoints, timeouts, or proof strategy.

## How to run

```bash
export TZ_PROJ_PATH=/path/to/tradezone
./start.sh
```

The script is blocking — it runs the full scenario and exits when done (or on failure). Logs are written to:

- `anvil.log` — Anvil stdout/stderr
- `forge-deploy.log` — contract deployment output
- `tz-proposer.log` — proposer stdout/stderr

## How to stop

If you need to tear down a run that is still in progress (e.g. you interrupted `start.sh` or it is stuck), run:

```bash
export TZ_PROJ_PATH=/path/to/tradezone
./stop.sh
```

This kills `anvil`, `tz-proposer`, and runs the TradeZone L2 clean-stop script. `start.sh` also calls this automatically on exit via `trap`, so manual cleanup is only needed after a forced interrupt.
