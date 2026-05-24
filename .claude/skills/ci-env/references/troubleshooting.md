# Troubleshooting

## Build Failures

### SP1 nested build: read-only registry dir
The build uses `TMPDIR=$(pwd)/target/tmp` to work around SP1 attempting
to write to the read-only cargo registry during nested builds. If you
see permission errors during build, ensure `target/tmp` is writable.

### Feature `tz` not found
The `tz` feature is defined in `fault-proof/Cargo.toml`. Ensure you're
building from the workspace root, not from inside `fault-proof/`.

### Nightly toolchain missing
The project requires `nightly-2025-09-15`. Run:
```bash
rustup toolchain install nightly-2025-09-15
```

## Process Crashes on Startup

### Proposer/Challenger dies immediately
Check the log for the actual error:
```bash
tail -50 dev/data/proposer.log
tail -50 dev/data/challenger.log
```

Common causes:
- Missing or invalid env vars (L1_RPC, L2_RPC, FACTORY_ADDRESS)
- Contract not deployed at the specified address
- L1/L2 RPC unreachable
- NETWORK_PRIVATE_KEY not set (required for real transactions)

### "GAME_TYPE not set" panic
`GAME_TYPE` is required for both proposer and challenger.
Set it in your env file or export it:
```bash
export GAME_TYPE=0           # standard OP
export GAME_TYPE=1961        # TradeZone
```

## Metrics Not Available

Proposer/challenger expose Prometheus metrics on their configured ports.
Verify:
```bash
curl http://127.0.0.1:9000/metrics   # proposer
curl http://127.0.0.1:9001/metrics   # challenger
```

If no response, the process may have crashed — check logs.

## Docker Issues

### Prometheus/Grafana won't start
Ensure Docker is running and ports are free:
```bash
docker ps
lsof -i :9090   # prometheus
lsof -i :3000   # grafana
```

### "file not found: .env.proposer"
The `fault-proof/docker-compose.yml` references `.env.proposer` and
`.env.challenger`. The start script creates empty files if missing,
but if running docker-compose manually, create them first:
```bash
touch fault-proof/.env.proposer fault-proof/.env.challenger
```

## Port Conflicts

Default ports:
- Proposer metrics: 9000
- Challenger metrics: 9001
- Prometheus: 9090
- Grafana: 3000

Override via env vars:
```bash
export PROPOSER_METRICS_PORT=9100
export CHALLENGER_METRICS_PORT=9101
export FP_PROMETHEUS_PORT=19090
export FP_GRAFANA_PORT=13000
```

## Stale PID Files

If `status.sh` shows a service as running but it's actually dead:
```bash
rm dev/data/.proposer.pid dev/data/.challenger.pid
```
Or use `stop.sh --clean` to remove all state.
