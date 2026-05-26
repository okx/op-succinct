---
name: ci-env
description: >
  All-in-one dev/CI environment lifecycle for op-succinct fault proof system.
  Build Rust binaries, start proposer/challenger processes,
  optional Prometheus + Grafana monitoring.
  Three topologies: fp-mock (zero Docker, mock proofs), fp-tz (TradeZone fault proof),
  fp-full (full proving + monitoring).
  Reuses existing fault-proof/ docker-compose and configs — no duplicated files.
  Use when: user asks to build, start, stop, restart, check status of, or troubleshoot
  the local dev environment; mentions "start env", "fp-mock", "fp-tz", "fp-full",
  "start proposer", "start challenger", "monitoring", "grafana", "prometheus",
  "ci-env", "dev environment".
  NOT for: contract deployment (use justfile recipes), ELF building (use just build-elfs),
  running tests (use just tests / just fp-integration-tests).
metadata:
  okx:
    version: "1.0.0"
    tags: [dev-environment, infrastructure, fault-proof, monitoring]
    category: infrastructure
  argument-hint: '[action: "build", "start", "stop", "clean", "status", "logs"]'
---

# CI Environment — op-succinct

Environment lifecycle management. Scripts live under `scripts/ci-env/`,
config templates under `dev/config/`, runtime data under `dev/data/`.

If `$ARGUMENTS` specifies an action, jump directly to that section.
Otherwise, ask the user which action they want.

## Topologies & Services

### fp-mock — Mock proving (zero Docker)

Proposer + Challenger with `MOCK_MODE=true`. No real proofs generated.
Fastest startup, for unit/integration testing.

| Service | Metrics Port | Config |
|---------|-------------|--------|
| Proposer (or tz-proposer) | 9000 | `dev/config/fp-mock.env` |
| Challenger (or tz-challenger) | 9001 | `dev/config/fp-mock.env` |

```bash
bash scripts/ci-env/start.sh fp-mock
bash scripts/ci-env/start.sh fp-mock --tz   # use tz- binaries
```

### fp-tz — TradeZone fault proof

tz-proposer + tz-challenger built with `--features tz`.
Points to TradeZone L2 endpoints. Supports mock or real proving.

| Service | Metrics Port | Config |
|---------|-------------|--------|
| tz-proposer | 9000 | `dev/config/fp-tz.env` |
| tz-challenger | 9001 | `dev/config/fp-tz.env` |

```bash
bash scripts/ci-env/start.sh fp-tz
bash scripts/ci-env/start.sh fp-tz --mock   # mock proofs
bash scripts/ci-env/start.sh fp-tz -m       # + monitoring
```

### fp-full — Full fault proof + monitoring

Proposer + Challenger with real proving via SP1 network.
Docker: Prometheus + Grafana (reuses `fault-proof/docker-compose.yml`).

| Service | Port | Config |
|---------|------|--------|
| Proposer (or tz-proposer) | metrics 9000 | `dev/config/fp-full.env` |
| Challenger (or tz-challenger) | metrics 9001 | `dev/config/fp-full.env` |
| Prometheus | 9090 | `fault-proof/prometheus/prometheus.yml` |
| Grafana | 3000 | `fault-proof/grafana/` |

```bash
bash scripts/ci-env/start.sh fp-full
bash scripts/ci-env/start.sh fp-full --tz   # use tz- binaries
```

## CLI Options

```
bash scripts/ci-env/start.sh <topology> [options]

Topologies:
  fp-mock        Mock proving, zero Docker (default)
  fp-tz          TradeZone fault proof (--features tz)
  fp-full        Full proving + Prometheus/Grafana

Options:
  --tz           Use tz-proposer/tz-challenger instead of standard
  --mock         Force MOCK_MODE=true (default in fp-mock)
  -m, --monitoring  Start Prometheus + Grafana
  --env <file>   Custom env file (default: dev/config/<topology>.env)
```

## Action 1: Build (`build`)

```bash
# Standard fault proof
cargo build --bin proposer --bin challenger --release

# TradeZone fault proof
cargo build --bin tz-proposer --bin tz-challenger --release --features tz
```

Note: Build uses `TMPDIR=$(pwd)/target/tmp` to fix SP1 nested build issue.

## Action 2: Start (`start`)

```bash
bash scripts/ci-env/start.sh fp-mock          # mock, zero Docker
bash scripts/ci-env/start.sh fp-tz            # TradeZone
bash scripts/ci-env/start.sh fp-tz --mock     # TradeZone mock
bash scripts/ci-env/start.sh fp-tz -m         # TradeZone + monitoring
bash scripts/ci-env/start.sh fp-full          # full + monitoring
bash scripts/ci-env/start.sh fp-full --tz     # full + tz binaries
bash scripts/ci-env/start.sh fp-mock --env /path/to/custom.env
```

**Startup DAG:**
1. (fp-full only) Docker: Prometheus + Grafana
2. Build: `cargo build --bin <proposer> --bin <challenger> --release`
3. Proposer: start + wait alive
4. Challenger: start + wait alive
5. Write `.test-env`

**Test env output:** All topologies write `dev/data/.test-env` with
`TOPOLOGY`, `L1_RPC`, `L2_RPC`, `FACTORY_ADDRESS`, etc.
Source it before running tests: `source dev/data/.test-env`.

## Action 3: Stop (`stop`)

```bash
bash scripts/ci-env/stop.sh              # stop all services, keep data
bash scripts/ci-env/stop.sh --clean      # stop + delete all runtime data
bash scripts/ci-env/stop.sh -c           # short form
```

Stop order: Challenger -> Proposer -> Docker monitoring -> Orphan cleanup.

What gets cleaned with `--clean`:
- `dev/data/.*.pid`, `dev/data/*.log` — PID files and logs
- `dev/data/.test-env`, `dev/data/.topology` — runtime state
- Docker volumes via `docker compose down -v`

## Action 4: Status (`status`)

```bash
bash scripts/ci-env/status.sh
```

Shows: process PIDs, metrics ports, Docker container states,
loaded environment variables, log file paths.

## Action 5: Logs (`logs`)

| Service | Path |
|---------|------|
| Proposer | `dev/data/proposer.log` |
| Challenger | `dev/data/challenger.log` |
| Prometheus | `docker logs prometheus` |
| Grafana | `docker logs grafana` |

## Environment Variables Reference

### Proposer (required)

| Variable | Default | Description |
|----------|---------|-------------|
| `L1_RPC` | — | L1 Ethereum RPC endpoint |
| `L2_RPC` | — | L2 RPC endpoint (or comma-separated for tz) |
| `FACTORY_ADDRESS` | — | DisputeGameFactory address |
| `ANCHOR_STATE_REGISTRY_ADDRESS` | — | AnchorStateRegistry address |
| `GAME_TYPE` | — (tz: 1961) | Game type identifier |

### Proposer (optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `MOCK_MODE` | false | Skip real proving |
| `FETCH_INTERVAL` | 30 | Check interval (seconds) |
| `PROPOSAL_INTERVAL_IN_BLOCKS` | 1800 | Blocks between proposals |
| `PROPOSER_METRICS_PORT` | 9000 | Metrics endpoint port |
| `SAFE_DB_FALLBACK` | false | Timestamp-based L1 head estimation |
| `MAX_CONCURRENT_DEFENSE_TASKS` | 8 | Concurrent defense tasks |
| `NETWORK_PRIVATE_KEY` | — | Wallet private key |
| `SP1_PROVER` | — | SP1 prover mode (network/local) |
| `SP1_PRIVATE_KEY` | — | SP1 network key |

### Challenger (optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `CHALLENGER_METRICS_PORT` | 9001 | Metrics endpoint port |
| `MALICIOUS_CHALLENGE_PERCENTAGE` | 0.0 | Test: % of valid games to challenge |

## Dependencies

Configs reused from the project (not duplicated in skill):
- `fault-proof/docker-compose.yml` — Prometheus, Grafana
- `fault-proof/prometheus/` — Prometheus config
- `fault-proof/grafana/` — Grafana provisioning + dashboards

## Troubleshooting

See `references/troubleshooting.md` for: build failures, SP1 issues,
process crash on startup, metrics not available, Docker issues.
