# TradeZone ZK Fault Proof Setup Manual

This manual covers the end-to-end setup for the TradeZone (`tz`) fault-proof path in this
repository: TradeZone REST services, contract deployment, `tz-proposer`, `tz-challenger`,
mock proofs, and optional real proving through SP1 Network or SP1 cluster.

The main mock-proof objective is:

1. The proposer creates a TradeZone dispute game.
2. The challenger challenges that game.
3. The proposer fetches real TradeZone witness data.
4. The proposer locally executes the range and aggregation guests.
5. The proposer submits a mock proof accepted by `SP1MockVerifier`.

## Service Inventory

| Service | Required for mock proof | Notes |
| --- | --- | --- |
| L1 execution RPC | Yes | Hosts `DisputeGameFactory`, `AnchorStateRegistry`, and dispute games. |
| TradeZone REST node | Yes | Must expose `/chain/confirmed_block_info`, `/chain/dex_state_snapshot`, and `/chain/blocks`. |
| Contracts | Yes | Deploy with `contracts/deploy-tz.sh`. |
| `tz-proposer` | Yes | Built with `--features tz`; creates games and proves challenged games. |
| `tz-challenger` | Yes for automatic challenge | Use `MALICIOUS_CHALLENGE_PERCENTAGE=100` for forced proof tests. |
| SP1 cluster | No for mock proof | Required only for real self-hosted proving. |
| SP1 Network | No for mock proof | Required only for real network proving. |
| Prometheus/Grafana | Optional | Useful for long-running tests. |

## Prerequisites

Install or verify:

```bash
cargo --version
forge --version
cast --version
jq --version
curl --version
~/.sp1/bin/cargo-prove --version
```

You also need:

- A reachable L1 RPC.
- Existing `DisputeGameFactory` and `AnchorStateRegistry` addresses on L1.
- A `Transactor` address authorized to update the factory implementation and init bond.
- A funded deployer/proposer L1 signer.
- A funded challenger L1 signer.
- TradeZone node data with at least one confirmed checkpoint.

The deployer address must be allowed as a proposer in `contracts/config/tz/opsuccinctfdgconfig.json`
or `permissionlessMode` must be `true`. The challenger address must be allowed as a challenger.

## Private TZ Dependency Access

The TZ range guest depends on private TradeZone crates from:

```text
ssh://git@github.com/okx/x2.git
```

The pinned crates are declared in the workspace `Cargo.toml`:

```text
tz-block-processor
tz-dex
tz-primitives
```

On a fresh remote machine, configure GitHub SSH access before building TZ ELFs:

```bash
ssh -T git@github.com
git ls-remote ssh://git@github.com/okx/x2.git 173544d7e8985b738c278cc4b26456569bb13e66
```

If `git ls-remote` fails, fix GitHub access first:

- Add the remote machine's public SSH key to a GitHub user or deploy key with access to `okx/x2`.
- Or connect to the remote machine with SSH agent forwarding and verify `ssh-add -l`.
- Confirm the pinned revision exists in the visible repository. If the revision is not visible even
  after authentication succeeds, update the three `x2` dependency pins to a valid TradeZone commit
  that matches the running TradeZone node.

Prefer Cargo's Git CLI fetcher for private SSH dependencies:

```bash
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[net]
git-fetch-with-cli = true
EOF
```

For one-off builds, this is equivalent:

```bash
CARGO_NET_GIT_FETCH_WITH_CLI=true just build-tz-elfs
```

## Build Artifacts

From the repository root:

```bash
just build-tz-elfs
just tz-vkeys
cargo build --release --features tz --bin tz-proposer --bin tz-challenger
```

`just tz-vkeys` prints the current TZ range and aggregation verification keys. If the guest code
or TradeZone serialization dependency changes, rebuild the TZ ELFs, regenerate vkeys, update
`contracts/config/tz/opsuccinctfdgconfig.json`, and redeploy contracts.

## One-Shot Local Anvil Mock Devnet

For a fresh local Anvil L1, use the setup script instead of manually editing config and copying
deployment addresses:

```bash
TZ_RPC=http://127.0.0.1:10000 L1_PORT=8547 scripts/setup-tz-mock-devnet.sh
```

The script:

1. Starts Anvil on `0.0.0.0:$L1_PORT`, or reuses `L1_RPC` if it is already reachable.
2. Fetches the latest TradeZone confirmed checkpoint and computes `keccak256(blockHash || appHash)`.
3. Updates `contracts/config/tz/opsuccinctfdgconfig.json` for mock-proof FDG deployment.
4. Installs missing contract submodules and patches the known `sp1-contracts` Solidity pragma issue.
5. Deploys `DeployOPSuccinctFDG` with `SP1MockVerifier`.
6. Writes repo-root `.env.tz-proposer` and `.env.tz-challenger`.
7. Writes `dev/data/tz-devnet.env` with deployed addresses for shell reuse.

By default it uses the standard Anvil keys:

```text
deployer/proposer: account 0
challenger:        account 1
game type:         1961
```

If the TZ vkeys changed, pass the values explicitly so the contract config is updated before
deployment:

```bash
TZ_RANGE_VKEY=0x... \
TZ_AGG_VKEY=0x... \
TZ_RPC=http://127.0.0.1:10000 \
L1_PORT=8547 \
scripts/setup-tz-mock-devnet.sh
```

To build and start the services as part of setup:

```bash
BUILD_BINARIES=1 START_SERVICES=1 TZ_RPC=http://127.0.0.1:10000 L1_PORT=8547 scripts/setup-tz-mock-devnet.sh
```

For manual startup after the script finishes:

```bash
RUST_LOG=info ./target/release/tz-proposer --env-file .env.tz-proposer
RUST_LOG=info ./target/release/tz-challenger --env-file .env.tz-challenger
```

For a forced proof-path test if automatic challenging misses the game:

```bash
set -a; source dev/data/tz-devnet.env; set +a
cd contracts
ENV_FILE=/dev/null RPC_URL="$L1_RPC" FACTORY_ADDRESS="$FACTORY_ADDRESS" PRIVATE_KEY="$CHALLENGER_PK" ./challenge-last-game.sh
```

This Anvil script deploys a fresh mock `DisputeGameFactory`, `AnchorStateRegistry`,
`MockSystemConfig`, and `MockOptimismPortal2`. For an existing OP Stack L1 deployment where you
must use an existing factory, registry, and owner/transactor, use `contracts/deploy-tz.sh` instead.

## TradeZone REST Checks

Set the TradeZone endpoint:

```bash
export TZ_RPC=http://127.0.0.1:10000
```

Check confirmed checkpoint data:

```bash
curl -fsS "$TZ_RPC/chain/confirmed_block_info" | jq
```

Expected shape:

```json
{
  "code": 0,
  "data": {
    "height": 12345,
    "blockHash": "0x...",
    "appHash": "0x..."
  }
}
```

The prover later needs:

- `GET /chain/dex_state_snapshot?height=<start>`
- `GET /chain/dex_state_snapshot/download?height=<start>`
- `GET /chain/blocks?start=<start+1>&end=<end>`

For a small smoke check:

```bash
HEIGHT=$(curl -fsS "$TZ_RPC/chain/confirmed_block_info" | jq -r '.data.height')
curl -fsS "$TZ_RPC/chain/dex_state_snapshot?height=$HEIGHT" | jq
```

If `state_available=false`, the TradeZone node should return a replay task and eventually make the
snapshot downloadable.

## Contract Configuration

Edit:

```text
contracts/config/tz/opsuccinctfdgconfig.json
```

For mock-proof testing:

```json
{
  "gameType": 1961,
  "permissionlessMode": false,
  "useSp1MockVerifier": true,
  "rollupConfigHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "proposerAddresses": ["<proposer-address>"],
  "challengerAddresses": ["<challenger-address>"]
}
```

For real proofs, set:

```json
"useSp1MockVerifier": false
```

and make sure `aggregationVkey`, `rangeVkeyCommitment`, and the verifier route match the TZ ELFs
and chosen proof mode.

## Bootstrap Root

The TZ root claim is:

```text
keccak256(blockHash || appHash)
```

Fetch the checkpoint and compute the bootstrap root:

```bash
INFO=$(curl -fsS "$TZ_RPC/chain/confirmed_block_info")
BOOTSTRAP_L2_BLOCK_NUMBER=$(jq -r '.data.height' <<<"$INFO")
BLOCK_HASH=$(jq -r '.data.blockHash' <<<"$INFO")
APP_HASH=$(jq -r '.data.appHash' <<<"$INFO")
BOOTSTRAP_ROOT_CLAIM=$(cast keccak "0x${BLOCK_HASH#0x}${APP_HASH#0x}")

echo "$BOOTSTRAP_L2_BLOCK_NUMBER"
echo "$BOOTSTRAP_ROOT_CLAIM"
```

Use a checkpoint height strictly greater than the current anchor height in `AnchorStateRegistry`.

## Deploy TZ Contracts

Create `contracts/.env.tz`:

```env
PRIVATE_KEY=<deployer_or_proposer_private_key>
FACTORY_ADDRESS=<dispute_game_factory>
ANCHOR_STATE_REGISTRY=<anchor_state_registry>
TRANSACTOR=<factory_owner_transactor>
BOOTSTRAP_ROOT_CLAIM=<computed_root_claim>
BOOTSTRAP_L2_BLOCK_NUMBER=<computed_checkpoint_height>
RPC_URL=<l1_rpc_url>
GAME_TYPE=1961
```

Note the deployment script uses `ANCHOR_STATE_REGISTRY`, while services use
`ANCHOR_STATE_REGISTRY_ADDRESS`.

Deploy:

```bash
cd contracts
./deploy-tz.sh
```

The script:

1. Deploys `AccessManager`.
2. Deploys either `SP1MockVerifier` or the real SP1 verifier gateway.
3. Deploys a bootstrap game implementation.
4. Registers game type `1961`.
5. Creates the bootstrap game.
6. Deploys and registers the production game implementation.

After the bootstrap game is eligible to close:

```bash
cd contracts
./close-games.sh
```

Check games:

```bash
cd contracts
GAME_TYPE=1961 ./list-games.sh
```

## Proving Mode Matrix

| Mode | Contract verifier | Proposer env | SP1 cluster needed |
| --- | --- | --- | --- |
| Mock proof | `SP1MockVerifier` | `MOCK_MODE=true`, no `SP1_PROVER=cluster` | No |
| SP1 Network | Real verifier gateway | `MOCK_MODE=false`, `NETWORK_PRIVATE_KEY=...` | No |
| SP1 cluster | Real verifier gateway | `MOCK_MODE=false`, `SP1_PROVER=cluster` | Yes |

Mock mode still fetches witness and locally executes the TZ guests. It skips real proof generation
and submits empty mock proof bytes accepted by `SP1MockVerifier`.

## Proposer Environment

Create `.env.tz-proposer`:

```env
L1_RPC=<l1_rpc_url>
L2_RPC=<tz_rest_url_or_comma_separated_urls>
L2_NODE_RPC=<first_tz_rest_url>

FACTORY_ADDRESS=<dispute_game_factory>
ANCHOR_STATE_REGISTRY_ADDRESS=<anchor_state_registry>
GAME_TYPE=1961

PRIVATE_KEY=<proposer_private_key>

MOCK_MODE=true
FETCH_INTERVAL=5
PROPOSAL_INTERVAL_IN_BLOCKS=100
SAFE_DB_FALLBACK=true
MAX_CONCURRENT_DEFENSE_TASKS=8

PROPOSER_METRICS_PORT=9000
TX_CONFIRMATION_TIMEOUT=120

# Optional diagnostics
# TZ_LOCAL_EXECUTE=1
# TZ_BLOCKS_PER_FETCH=1000
# TZ_SNAPSHOT_POLL_INTERVAL_SECS=5
```

`L2_NODE_RPC` is required because the shared host fetcher validates it at startup. The TZ path does
not use OP Stack node RPC, so set it to a valid TradeZone URL.

For SP1 Network real proving, change:

```env
MOCK_MODE=false
NETWORK_PRIVATE_KEY=<sp1_network_private_key>
RANGE_PROOF_STRATEGY=reserved
AGG_PROOF_STRATEGY=reserved
AGG_PROOF_MODE=plonk
TIMEOUT=14400
```

For SP1 cluster real proving, change:

```env
MOCK_MODE=false
SP1_PROVER=cluster
CLI_CLUSTER_RPC=http://<cluster_lb_endpoint>:50051
CLI_S3_BUCKET=<bucket>
CLI_S3_REGION=<region>
TIMEOUT=21600
```

Use `CLI_REDIS_NODES=redis://...` instead of S3 only for small tests. Redis artifacts can expire
while large TZ proofs are still running.

## Challenger Environment

Create `.env.tz-challenger`:

```env
L1_RPC=<l1_rpc_url>
L2_RPC=<tz_rest_url_or_comma_separated_urls>
L2_NODE_RPC=<first_tz_rest_url>

FACTORY_ADDRESS=<dispute_game_factory>
ANCHOR_STATE_REGISTRY_ADDRESS=<anchor_state_registry>
GAME_TYPE=1961

PRIVATE_KEY=<challenger_private_key>

FETCH_INTERVAL=5
MALICIOUS_CHALLENGE_PERCENTAGE=100
CHALLENGER_METRICS_PORT=9001
TX_CONFIRMATION_TIMEOUT=120
```

`MALICIOUS_CHALLENGE_PERCENTAGE=100` is only for testing. It forces the challenger to challenge
valid proposer-created games, which drives the proposer defense proof path.

For production-like honest challenger behavior:

```env
MALICIOUS_CHALLENGE_PERCENTAGE=0
```

## Start Services Directly

Terminal 1:

```bash
RUST_LOG=info ./target/release/tz-proposer --env-file .env.tz-proposer
```

Terminal 2:

```bash
RUST_LOG=info ./target/release/tz-challenger --env-file .env.tz-challenger
```

Expected mock-proof sequence:

1. `tz-proposer` syncs the anchor and cached games.
2. `tz-proposer` polls `/chain/confirmed_block_info`.
3. Once `confirmed_height - canonical_head >= PROPOSAL_INTERVAL_IN_BLOCKS`, it creates a game.
4. `tz-challenger` refreshes the checkpoint cache and loads the game.
5. `tz-challenger` calls `challenge()`.
6. `tz-proposer` detects `ProposalStatus::Challenged`.
7. `tz-proposer` fetches snapshot and block witness.
8. `tz-proposer` logs `tz: generating range proof` and `tz: generating aggregation proof`.
9. `tz-proposer` submits `prove()`.
10. The game becomes proven and can resolve as `DEFENDER_WINS`.

## Start Services With Helper Script

You can also use the helper script:

```bash
bash scripts/ci-env/start.sh fp-tz --mock --env /absolute/path/to/fp-tz.env
```

For monitoring:

```bash
bash scripts/ci-env/start.sh fp-tz --mock --monitoring --env /absolute/path/to/fp-tz.env
```

Important: the helper exports the env file into the process environment, but it does not pass
`--env-file` to the binaries. The current `tz-proposer` and `tz-challenger` binaries still require
their default env files to exist. Before using the helper, create repo-root files:

```bash
cp /absolute/path/to/proposer.env .env.tz-proposer
cp /absolute/path/to/challenger.env .env.tz-challenger
```

Use direct startup if you do not want repo-root env files or if proposer and challenger must use
different private keys.

Logs and pid files are written under:

```text
dev/data/
```

Check status:

```bash
bash scripts/ci-env/status.sh
```

Stop:

```bash
bash scripts/ci-env/stop.sh
```

The helper's `--env` option is best for common topology settings. The binary-specific default env
files are still the source of truth for per-service values.

## Manual Challenge Alternative

If you want to run the proposer but trigger the challenge manually:

```bash
cd contracts
PRIVATE_KEY=<challenger_private_key> FACTORY_ADDRESS=<factory> RPC_URL=<l1_rpc> ./challenge-last-game.sh
```

Then watch the proposer logs for proof generation and `prove()` submission.

## Verification Commands

List games:

```bash
cd contracts
L1_RPC=<l1_rpc_url> FACTORY_ADDRESS=<factory> GAME_TYPE=1961 ./list-games.sh
```

Inspect a specific game:

```bash
cd contracts
L1_RPC=<l1_rpc_url> ./show-game.sh <game_proxy_address>
```

Useful expected states:

| Stage | GameStatus | ProposalStatus |
| --- | --- | --- |
| Created | `IN_PROGRESS` | `Unchallenged` |
| Challenged | `IN_PROGRESS` | `Challenged` |
| Proof submitted | `IN_PROGRESS` | `ChallengedAndValidProofProvided` |
| Resolved | `DEFENDER_WINS` | `Resolved` |

Proposer logs should include:

```text
tz: fetching witness (snapshot + blocks) from tz chain
tz: generating range proof
tz: generating aggregation proof
tz: proof submitted
Game proven successfully
```

Challenger logs should include:

```text
Malicious challenging enabled
Game challenged successfully
```

## Resolve And Close Games

The proposer normally attempts eligible resolution and bond claiming. You can also run:

```bash
cd contracts
./close-games.sh
```

`close-games.sh` resolves games whose `gameOver()` is true and closes finalized games. Finalization
depends on the `AnchorStateRegistry` finality delay. On long-delay environments, closing and credit
claiming may require waiting even after proof submission.

## Troubleshooting

### `L2_NODE_RPC must be set`

Set:

```env
L2_NODE_RPC=<first_tz_rest_url>
```

The TZ path validates this variable even though it does not use OP Stack node RPC.

### No game is created

Check:

- `AnchorStateRegistry.respectedGameType()` equals `GAME_TYPE`.
- `/chain/confirmed_block_info` returns non-null data.
- `confirmed_height - canonical_head >= PROPOSAL_INTERVAL_IN_BLOCKS`.
- The proposer address is allowed in `AccessManager`.
- The proposer signer has enough L1 funds for gas and init bond.

Use a smaller `PROPOSAL_INTERVAL_IN_BLOCKS` for smoke tests.

### Challenger does not challenge

Check:

- `MALICIOUS_CHALLENGE_PERCENTAGE=100` for forced testing.
- The challenger address is allowed in `AccessManager`.
- The challenger signer has enough L1 funds for gas and challenger bond.
- The challenger can compute the exact TZ root claim for the game height. Cache misses are skipped.

### Proposer skips proving

Check:

- The game is cached by the proposer.
- The game identity matches the on-chain TZ game implementation.
- The proof deadline has not passed.
- `MOCK_MODE=true` is not combined with `SP1_PROVER=cluster`.

### Snapshot replay is slow or stuck

Watch proposer logs for replay progress. Tune:

```env
TZ_SNAPSHOT_POLL_INTERVAL_SECS=5
TZ_BLOCKS_PER_FETCH=1000
```

If the replay task fails, inspect the TradeZone node logs. The prover depends on exact snapshot and
block serialization compatibility between TradeZone and this repo's TZ ELFs.

### Contract `prove()` reverts in mock mode

Check:

- Contracts were deployed with `"useSp1MockVerifier": true`.
- Proposer env has `MOCK_MODE=true`.
- `SP1_PROVER` is not set to `cluster`.

### Contract `prove()` reverts in real proof mode

Check:

- Contracts were deployed with the real SP1 verifier gateway.
- `AGG_PROOF_MODE` matches the verifier route.
- `aggregationVkey` and `rangeVkeyCommitment` match `just tz-vkeys`.
- TZ ELFs were rebuilt after any guest or TradeZone serialization dependency change.

## Minimal Mock-Proof Checklist

```bash
# 1. Build
just build-tz-elfs
just tz-vkeys
cargo build --release --features tz --bin tz-proposer --bin tz-challenger

# 2. Deploy with contracts/config/tz/opsuccinctfdgconfig.json useSp1MockVerifier=true
cd contracts
./deploy-tz.sh

# Run after the bootstrap game is eligible to resolve/finalize. Repeat if it is skipped.
./close-games.sh
cd ..

# 3. Start proposer and challenger in separate terminals
# Terminal 1
RUST_LOG=info ./target/release/tz-proposer --env-file .env.tz-proposer

# Terminal 2
RUST_LOG=info ./target/release/tz-challenger --env-file .env.tz-challenger

# 4. Verify
cd contracts
GAME_TYPE=1961 ./list-games.sh
./show-game.sh <game_proxy_address>
```
