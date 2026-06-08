#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/contracts"
DATA_DIR="${DATA_DIR:-$ROOT_DIR/dev/data}"

DEFAULT_ANVIL_DEPLOYER_PK="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEFAULT_ANVIL_CHALLENGER_PK="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
ZERO_ADDRESS="0x0000000000000000000000000000000000000000"
ZERO_BYTES32="0x0000000000000000000000000000000000000000000000000000000000000000"

L1_HOST="${L1_HOST:-0.0.0.0}"
L1_PORT="${L1_PORT:-8547}"
CHAIN_ID="${CHAIN_ID:-31337}"
L1_RPC="${L1_RPC:-${RPC_URL:-http://127.0.0.1:$L1_PORT}}"
TZ_RPC="${TZ_RPC:-${L2_RPC:-http://127.0.0.1:10000}}"
TZ_NODE_RPC="${TZ_NODE_RPC:-${TZ_RPC%%,*}}"

DEPLOYER_PK="${DEPLOYER_PK:-${PRIVATE_KEY:-$DEFAULT_ANVIL_DEPLOYER_PK}}"
PROPOSER_PK="${PROPOSER_PK:-$DEPLOYER_PK}"
CHALLENGER_PK="${CHALLENGER_PK:-$DEFAULT_ANVIL_CHALLENGER_PK}"

GAME_TYPE="${GAME_TYPE:-1961}"
MOCK_MODE="${MOCK_MODE:-true}"
FETCH_INTERVAL="${FETCH_INTERVAL:-5}"
PROPOSAL_INTERVAL_IN_BLOCKS="${PROPOSAL_INTERVAL_IN_BLOCKS:-1}"
SAFE_DB_FALLBACK="${SAFE_DB_FALLBACK:-true}"
MAX_CONCURRENT_DEFENSE_TASKS="${MAX_CONCURRENT_DEFENSE_TASKS:-8}"
PROPOSER_METRICS_PORT="${PROPOSER_METRICS_PORT:-9000}"
CHALLENGER_METRICS_PORT="${CHALLENGER_METRICS_PORT:-9001}"
TX_CONFIRMATION_TIMEOUT="${TX_CONFIRMATION_TIMEOUT:-120}"
MALICIOUS_CHALLENGE_PERCENTAGE="${MALICIOUS_CHALLENGE_PERCENTAGE:-100}"

DISPUTE_GAME_FINALITY_DELAY_SECONDS="${DISPUTE_GAME_FINALITY_DELAY_SECONDS:-10}"
MAX_CHALLENGE_DURATION="${MAX_CHALLENGE_DURATION:-300}"
MAX_PROVE_DURATION="${MAX_PROVE_DURATION:-3600}"
FALLBACK_TIMEOUT_FP_SECS="${FALLBACK_TIMEOUT_FP_SECS:-604800}"

INSTALL_SUBMODULES="${INSTALL_SUBMODULES:-1}"
PATCH_SP1_PRAGMAS="${PATCH_SP1_PRAGMAS:-1}"
BUILD_BINARIES="${BUILD_BINARIES:-0}"
START_SERVICES="${START_SERVICES:-0}"
SKIP_ANVIL="${SKIP_ANVIL:-0}"
SKIP_TZ_CHECKPOINT="${SKIP_TZ_CHECKPOINT:-0}"

CONFIG_PATH="${CONFIG_PATH:-$CONTRACTS_DIR/config/tz/opsuccinctfdgconfig.json}"
ANVIL_LOG="${ANVIL_LOG:-$DATA_DIR/anvil-$L1_PORT.log}"
ANVIL_PID_FILE="${ANVIL_PID_FILE:-$DATA_DIR/anvil-$L1_PORT.pid}"
DEPLOY_LOG="${DEPLOY_LOG:-$DATA_DIR/tz-fdg-deploy.log}"
SUMMARY_ENV="$DATA_DIR/tz-devnet.env"
PROPOSER_ENV="$ROOT_DIR/.env.tz-proposer"
CHALLENGER_ENV="$ROOT_DIR/.env.tz-challenger"

log() {
  printf '[tz-devnet] %s\n' "$*"
}

fail() {
  printf '[tz-devnet] error: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

wait_for_l1_rpc() {
  local rpc="$1"
  local i

  for i in $(seq 1 30); do
    if cast chain-id --rpc-url "$rpc" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  return 1
}

start_or_reuse_anvil() {
  if cast chain-id --rpc-url "$L1_RPC" >/dev/null 2>&1; then
    log "reusing L1 RPC at $L1_RPC"
    return
  fi

  if [[ "$SKIP_ANVIL" == "1" ]]; then
    fail "L1 RPC is not reachable at $L1_RPC and SKIP_ANVIL=1"
  fi

  require_cmd anvil
  log "starting Anvil on $L1_HOST:$L1_PORT (log: $ANVIL_LOG)"
  nohup anvil --host "$L1_HOST" --port "$L1_PORT" --chain-id "$CHAIN_ID" >"$ANVIL_LOG" 2>&1 &
  echo "$!" >"$ANVIL_PID_FILE"

  if ! wait_for_l1_rpc "$L1_RPC"; then
    tail -n 80 "$ANVIL_LOG" >&2 || true
    fail "Anvil did not become ready at $L1_RPC"
  fi
}

fetch_tz_checkpoint() {
  local info
  local code

  log "fetching TradeZone checkpoint from ${TZ_RPC%%,*}"
  info="$(curl -fsS "${TZ_RPC%%,*}/chain/confirmed_block_info")"
  code="$(jq -r '.code // empty' <<<"$info")"
  if [[ -n "$code" && "$code" != "0" ]]; then
    fail "TradeZone checkpoint endpoint returned code=$code"
  fi

  STARTING_L2_BLOCK_NUMBER="$(jq -r '.data.height // empty' <<<"$info")"
  BLOCK_HASH="$(jq -r '.data.blockHash // empty' <<<"$info")"
  APP_HASH="$(jq -r '.data.appHash // empty' <<<"$info")"

  [[ -n "$STARTING_L2_BLOCK_NUMBER" && "$STARTING_L2_BLOCK_NUMBER" != "null" ]] || fail "missing .data.height in checkpoint response"
  [[ -n "$BLOCK_HASH" && "$BLOCK_HASH" != "null" ]] || fail "missing .data.blockHash in checkpoint response"
  [[ -n "$APP_HASH" && "$APP_HASH" != "null" ]] || fail "missing .data.appHash in checkpoint response"

  STARTING_ROOT="$(cast keccak "0x${BLOCK_HASH#0x}${APP_HASH#0x}")"
  log "checkpoint height=$STARTING_L2_BLOCK_NUMBER root=$STARTING_ROOT"
}

ensure_contract_deps() {
  if [[ "$INSTALL_SUBMODULES" != "1" ]]; then
    return
  fi

  if [[ -d "$CONTRACTS_DIR/lib/sp1-contracts/contracts/src" && -d "$CONTRACTS_DIR/lib/forge-std/src" ]]; then
    return
  fi

  log "installing contract submodules"
  git -C "$ROOT_DIR" submodule update --init --recursive
}

patch_sp1_pragmas() {
  local sp1_dir="$CONTRACTS_DIR/lib/sp1-contracts"
  local file

  if [[ "$PATCH_SP1_PRAGMAS" != "1" ]]; then
    return
  fi

  [[ -d "$sp1_dir" ]] || fail "missing $sp1_dir; run git submodule update --init --recursive"

  log "patching sp1-contracts Solidity pragmas for Foundry resolver compatibility"
  while IFS= read -r -d '' file; do
    if [[ "$(uname -s)" == "Darwin" ]]; then
      sed -i '' 's/pragma solidity \^0.8.20;/pragma solidity >=0.8.15;/' "$file"
      sed -i '' 's/pragma solidity 0.8.20;/pragma solidity >=0.8.15;/' "$file"
    else
      sed -i 's/pragma solidity \^0.8.20;/pragma solidity >=0.8.15;/' "$file"
      sed -i 's/pragma solidity 0.8.20;/pragma solidity >=0.8.15;/' "$file"
    fi
  done < <(find "$sp1_dir" -name '*.sol' -type f -print0)
}

update_contract_config() {
  local backup_path="$DATA_DIR/opsuccinctfdgconfig.$(date +%Y%m%d-%H%M%S).json"
  local tmp_path

  [[ -f "$CONFIG_PATH" ]] || fail "missing config file: $CONFIG_PATH"

  DEPLOYER_ADDRESS="$(cast wallet address --private-key "$DEPLOYER_PK")"
  PROPOSER_ADDRESS="$(cast wallet address --private-key "$PROPOSER_PK")"
  CHALLENGER_ADDRESS="$(cast wallet address --private-key "$CHALLENGER_PK")"

  cp "$CONFIG_PATH" "$backup_path"
  tmp_path="$(mktemp)"

  jq \
    --arg gameType "$GAME_TYPE" \
    --arg proposer "$PROPOSER_ADDRESS" \
    --arg challenger "$CHALLENGER_ADDRESS" \
    --arg startingL2BlockNumber "$STARTING_L2_BLOCK_NUMBER" \
    --arg startingRoot "$STARTING_ROOT" \
    --arg rollupConfigHash "$ZERO_BYTES32" \
    --arg zero "$ZERO_ADDRESS" \
    --arg finalityDelay "$DISPUTE_GAME_FINALITY_DELAY_SECONDS" \
    --arg maxChallenge "$MAX_CHALLENGE_DURATION" \
    --arg maxProve "$MAX_PROVE_DURATION" \
    --arg fallbackTimeout "$FALLBACK_TIMEOUT_FP_SECS" \
    --arg rangeVkey "${TZ_RANGE_VKEY:-}" \
    --arg aggregationVkey "${TZ_AGG_VKEY:-}" \
    '
    .gameType = ($gameType | tonumber)
    | .permissionlessMode = false
    | .useSp1MockVerifier = true
    | .proposerAddresses = [$proposer]
    | .challengerAddresses = [$challenger]
    | .startingL2BlockNumber = ($startingL2BlockNumber | tonumber)
    | .startingRoot = $startingRoot
    | .rollupConfigHash = $rollupConfigHash
    | .existingAnchorStateRegistry = $zero
    | .existingDisputeGameFactoryProxy = $zero
    | .systemConfigAddress = $zero
    | .optimismPortal2Address = $zero
    | .disputeGameFinalityDelaySeconds = ($finalityDelay | tonumber)
    | .maxChallengeDuration = ($maxChallenge | tonumber)
    | .maxProveDuration = ($maxProve | tonumber)
    | .fallbackTimeoutFpSecs = ($fallbackTimeout | tonumber)
    | if $rangeVkey != "" then .rangeVkeyCommitment = $rangeVkey else . end
    | if $aggregationVkey != "" then .aggregationVkey = $aggregationVkey else . end
    ' "$CONFIG_PATH" >"$tmp_path"

  mv "$tmp_path" "$CONFIG_PATH"
  log "updated contract config: $CONFIG_PATH"
  log "previous config backup: $backup_path"
}

build_binaries_if_requested() {
  if [[ "$BUILD_BINARIES" != "1" ]]; then
    return
  fi

  log "building tz-proposer and tz-challenger"
  cargo build --release --features tz --bin tz-proposer --bin tz-challenger
}

deploy_contracts() {
  log "deploying OPSuccinct FDG contracts"
  (
    cd "$CONTRACTS_DIR"
    forge clean
    OP_SUCCINCT_FAULT_DISPUTE_GAME_CONFIG_PATH="$CONFIG_PATH" \
      forge script script/fp/DeployOPSuccinctFDG.s.sol:DeployOPSuccinctFDG \
        --rpc-url "$L1_RPC" \
        --private-key "$DEPLOYER_PK" \
        --broadcast \
        --slow \
        --via-ir \
        --optimize \
        -vvvv
  ) | tee "$DEPLOY_LOG"
}

parse_deployed_address() {
  local label="$1"

  awk -v label="$label" '
    $0 ~ label {
      for (i = NF; i >= 1; i--) {
        if ($i ~ /^0x[0-9a-fA-F]{40}$/) {
          print $i
          exit
        }
      }
    }
  ' "$DEPLOY_LOG"
}

load_deployed_addresses() {
  FACTORY_ADDRESS="$(parse_deployed_address "factoryProxy: address")"
  ANCHOR_STATE_REGISTRY_ADDRESS="$(parse_deployed_address "anchorStateRegistry: address")"
  SP1_VERIFIER_ADDRESS="$(parse_deployed_address "sp1Verifier: address")"

  if [[ -z "$SP1_VERIFIER_ADDRESS" ]]; then
    SP1_VERIFIER_ADDRESS="$(parse_deployed_address "Using SP1 Mock Verifier:")"
  fi

  [[ -n "$FACTORY_ADDRESS" ]] || fail "could not parse factoryProxy from $DEPLOY_LOG"
  [[ -n "$ANCHOR_STATE_REGISTRY_ADDRESS" ]] || fail "could not parse anchorStateRegistry from $DEPLOY_LOG"
  [[ -n "$SP1_VERIFIER_ADDRESS" ]] || fail "could not parse sp1 verifier from $DEPLOY_LOG"

  local factory_code
  factory_code="$(cast code "$FACTORY_ADDRESS" --rpc-url "$L1_RPC")"
  [[ "$factory_code" != "0x" ]] || fail "factory $FACTORY_ADDRESS has no code on $L1_RPC"
}

write_service_envs() {
  log "writing $PROPOSER_ENV"
  cat >"$PROPOSER_ENV" <<EOF
L1_RPC=$L1_RPC
L2_RPC=$TZ_RPC
L2_NODE_RPC=$TZ_NODE_RPC

FACTORY_ADDRESS=$FACTORY_ADDRESS
ANCHOR_STATE_REGISTRY_ADDRESS=$ANCHOR_STATE_REGISTRY_ADDRESS
GAME_TYPE=$GAME_TYPE

PRIVATE_KEY=$PROPOSER_PK

MOCK_MODE=$MOCK_MODE
FETCH_INTERVAL=$FETCH_INTERVAL
PROPOSAL_INTERVAL_IN_BLOCKS=$PROPOSAL_INTERVAL_IN_BLOCKS
SAFE_DB_FALLBACK=$SAFE_DB_FALLBACK
MAX_CONCURRENT_DEFENSE_TASKS=$MAX_CONCURRENT_DEFENSE_TASKS
PROPOSER_METRICS_PORT=$PROPOSER_METRICS_PORT
TX_CONFIRMATION_TIMEOUT=$TX_CONFIRMATION_TIMEOUT
EOF

  log "writing $CHALLENGER_ENV"
  cat >"$CHALLENGER_ENV" <<EOF
L1_RPC=$L1_RPC
L2_RPC=$TZ_RPC
L2_NODE_RPC=$TZ_NODE_RPC

FACTORY_ADDRESS=$FACTORY_ADDRESS
ANCHOR_STATE_REGISTRY_ADDRESS=$ANCHOR_STATE_REGISTRY_ADDRESS
GAME_TYPE=$GAME_TYPE

PRIVATE_KEY=$CHALLENGER_PK

FETCH_INTERVAL=$FETCH_INTERVAL
MALICIOUS_CHALLENGE_PERCENTAGE=$MALICIOUS_CHALLENGE_PERCENTAGE
CHALLENGER_METRICS_PORT=$CHALLENGER_METRICS_PORT
TX_CONFIRMATION_TIMEOUT=$TX_CONFIRMATION_TIMEOUT
EOF

  log "writing $SUMMARY_ENV"
  cat >"$SUMMARY_ENV" <<EOF
export L1_RPC='$L1_RPC'
export RPC_URL='$L1_RPC'
export TZ_RPC='$TZ_RPC'
export L2_RPC='$TZ_RPC'
export L2_NODE_RPC='$TZ_NODE_RPC'
export GAME_TYPE='$GAME_TYPE'
export DEPLOYER_ADDRESS='$DEPLOYER_ADDRESS'
export PROPOSER_ADDRESS='$PROPOSER_ADDRESS'
export CHALLENGER_ADDRESS='$CHALLENGER_ADDRESS'
export DEPLOYER_PK='$DEPLOYER_PK'
export PROPOSER_PK='$PROPOSER_PK'
export CHALLENGER_PK='$CHALLENGER_PK'
export FACTORY_ADDRESS='$FACTORY_ADDRESS'
export ANCHOR_STATE_REGISTRY_ADDRESS='$ANCHOR_STATE_REGISTRY_ADDRESS'
export SP1_VERIFIER_ADDRESS='$SP1_VERIFIER_ADDRESS'
export STARTING_L2_BLOCK_NUMBER='$STARTING_L2_BLOCK_NUMBER'
export STARTING_ROOT='$STARTING_ROOT'
export DEPLOY_LOG='$DEPLOY_LOG'
EOF
}

start_service_if_requested() {
  local name="$1"
  local bin_path="$2"
  local env_file="$3"
  local log_file="$4"
  local pid_file="$5"

  [[ -x "$bin_path" ]] || fail "missing executable $bin_path; run BUILD_BINARIES=1 $0 or cargo build --release --features tz --bin tz-proposer --bin tz-challenger"

  if [[ -f "$pid_file" ]]; then
    local old_pid
    old_pid="$(cat "$pid_file")"
    if [[ -n "$old_pid" ]] && ps -p "$old_pid" >/dev/null 2>&1; then
      log "$name already running pid=$old_pid"
      return
    fi
  fi

  log "starting $name (log: $log_file)"
  RUST_LOG="${RUST_LOG:-info}" nohup "$bin_path" --env-file "$env_file" >"$log_file" 2>&1 &
  echo "$!" >"$pid_file"
}

start_services_if_requested() {
  if [[ "$START_SERVICES" != "1" ]]; then
    return
  fi

  start_service_if_requested \
    "tz-proposer" \
    "$ROOT_DIR/target/release/tz-proposer" \
    "$PROPOSER_ENV" \
    "$DATA_DIR/tz-proposer.log" \
    "$DATA_DIR/tz-proposer.pid"

  start_service_if_requested \
    "tz-challenger" \
    "$ROOT_DIR/target/release/tz-challenger" \
    "$CHALLENGER_ENV" \
    "$DATA_DIR/tz-challenger.log" \
    "$DATA_DIR/tz-challenger.pid"
}

print_summary() {
  cat <<EOF

[tz-devnet] setup complete

L1 RPC:                  $L1_RPC
TradeZone RPC:           $TZ_RPC
Factory:                 $FACTORY_ADDRESS
AnchorStateRegistry:     $ANCHOR_STATE_REGISTRY_ADDRESS
SP1 verifier:            $SP1_VERIFIER_ADDRESS
Proposer address:         $PROPOSER_ADDRESS
Challenger address:       $CHALLENGER_ADDRESS
Starting TZ block:        $STARTING_L2_BLOCK_NUMBER
Starting root:            $STARTING_ROOT

Env files:
  $PROPOSER_ENV
  $CHALLENGER_ENV
  $SUMMARY_ENV

Start services:
  RUST_LOG=info ./target/release/tz-proposer --env-file .env.tz-proposer
  RUST_LOG=info ./target/release/tz-challenger --env-file .env.tz-challenger

Manual challenge helper:
  set -a; source dev/data/tz-devnet.env; set +a
  cd contracts && ENV_FILE=/dev/null RPC_URL="\$L1_RPC" FACTORY_ADDRESS="\$FACTORY_ADDRESS" PRIVATE_KEY="\$CHALLENGER_PK" ./challenge-last-game.sh
EOF
}

main() {
  require_cmd curl
  require_cmd jq
  require_cmd cast
  require_cmd forge

  mkdir -p "$DATA_DIR"

  start_or_reuse_anvil
  if [[ "$SKIP_TZ_CHECKPOINT" == "1" ]]; then
    STARTING_L2_BLOCK_NUMBER="${STARTING_L2_BLOCK_NUMBER:-0}"
    STARTING_ROOT="${STARTING_ROOT:-$ZERO_BYTES32}"
    log "using configured checkpoint height=$STARTING_L2_BLOCK_NUMBER root=$STARTING_ROOT"
  else
    fetch_tz_checkpoint
  fi
  ensure_contract_deps
  patch_sp1_pragmas
  update_contract_config
  build_binaries_if_requested
  deploy_contracts
  load_deployed_addresses
  write_service_envs
  start_services_if_requested
  print_summary
}

main "$@"
