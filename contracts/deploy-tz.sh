#!/bin/bash
set -euo pipefail

# Deploys OPSuccinctFaultDisputeGame for TradeZone (tz) and bootstraps the
# AnchorStateRegistry by creating + resolving + closing a single short-lived game.
#
# Usage:
#   ./deploy-tz.sh                # auto-loads ./.env.tz if present
#   ENV_FILE=path/to/.env ./deploy-tz.sh   # custom env file
#
# Required envs (either exported manually or set in the env file):
#   PRIVATE_KEY                broadcasting EOA private key
#   FACTORY_ADDRESS            DisputeGameFactory
#   ANCHOR_STATE_REGISTRY      AnchorStateRegistry
#   TRANSACTOR                 Transactor that owns the factory
#   BOOTSTRAP_ROOT_CLAIM       bytes32 root claim for the bootstrap game
#   BOOTSTRAP_L2_BLOCK_NUMBER  uint256 l2 block number for the bootstrap game
#
# Optional envs:
#   RPC_URL                    defaults to http://127.0.0.1:8545
#
# The broadcasting EOA must:
#   - be a whitelisted proposer (or AccessManager in permissionless mode)
#   - hold >= config.initialBondWei (from contracts/opsuccinctfdgconfig.json)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Auto-load env file if present. ENV_FILE overrides the default location.
ENV_FILE=${ENV_FILE:-"$SCRIPT_DIR/.env.tz"}
if [[ -f "$ENV_FILE" ]]; then
  echo "Loading env from $ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

RPC_URL=${RPC_URL:-http://127.0.0.1:8545}

# Validate required env vars
required_envs=(
  PRIVATE_KEY
  FACTORY_ADDRESS
  ANCHOR_STATE_REGISTRY
  TRANSACTOR
  BOOTSTRAP_ROOT_CLAIM
  BOOTSTRAP_L2_BLOCK_NUMBER
)
missing=()
for v in "${required_envs[@]}"; do
  if [[ -z "${!v:-}" ]]; then
    missing+=("$v")
  fi
done
if (( ${#missing[@]} > 0 )); then
  echo "Missing required env vars: ${missing[*]}" >&2
  exit 1
fi

# Patch sp1-contracts pragma to be compatible with >=0.8.15 (same as deploy-testnet.sh)
if [[ "$OSTYPE" == "darwin"* ]]; then
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i '' 's/pragma solidity \^0.8.20;/pragma solidity >=0.8.15;/'
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i '' 's/pragma solidity 0.8.20;/pragma solidity >=0.8.15;/'
else
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i 's/pragma solidity \^0.8.20;/pragma solidity >=0.8.15;/'
  find lib/sp1-contracts -name "*.sol" -type f | xargs sed -i 's/pragma solidity 0.8.20;/pragma solidity >=0.8.15;/'
fi

echo "Deploying via RPC: $RPC_URL"

# --slow forces each tx to mine before the next is sent. This is what lets the
# bootstrap game's 1s challenge deadline lapse before resolve() is called.
forge script \
  script/fp/DeployOPSuccinctLiteTz.s.sol:DeployOPSuccinctLiteTz \
  -vvv \
  --slow \
  --private-key="$PRIVATE_KEY" \
  --rpc-url="$RPC_URL" \
  --broadcast
