#!/bin/bash
set -euo pipefail

# Sync select fields from xlayer-toolkit/devnet into ./.env.tz.
#
# Sources:
#   $DEVNET_DIR/.env                     — devnet env file
#   $DEVNET_DIR/config-op/state.json     — op-deployer state
#
# Mappings written into .env.tz:
#   TRANSACTOR              <- devnet/.env TRANSACTOR
#   FACTORY_ADDRESS         <- state.json .opChainDeployments[0].DisputeGameFactoryProxy
#   ANCHOR_STATE_REGISTRY   <- state.json .opChainDeployments[0].AnchorStateRegistryProxy
#
# Usage:
#   DEVNET_DIR=/data/yxq/xlayer-toolkit/devnet ./sync-env.sh
#   ./sync-env.sh                       # uses default DEVNET_DIR below

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

DEVNET_DIR=${DEVNET_DIR:-$SCRIPT_DIR/../../xlayer-toolkit/devnet}
OUT_FILE=${OUT_FILE:-"$SCRIPT_DIR/.env.tz"}
EXAMPLE_FILE=${EXAMPLE_FILE:-"$SCRIPT_DIR/example.env.tz"}

SRC_ENV="$DEVNET_DIR/.env"
SRC_STATE="$DEVNET_DIR/config-op/state.json"

for f in "$SRC_ENV" "$SRC_STATE" "$EXAMPLE_FILE"; do
  if [[ ! -f "$f" ]]; then
    echo "Missing source file: $f" >&2
    exit 1
  fi
done

if [[ ! -f "$OUT_FILE" ]]; then
  echo "Bootstrapping $OUT_FILE from $EXAMPLE_FILE"
  cp "$EXAMPLE_FILE" "$OUT_FILE"
fi

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

# Read a KEY=value line from devnet/.env, strip surrounding quotes.
read_env() {
  local key=$1
  grep -E "^${key}=" "$SRC_ENV" | tail -1 | cut -d= -f2- | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

TRANSACTOR=$(read_env TRANSACTOR)
FACTORY_ADDRESS=$(jq -r '.opChainDeployments[0].DisputeGameFactoryProxy' "$SRC_STATE")
ANCHOR_STATE_REGISTRY=$(jq -r '.opChainDeployments[0].AnchorStateRegistryProxy' "$SRC_STATE")

for name in TRANSACTOR FACTORY_ADDRESS ANCHOR_STATE_REGISTRY; do
  val=${!name}
  if [[ -z "$val" || "$val" == "null" ]]; then
    echo "Failed to resolve $name from sources" >&2
    exit 1
  fi
done

sed_inplace() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    sed -i '' "$@"
  else
    sed -i "$@"
  fi
}

# Upsert KEY=VALUE in $OUT_FILE — replace existing line or append.
# Values here are hex addresses (no `|`, `/`, `&`), safe for sed.
upsert() {
  local key=$1 val=$2
  if grep -qE "^${key}=" "$OUT_FILE"; then
    sed_inplace -E "s|^${key}=.*|${key}=${val}|" "$OUT_FILE"
  else
    echo "${key}=${val}" >> "$OUT_FILE"
  fi
}

upsert TRANSACTOR             "$TRANSACTOR"
upsert FACTORY_ADDRESS        "$FACTORY_ADDRESS"
upsert ANCHOR_STATE_REGISTRY  "$ANCHOR_STATE_REGISTRY"

echo "Synced into $OUT_FILE:"
echo "  TRANSACTOR=$TRANSACTOR"
echo "  FACTORY_ADDRESS=$FACTORY_ADDRESS"
echo "  ANCHOR_STATE_REGISTRY=$ANCHOR_STATE_REGISTRY"
