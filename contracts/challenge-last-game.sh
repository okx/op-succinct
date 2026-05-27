#!/bin/bash
set -euo pipefail

# Reads .env.tz, finds the most recently created game in the factory, and
# challenges it with the game's required CHALLENGER_BOND.
#
# Usage:
#   ./challenge-last-game.sh
#   DRY_RUN=1 ./challenge-last-game.sh
#
# Required env (in .env.tz or exported):
#   PRIVATE_KEY        challenger EOA — must be whitelisted in AccessManager
#                      (or AccessManager must be in permissionless mode)
#   FACTORY_ADDRESS    DisputeGameFactory
# Optional env:
#   RPC_URL            default http://127.0.0.1:8545
#   DRY_RUN            default 0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE=${ENV_FILE:-"$SCRIPT_DIR/.env.tz"}
if [[ -f "$ENV_FILE" ]]; then
  echo "Loading env from $ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

RPC_URL=${RPC_URL:-http://127.0.0.1:8545}
DRY_RUN=${DRY_RUN:-0}

for v in PRIVATE_KEY FACTORY_ADDRESS; do
  if [[ -z "${!v:-}" ]]; then
    echo "Missing required env: $v" >&2
    exit 1
  fi
done

cast_call() { cast call "$@" --rpc-url "$RPC_URL"; }
# Newer foundry prints "<value> [<sci>]" for ints; keep just the raw value.
strip_sci() { awk '{print $1}'; }

GAME_COUNT=$(cast_call "$FACTORY_ADDRESS" 'gameCount()(uint256)' | strip_sci)
echo "Factory $FACTORY_ADDRESS gameCount=$GAME_COUNT"
if [[ "$GAME_COUNT" -eq 0 ]]; then
  echo "No games to challenge."
  exit 0
fi

LAST_INDEX=$((GAME_COUNT - 1))
mapfile -t parts < <(cast_call "$FACTORY_ADDRESS" \
    'gameAtIndex(uint256)(uint32,uint64,address)' "$LAST_INDEX")
GAME_TYPE=$(printf '%s' "${parts[0]}" | strip_sci)
GAME_TS=$(printf '%s' "${parts[1]}" | strip_sci)
GAME_ADDR=${parts[2]}

echo "Last game:"
echo "  index:     $LAST_INDEX"
echo "  gameType:  $GAME_TYPE"
echo "  createdAt: $GAME_TS"
echo "  address:   $GAME_ADDR"

STATUS=$(cast_call "$GAME_ADDR" 'status()(uint8)' | strip_sci)
BOND=$(cast_call "$GAME_ADDR" 'challengerBond()(uint256)' | strip_sci)
OVER=$(cast_call "$GAME_ADDR" 'gameOver()(bool)')

echo "  status:          $STATUS  (0=IN_PROGRESS 1=CHALLENGER_WINS 2=DEFENDER_WINS)"
echo "  gameOver:        $OVER"
echo "  challengerBond:  $BOND wei"

if [[ "$OVER" == "true" ]]; then
  echo "Game is already over, cannot challenge." >&2
  exit 1
fi

CALLER=$(cast wallet address --private-key "$PRIVATE_KEY")
echo "Challenger EOA: $CALLER"

if [[ "$DRY_RUN" != "0" ]]; then
  echo "[dry-run] would: cast send $GAME_ADDR 'challenge()' --value $BOND"
  exit 0
fi

echo "Sending challenge()..."
TX=$(cast send "$GAME_ADDR" 'challenge()' \
  --value "$BOND" \
  --private-key "$PRIVATE_KEY" \
  --rpc-url "$RPC_URL" \
  --json)

TX_HASH=$(echo "$TX" | jq -r '.transactionHash')
TX_STATUS=$(echo "$TX" | jq -r '.status')
echo "tx: $TX_HASH  status=$TX_STATUS"

if [[ "$TX_STATUS" != "0x1" && "$TX_STATUS" != "1" ]]; then
  echo "challenge() failed" >&2
  exit 1
fi

NEW_STATUS=$(cast_call "$GAME_ADDR" 'status()(uint8)' | strip_sci)
echo "Game status now: $NEW_STATUS"
