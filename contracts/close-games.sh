#!/bin/bash
set -euo pipefail

# Scans the DisputeGameFactory and advances every OPSuccinct game of GAME_TYPE
# through whatever next step it's eligible for:
#   - status == IN_PROGRESS && gameOver()        -> resolve()        (if RESOLVE=1)
#   - status != IN_PROGRESS && !closed && final  -> closeGame()
# Games that are already closed, still in their challenge window, or not yet
# finalized (portal finality delay not elapsed) are skipped.
#
# Usage:
#   ./close-games.sh                 # auto-loads ./.env.tz
#   DRY_RUN=1 ./close-games.sh       # show plan, no broadcast
#   RESOLVE=0 ./close-games.sh       # only closeGame, never resolve
#   GAME_TYPE=1961 ./close-games.sh  # override game type filter
#
# Required env (or in .env.tz):
#   PRIVATE_KEY               any funded EOA (no special role needed)
#   FACTORY_ADDRESS
#   ANCHOR_STATE_REGISTRY
# Optional env:
#   GAME_TYPE   default 1961
#   RPC_URL     default http://127.0.0.1:8545
#   DRY_RUN     default 0
#   RESOLVE     default 1

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
GAME_TYPE=${GAME_TYPE:-1961}
DRY_RUN=${DRY_RUN:-0}
RESOLVE=${RESOLVE:-1}

for v in PRIVATE_KEY FACTORY_ADDRESS ANCHOR_STATE_REGISTRY; do
  if [[ -z "${!v:-}" ]]; then
    echo "Missing required env: $v" >&2
    exit 1
  fi
done

# GameStatus           : 0 IN_PROGRESS | 1 CHALLENGER_WINS | 2 DEFENDER_WINS
# BondDistributionMode : 0 UNDECIDED   | 1 NORMAL          | 2 REFUND
STATUS_IN_PROGRESS=0
BDM_UNDECIDED=0

cast_call() { cast call "$@" --rpc-url "$RPC_URL"; }
cast_send() { cast send "$@" --private-key "$PRIVATE_KEY" --rpc-url "$RPC_URL" >/dev/null; }

GAME_COUNT=$(cast_call "$FACTORY_ADDRESS" 'gameCount()(uint256)')
echo "Factory $FACTORY_ADDRESS reports gameCount=$GAME_COUNT (filter gameType=$GAME_TYPE)"
if [[ "$GAME_COUNT" -eq 0 ]]; then
  echo "Nothing to do."
  exit 0
fi

resolved=0
closed=0
skipped=0

for ((i=0; i<GAME_COUNT; i++)); do
  # gameAtIndex returns (uint32, uint64, address) — 3 lines from cast
  mapfile -t parts < <(cast_call "$FACTORY_ADDRESS" \
      'gameAtIndex(uint256)(uint32,uint64,address)' "$i")
  gt=${parts[0]}
  proxy=${parts[2]}

  if [[ "$gt" != "$GAME_TYPE" ]]; then
    continue
  fi

  status=$(cast_call "$proxy" 'status()(uint8)')
  bdm=$(cast_call "$proxy" 'bondDistributionMode()(uint8)')

  printf "[%2d] %s status=%s bdm=%s " "$i" "$proxy" "$status" "$bdm"

  if [[ "$bdm" != "$BDM_UNDECIDED" ]]; then
    echo "-> already closed, skip"
    skipped=$((skipped+1))
    continue
  fi

  if [[ "$status" == "$STATUS_IN_PROGRESS" ]]; then
    if [[ "$RESOLVE" != "1" ]]; then
      echo "-> IN_PROGRESS and RESOLVE=0, skip"
      skipped=$((skipped+1))
      continue
    fi
    over=$(cast_call "$proxy" 'gameOver()(bool)')
    if [[ "$over" != "true" ]]; then
      echo "-> challenge window not over, skip"
      skipped=$((skipped+1))
      continue
    fi
    echo -n "-> resolve()"
    if [[ "$DRY_RUN" == "0" ]]; then
      if cast_send "$proxy" 'resolve()' 2>/dev/null; then
        resolved=$((resolved+1))
        status=$(cast_call "$proxy" 'status()(uint8)')
        echo -n " ok (new status=$status) "
      else
        echo " FAILED, skip"
        skipped=$((skipped+1))
        continue
      fi
    else
      echo -n " [dry-run] "
      resolved=$((resolved+1))
    fi
  fi

  finalized=$(cast_call "$ANCHOR_STATE_REGISTRY" \
      'isGameFinalized(address)(bool)' "$proxy")
  if [[ "$finalized" != "true" ]]; then
    echo "-> not finalized (waiting for finality delay), skip"
    skipped=$((skipped+1))
    continue
  fi

  echo -n "-> closeGame()"
  if [[ "$DRY_RUN" == "0" ]]; then
    if cast_send "$proxy" 'closeGame()' 2>/dev/null; then
      closed=$((closed+1))
      echo " ok"
    else
      echo " FAILED"
      skipped=$((skipped+1))
    fi
  else
    echo " [dry-run]"
    closed=$((closed+1))
  fi
done

echo "---"
echo "Resolved: $resolved   Closed: $closed   Skipped: $skipped"

if [[ "$closed" -gt 0 && "$DRY_RUN" == "0" ]]; then
  echo "Current anchor:"
  cast_call "$ANCHOR_STATE_REGISTRY" 'getAnchorRoot()(bytes32,uint256)'
fi
