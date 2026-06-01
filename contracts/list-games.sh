#!/usr/bin/env bash
# List every dispute game in the factory together with its on-chain `GameStatus`
# and the `ProposalStatus` stored in `claimData`.
#
# Required env vars:
#   FACTORY_ADDRESS  DisputeGameFactory deployment
#
# Optional env vars:
#   L1_RPC           RPC endpoint of the L1 hosting the factory
#                    (default: http://127.0.0.1:8545)
#   GAME_TYPE        if set, only list games of this type (e.g. 1961 for tz)
#   LIMIT            number of most-recent games to print (default: 100,
#                    use 0 or "all" to print every game)
#   ENV_FILE         env file to source (default: .env.tz if present, else .env)
#
# Usage:
#   ./list-games.sh
#   GAME_TYPE=1961 ./list-games.sh
#   LIMIT=all ./list-games.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-}"
if [[ -z "$ENV_FILE" ]]; then
    if [[ -f "$SCRIPT_DIR/.env.tz" ]]; then
        ENV_FILE="$SCRIPT_DIR/.env.tz"
    elif [[ -f "$SCRIPT_DIR/.env" ]]; then
        ENV_FILE="$SCRIPT_DIR/.env"
    fi
fi
if [[ -n "$ENV_FILE" && -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
fi

L1_RPC="${L1_RPC:-http://127.0.0.1:8545}"
: "${FACTORY_ADDRESS:?FACTORY_ADDRESS must be set}"
GAME_TYPE_FILTER="${GAME_TYPE:-}"
LIMIT_INPUT="${LIMIT:-100}"
if [[ "$LIMIT_INPUT" == "all" || "$LIMIT_INPUT" == "0" ]]; then
    LIMIT=0
elif [[ "$LIMIT_INPUT" =~ ^[0-9]+$ ]]; then
    LIMIT="$LIMIT_INPUT"
else
    echo "LIMIT must be a non-negative integer or 'all' (got: $LIMIT_INPUT)" >&2
    exit 1
fi

# OPSuccinctFaultDisputeGame.sol enum GameStatus (uint8)
GAME_STATUS=(IN_PROGRESS CHALLENGER_WINS DEFENDER_WINS)
# OPSuccinctFaultDisputeGame.sol enum ProposalStatus (uint8)
PROPOSAL_STATUS=(Unchallenged Challenged UnchallengedAndValidProofProvided ChallengedAndValidProofProvided Resolved)

label() {
    local raw="$1"
    local -n table="$2"
    local default="${3:-?}"
    if [[ "$raw" =~ ^[0-9]+$ ]] && (( raw < ${#table[@]} )); then
        echo "${table[$raw]}"
    else
        echo "$default($raw)"
    fi
}

GAME_COUNT=$(cast call --rpc-url "$L1_RPC" "$FACTORY_ADDRESS" "gameCount()(uint256)")

if (( LIMIT == 0 || LIMIT >= GAME_COUNT )); then
    START_INDEX=0
    RANGE_DESC="all $GAME_COUNT games"
else
    START_INDEX=$(( GAME_COUNT - LIMIT ))
    RANGE_DESC="last $LIMIT games (idx $START_INDEX .. $((GAME_COUNT - 1)))"
fi

echo "L1_RPC    : $L1_RPC"
echo "Factory   : $FACTORY_ADDRESS"
echo "gameCount : $GAME_COUNT"
echo "Showing   : $RANGE_DESC"
[[ -n "$GAME_TYPE_FILTER" ]] && echo "Filter    : gameType == $GAME_TYPE_FILTER"
echo

printf '%5s  %-42s  %9s  %-18s  %s\n' idx proxy gameType GameStatus ProposalStatus
printf -- '%.0s-' {1..120}; echo

for (( i = START_INDEX; i < GAME_COUNT; i++ )); do
    # gameAtIndex(uint256) returns (GameType uint32, Timestamp uint64, IDisputeGame address)
    mapfile -t entry < <(cast call --rpc-url "$L1_RPC" "$FACTORY_ADDRESS" \
        "gameAtIndex(uint256)(uint32,uint64,address)" "$i")
    game_type_actual="${entry[0]}"
    proxy="${entry[2]}"

    if [[ -n "$GAME_TYPE_FILTER" && "$game_type_actual" != "$GAME_TYPE_FILTER" ]]; then
        continue
    fi

    if game_status_raw=$(cast call --rpc-url "$L1_RPC" "$proxy" "status()(uint8)" 2>/dev/null); then
        game_status_label=$(label "$game_status_raw" GAME_STATUS unknown)
    else
        game_status_label="<call_err>"
    fi

    # ClaimData is `ClaimData public claimData` — Solidity auto-unpacks the struct
    # into (parentIndex uint32, counteredBy address, prover address, claim bytes32,
    #       status ProposalStatus uint8, deadline Timestamp uint64).
    if mapfile -t claim < <(cast call --rpc-url "$L1_RPC" "$proxy" \
            "claimData()(uint32,address,address,bytes32,uint8,uint64)" 2>/dev/null); then
        proposal_status_label=$(label "${claim[4]}" PROPOSAL_STATUS unknown)
    else
        proposal_status_label="<call_err>"
    fi

    printf '%5d  %-42s  %9s  %-18s  %s\n' \
        "$i" "$proxy" "$game_type_actual" "$game_status_label" "$proposal_status_label"
done
