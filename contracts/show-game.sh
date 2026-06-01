#!/usr/bin/env bash
# Print the full ClaimData struct of an OPSuccinctFaultDisputeGame proxy.
#
# Usage:
#   ./show-game.sh <GAME_PROXY>
#
# Optional env vars:
#   L1_RPC     RPC endpoint of the L1 hosting the game
#              (default: http://127.0.0.1:8545)
#   ENV_FILE   env file to source (default: .env.tz if present, else .env)
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <GAME_PROXY>" >&2
    exit 1
fi

GAME_PROXY="$1"

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

fmt_ts() {
    local ts="$1"
    [[ "$ts" =~ ^[0-9]+$ ]] || { echo ""; return; }
    # macOS BSD date uses -r, GNU date uses -d @
    date -r "$ts" -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
        || date -u -d "@$ts" +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
        || echo ""
}

echo "L1_RPC : $L1_RPC"
echo "Game   : $GAME_PROXY"
echo

if status_raw=$(cast call --rpc-url "$L1_RPC" "$GAME_PROXY" "status()(uint8)" 2>/dev/null); then
    game_status_label=$(label "$status_raw" GAME_STATUS unknown)
else
    status_raw=""
    game_status_label="<call_err>"
fi

mapfile -t cd < <(cast call --rpc-url "$L1_RPC" "$GAME_PROXY" \
    "claimData()(uint32,address,address,bytes32,uint8,uint64)")

parent_index="${cd[0]}"
countered_by="${cd[1]}"
prover="${cd[2]}"
claim="${cd[3]}"
proposal_status_raw="${cd[4]}"
deadline="${cd[5]}"

proposal_status_label=$(label "$proposal_status_raw" PROPOSAL_STATUS unknown)
deadline_human=$(fmt_ts "$deadline")

printf '%-22s %s\n' 'GameStatus'      "$status_raw ($game_status_label)"
echo
echo 'ClaimData:'
printf '  %-20s %s\n' 'parentIndex'   "$parent_index"
printf '  %-20s %s\n' 'counteredBy'   "$countered_by"
printf '  %-20s %s\n' 'prover'        "$prover"
printf '  %-20s %s\n' 'claim'         "$claim"
printf '  %-20s %s\n' 'status'        "$proposal_status_raw ($proposal_status_label)"
if [[ -n "$deadline_human" ]]; then
    printf '  %-20s %s (%s)\n' 'deadline'  "$deadline" "$deadline_human"
else
    printf '  %-20s %s\n' 'deadline'      "$deadline"
fi
