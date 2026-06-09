#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

: "${TZ_PROJ_PATH:?TZ_PROJ_PATH must be set by the caller}"

get_proposal_status() {
  local game_address="$1"
  local raw
  raw=$(cast call "$game_address" "claimData()(uint32,address,address,bytes32,uint8,uint64)" --rpc-url http://localhost:8545 | awk 'NR==5')
  case "$raw" in
    0) echo "Unchallenged" ;;
    1) echo "Challenged" ;;
    2) echo "UnchallengedAndValidProofProvided" ;;
    3) echo "ChallengedAndValidProofProvided" ;;
    4) echo "Resolved" ;;
    *) echo "Unknown($raw)" ;;
  esac
}

echo "======================================================================"
echo "[*] Spinning up L1 node..."
anvil --block-time 1 > "$SCRIPT_DIR/anvil.log" 2>&1 &

ANVIL_PID=$!
cleanup() {
  echo "[*] Stopping anvil (PID $ANVIL_PID)..."
  kill "$ANVIL_PID" 2>/dev/null || true
  echo "[*] Stopping proposer (PID ${PROPOSER_PID:-unset})..."
  kill "${PROPOSER_PID:-}" 2>/dev/null || true
  echo "[*] Stopping L2 (TradeZone)..."
  (cd "$TZ_PROJ_PATH" && ./dev/scripts/ci-env/stop.sh --clean) || true
}
trap cleanup EXIT

ANVIL_PREFUNDED_MNEMONICS="test test test test test test test test test test test junk"

export DEPLOYER_SK=$(cast wallet private-key --mnemonic "$ANVIL_PREFUNDED_MNEMONICS" --mnemonic-index 0)

export PROPOSER_SK=$(cast wallet private-key --mnemonic "$ANVIL_PREFUNDED_MNEMONICS" --mnemonic-index 1)
export PROPOSER=$(cast wallet address --private-key "$PROPOSER_SK")

export CHALLENGER_SK=$(cast wallet private-key --mnemonic "$ANVIL_PREFUNDED_MNEMONICS" --mnemonic-index 2)
export CHALLENGER=$(cast wallet address --private-key "$CHALLENGER_SK")

SP1_CONTRACTS_DIR="$SCRIPT_DIR/../contracts/lib/sp1-contracts"
if [[ "$OSTYPE" == "darwin"* ]]; then
  find "$SP1_CONTRACTS_DIR" -name "*.sol" -type f | xargs sed -i '' 's/pragma solidity \^0.8.20;/pragma solidity >=0.8.15;/'
  find "$SP1_CONTRACTS_DIR" -name "*.sol" -type f | xargs sed -i '' 's/pragma solidity 0.8.20;/pragma solidity >=0.8.15;/'
else
  find "$SP1_CONTRACTS_DIR" -name "*.sol" -type f | xargs sed -i 's/pragma solidity \^0.8.20;/pragma solidity >=0.8.15;/'
  find "$SP1_CONTRACTS_DIR" -name "*.sol" -type f | xargs sed -i 's/pragma solidity 0.8.20;/pragma solidity >=0.8.15;/'
fi

 
echo "======================================================================"
echo "[*] Deploying contracts and getting addresses..."
cd ../contracts
FORGE_LOG="$SCRIPT_DIR/forge-deploy.log"
forge script script/fp/DeployOPSuccintLiteTzAll.s.sol --rpc-url http://localhost:8545 --broadcast 2>&1 | tee "$FORGE_LOG"
FACTORY_ADDRESS=$(grep "DisputeGameFactory   :" "$FORGE_LOG" | awk '{print $NF}')
ANCHOR_STATE_REGISTRY=$(grep "AnchorStateRegistry  :" "$FORGE_LOG" | awk '{print $NF}')

cd $SCRIPT_DIR

sed \
  -e "s|{{FACTORY_ADDRESS}}|$FACTORY_ADDRESS|g" \
  -e "s|{{ANCHOR_STATE_REGISTRY_ADDRESS}}|$ANCHOR_STATE_REGISTRY|g" \
  -e "s|{{PRIVATE_KEY}}|$PROPOSER_SK|g" \
  "$SCRIPT_DIR/example.env.tz-proposer" > "$SCRIPT_DIR/.env.tz-proposer"


echo "======================================================================"
echo "[*] Spin up L2(Tradezone)..."

cd $TZ_PROJ_PATH
./dev/scripts/ci-env/start.sh ci-single --zkvm
cd $SCRIPT_DIR

cd ..

# when building tz-proposer, cargo will dump some artifacts to $CARGO_HOME and $TMPDIR. 
# Set $CARGO_HOME and $TMPDIR to ones inside DACS to address permission issue. 
if [[ -n "$DACS" ]]; then 
    export CARGO_HOME=$DACS/.cargo
    export TMPDIR=$DACS/Documents/tmp
fi

echo "[*] Building tz-proposer..."
cargo build --bin tz-proposer --features tz
echo "[*] Spin up Proposer..."
./target/debug/tz-proposer --env-file "$SCRIPT_DIR/.env.tz-proposer" \
  > "$SCRIPT_DIR/tz-proposer.log" 2>&1 &
PROPOSER_PID=$!
cd $SCRIPT_DIR

echo "[*] All services launched. Start to get a game to challenge..."
sleep 10

echo "[*] Waiting for first game to be deployed (timeout: 5 minutes)..."
GAME_DEADLINE=$((SECONDS + 300))
GAME_COUNT=0
while [[ $SECONDS -lt $GAME_DEADLINE ]]; do
  GAME_COUNT=$(cast call "$FACTORY_ADDRESS" "gameCount()(uint256)" --rpc-url http://localhost:8545 | awk '{print $1}')
  echo "[*] $(date '+%H:%M:%S') Waiting for game deployment ($SECONDS/$GAME_DEADLINE secs). "
  if [[ "$GAME_COUNT" -gt 0 ]]; then
    break
  fi
  sleep 5
done
if [[ "$GAME_COUNT" -eq 0 ]]; then
  echo "[!] No games deployed within 5 minutes."
  exit 1
fi

LAST_INDEX=$((GAME_COUNT - 1))
LAST_GAME_ADDRESS=$(cast call "$FACTORY_ADDRESS" "gameAtIndex(uint256)(uint32,uint64,address)" "$LAST_INDEX" --rpc-url http://localhost:8545 | awk 'NR==3')
echo "[*] Last deployed game address: $LAST_GAME_ADDRESS"

PROPOSAL_STATUS=$(get_proposal_status "$LAST_GAME_ADDRESS")
echo "[*] Last game ProposalStatus: $PROPOSAL_STATUS"
if [[ "$PROPOSAL_STATUS" != "Unchallenged" ]]; then
  echo "[!] Expected ProposalStatus 'Unchallenged', got '$PROPOSAL_STATUS'"
  exit 1
fi

echo "[*] Raising challenge on game $LAST_GAME_ADDRESS (status: $PROPOSAL_STATUS)..."
CHALLENGER_BOND=$(cast call "$LAST_GAME_ADDRESS" "challengerBond()(uint256)" --rpc-url http://localhost:8545 | awk '{print $1}')
CHALLENGE_RECEIPT=$(cast send "$LAST_GAME_ADDRESS" "challenge()" \
  --value "$CHALLENGER_BOND" \
  --private-key "$CHALLENGER_SK" \
  --rpc-url http://localhost:8545 \
  --json)
CHALLENGE_TX_STATUS=$(echo "$CHALLENGE_RECEIPT" | jq -r '.status')
if [[ "$CHALLENGE_TX_STATUS" != "0x1" ]]; then
  echo "[!] Challenge transaction failed (status: $CHALLENGE_TX_STATUS)"
  exit 1
fi
echo "[*] Challenge raised successfully on game $LAST_GAME_ADDRESS."

PROPOSAL_STATUS=$(get_proposal_status "$LAST_GAME_ADDRESS")
if [[ "$PROPOSAL_STATUS" != "Challenged" ]]; then
  echo "[!] Expected ProposalStatus 'Challenged' after challenge tx, got '$PROPOSAL_STATUS'"
  exit 1
fi
echo "[*] Game status confirmed: $PROPOSAL_STATUS"

echo "[*] Polling for game resolution (timeout: 5 minutes)..."
DEADLINE=$((SECONDS + 300))
while [[ $SECONDS -lt $DEADLINE ]]; do
  PROPOSAL_STATUS=$(get_proposal_status "$LAST_GAME_ADDRESS")
  echo "[*] $(date '+%H:%M:%S') Waiting Game to be Resolved ($SECONDS/$DEADLINE secs), Current Status: $PROPOSAL_STATUS. "
  if [[ "$PROPOSAL_STATUS" == "Resolved" ]]; then
    echo -e "\n\033[1;32m✔ SUCCESS: Game $LAST_GAME_ADDRESS resolved successfully!\033[0m\n"
    break
  fi
  sleep 5
done

if [[ "$PROPOSAL_STATUS" != "Resolved" ]]; then
  echo "[!] Game did not resolve within 5 minutes (last status: $PROPOSAL_STATUS)"
  exit 1
fi
