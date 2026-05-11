#!/usr/bin/env bash
# X Layer ZK Fault Proof — Sepolia Deployment Verification
# Usage: ./verify-sepolia-deployment.sh <RPC_URL>

set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Error: RPC_URL is required"
    echo "Usage: $0 <RPC_URL>"
    exit 1
fi
L1="$1"

# Contract addresses
GAME_IMPLEMENTATION=0x292812e59A49140f6737015ccA54bd5e8a565100
DISPUTE_GAME_FACTORY=0x80388586ab4580936BCb409Cc2dC6BC0221e1B6F
ACCESS_MANAGER=0x33D211daB418F65Ca71035055bCF557808aCa13f
ANCHOR_STATE_REGISTRY=0x1A8DFc1d6ccfB3bE886b2539823539a9DC0956a5
OPTIMISM_PORTAL2=0x1529a34331d7d85c8868fc88ec730ae56d3ec9c0
SP1_VERIFIER=0x397A5f7f3dBd538f23DE225B51f532c34448dA9B
PROPOSER=0x829D57F38D2A94514a3dbA2297fDD1Bc52bB1938
CHALLENGER=0x7c3787bf0d78a9e2f802916110e4ddd6e3ed262c
CANNON_GAME_IMPLEMENTATION=0x34f0482A8F7B91F8C9346A9cCA705Ba8aC9A1CE3

PASS=0
FAIL=0
TOTAL=0

# check label sig target expected [arg...]
check() {
    local label="$1" sig="$2" target="$3" expected="$4"
    shift 4
    TOTAL=$((TOTAL + 1))
    # strip cast annotation like "604800 [6.048e5]" -> "604800"
    actual=$(cast call "$target" "$sig" "$@" -r "$L1" 2>/dev/null | sed 's/ \[.*\]//' | tr '[:upper:]' '[:lower:]' | xargs)
    expected_lower=$(echo "$expected" | tr '[:upper:]' '[:lower:]' | xargs)
    if [[ "$actual" == "$expected_lower" ]]; then
        echo "  PASS  $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $label"
        echo "        expected: $expected"
        echo "        actual:   $actual"
        FAIL=$((FAIL + 1))
    fi
}

check_nonempty() {
    local label="$1" target="$2"
    TOTAL=$((TOTAL + 1))
    code=$(cast code "$target" -r "$L1" 2>/dev/null)
    if [[ -n "$code" && "$code" != "0x" ]]; then
        echo "  PASS  $label (has code)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $label (no code)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== S1.1: Game Implementation Parameters ==="
check "maxChallengeDuration"  "maxChallengeDuration()(uint64)"  "$GAME_IMPLEMENTATION" "3600"
check "maxProveDuration"      "maxProveDuration()(uint64)"      "$GAME_IMPLEMENTATION" "604800"
check "challengerBond"        "challengerBond()(uint256)"       "$GAME_IMPLEMENTATION" "10000000000"
check "sp1Verifier"           "sp1Verifier()(address)"          "$GAME_IMPLEMENTATION" "$SP1_VERIFIER"
check "anchorStateRegistry"   "anchorStateRegistry()(address)"  "$GAME_IMPLEMENTATION" "$ANCHOR_STATE_REGISTRY"
check "disputeGameFactory"    "disputeGameFactory()(address)"   "$GAME_IMPLEMENTATION" "$DISPUTE_GAME_FACTORY"
check "accessManager"         "accessManager()(address)"        "$GAME_IMPLEMENTATION" "$ACCESS_MANAGER"

echo ""
echo "=== S1.2: Factory Registration ==="
check "gameImpls(42)"  "gameImpls(uint32)(address)" "$DISPUTE_GAME_FACTORY" "$GAME_IMPLEMENTATION"  42
check "initBonds(42)"  "initBonds(uint32)(uint256)"  "$DISPUTE_GAME_FACTORY" "10000000000"          42

echo ""
echo "=== S1.3: AccessManager Permissions ==="
check "proposer whitelisted"       "proposers(address)(bool)"    "$ACCESS_MANAGER" "true"  "$PROPOSER"
check "challenger whitelisted"     "challengers(address)(bool)"  "$ACCESS_MANAGER" "true"  "$CHALLENGER"
check "proposer addr(0) not set"   "proposers(address)(bool)"    "$ACCESS_MANAGER" "false" "0x0000000000000000000000000000000000000000"
check "challenger addr(0) not set" "challengers(address)(bool)"  "$ACCESS_MANAGER" "false" "0x0000000000000000000000000000000000000000"
check "FALLBACK_TIMEOUT"           "FALLBACK_TIMEOUT()(uint256)" "$ACCESS_MANAGER" "604800"

echo ""
echo "=== S1.4: AnchorStateRegistry & OptimismPortal2 ==="
check "ASR respectedGameType"     "respectedGameType()(uint32)"                "$ANCHOR_STATE_REGISTRY" "42"
check "ASR finalityDelay"         "disputeGameFinalityDelaySeconds()(uint256)" "$ANCHOR_STATE_REGISTRY" "12600"
check "Portal respectedGameType"  "respectedGameType()(uint32)"                "$OPTIMISM_PORTAL2"      "42"
check "Portal finalityDelay"      "disputeGameFinalityDelaySeconds()(uint256)" "$OPTIMISM_PORTAL2"      "12600"
check "Portal proofMaturity"      "proofMaturityDelaySeconds()(uint256)"       "$OPTIMISM_PORTAL2"      "25200"

echo ""
echo "=== S1.5: SP1Verifier Contract ==="
check_nonempty "SP1Verifier" "$SP1_VERIFIER"

echo ""
echo "=== S1.6: Legacy Cannon Game Type ==="
check "gameImpls(1)" "gameImpls(uint32)(address)" "$DISPUTE_GAME_FACTORY" "$CANNON_GAME_IMPLEMENTATION" 1

echo ""
echo "=============================="
echo "Result: $PASS/$TOTAL passed, $FAIL failed"
if [[ $FAIL -eq 0 ]]; then
    echo "ALL PASS"
    exit 0
else
    echo "SOME CHECKS FAILED"
    exit 1
fi
