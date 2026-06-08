#!/usr/bin/env bash
# challenge_game.sh — 通过 DisputeGameFactory 找到 game 并发起 challenge
#
# 用法:
#   ./challenge_game.sh --dgf <DGF_ADDRESS> --game-id <INDEX> \
#                       --proof-type <tee|zk> --rpc <L1_RPC_URL> \
#                       --private-key <HEX_KEY>
#
# 示例:
#   ./challenge_game.sh \
#     --dgf 0xabc...  \
#     --game-id 3     \
#     --proof-type tee \
#     --rpc https://l1-rpc.example.com \
#     --private-key 0xdeadbeef...

set -euo pipefail

# ── 参数解析 ──────────────────────────────────────────────────────────────────
DGF=""
GAME_ID=""
PROOF_TYPE=""
RPC_URL=""
PRIVATE_KEY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dgf)          DGF="$2";          shift 2 ;;
    --game-id)      GAME_ID="$2";      shift 2 ;;
    --proof-type)   PROOF_TYPE="$2";   shift 2 ;;
    --rpc)          RPC_URL="$2";      shift 2 ;;
    --private-key)  PRIVATE_KEY="$2";  shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

# ── 校验必填参数 ──────────────────────────────────────────────────────────────
if [[ -z "$DGF" || -z "$GAME_ID" || -z "$PROOF_TYPE" || -z "$RPC_URL" || -z "$PRIVATE_KEY" ]]; then
  echo "用法: $0 --dgf <地址> --game-id <索引> --proof-type <tee|zk> --rpc <URL> --private-key <KEY>" >&2
  exit 1
fi

# ProofType 枚举: TEE=0, ZK=1
case "${PROOF_TYPE,,}" in
  tee) PROOF_TYPE_UINT=0 ;;
  zk)  PROOF_TYPE_UINT=1 ;;
  *)
    echo "错误: --proof-type 必须是 tee 或 zk" >&2
    exit 1
    ;;
esac

# ── 依赖检查 ──────────────────────────────────────────────────────────────────
if ! command -v cast &>/dev/null; then
  echo "错误: 未找到 cast，请先安装 foundry (https://getfoundry.sh)" >&2
  exit 1
fi

echo "=== Challenge Game ==="
echo "  DGF 地址    : $DGF"
echo "  Game ID     : $GAME_ID"
echo "  Proof Type  : ${PROOF_TYPE^^} ($PROOF_TYPE_UINT)"
echo "  RPC         : $RPC_URL"
echo ""

# ── 1. 通过 gameAtIndex 查询 game 地址 ───────────────────────────────────────
echo "[1/4] 查询 game 地址 (index=$GAME_ID)..."
GAME_QUERY=$(cast call "$DGF" \
  "gameAtIndex(uint256)(uint32,uint64,address)" \
  "$GAME_ID" \
  --rpc-url "$RPC_URL")

# cast 输出为多行，第三行是 proxy 地址
GAME_ADDRESS=$(echo "$GAME_QUERY" | awk 'NR==3{print $1}')
GAME_TYPE=$(echo "$GAME_QUERY" | awk 'NR==1{print $1}')
GAME_TIMESTAMP=$(echo "$GAME_QUERY" | awk 'NR==2{print $1}')

if [[ -z "$GAME_ADDRESS" || "$GAME_ADDRESS" == "0x0000000000000000000000000000000000000000" ]]; then
  echo "错误: 未找到 game ID=$GAME_ID" >&2
  exit 1
fi

echo "  Game 地址   : $GAME_ADDRESS"
echo "  Game Type   : $GAME_TYPE"
echo "  创建时间    : $(date -r "$GAME_TIMESTAMP" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$GAME_TIMESTAMP")"
echo ""

# ── 2. 查询 game 当前状态 ─────────────────────────────────────────────────────
echo "[2/4] 查询 game 状态..."

# claimData 返回 (ProposalStatus status, address counteredBy, uint64 deadline, bytes32 claim)
CLAIM_RAW=$(cast call "$GAME_ADDRESS" \
  "claimData()((uint8,address,uint64,bytes32))" \
  --rpc-url "$RPC_URL" 2>/dev/null || true)

# 也可以单独查 status
STATUS_RAW=$(cast call "$GAME_ADDRESS" \
  "status()(uint8)" \
  --rpc-url "$RPC_URL" 2>/dev/null || echo "?")

case "$STATUS_RAW" in
  0) STATUS_STR="Unchallenged" ;;
  1) STATUS_STR="Challenged" ;;
  2) STATUS_STR="Defended" ;;
  3) STATUS_STR="ProposerWon" ;;
  4) STATUS_STR="ChallengerWon" ;;
  *) STATUS_STR="Unknown($STATUS_RAW)" ;;
esac

echo "  Game 状态   : $STATUS_STR"

if [[ "$STATUS_RAW" != "0" ]]; then
  echo "错误: game 状态不是 Unchallenged（当前=$STATUS_STR），无法 challenge" >&2
  exit 1
fi

# ── 3. 查询 challenger bond ───────────────────────────────────────────────────
echo "[3/4] 查询 challenger bond..."
BOND_WEI=$(cast call "$GAME_ADDRESS" \
  "challengerBond()(uint256)" \
  --rpc-url "$RPC_URL" | awk '{print $1}')

BOND_ETH=$(cast to-unit "$BOND_WEI" ether 2>/dev/null | awk '{print $1}' || echo "?")
echo "  Bond 金额   : $BOND_WEI wei ($BOND_ETH ETH)"
echo ""

# ── 4. 发起 challenge ─────────────────────────────────────────────────────────
echo "[4/4] 发起 challenge (ProofType=${PROOF_TYPE^^})..."
echo "  调用        : challenge(uint8) 参数=$PROOF_TYPE_UINT, value=$BOND_WEI wei"
echo ""

TX_HASH=$(cast send "$GAME_ADDRESS" \
  "challenge(uint8)(uint8)" \
  "$PROOF_TYPE_UINT" \
  --value "$BOND_WEI" \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --json | python3 -c "import sys,json; print(json.load(sys.stdin)['transactionHash'])" 2>/dev/null \
  || cast send "$GAME_ADDRESS" \
       "challenge(uint8)(uint8)" \
       "$PROOF_TYPE_UINT" \
       --value "$BOND_WEI" \
       --rpc-url "$RPC_URL" \
       --private-key "$PRIVATE_KEY")

echo "✓ Challenge 成功!"
echo "  交易 Hash   : $TX_HASH"
echo ""
echo "验证 challenge 结果:"
echo "  cast call $GAME_ADDRESS 'claimData()((uint8,address,uint64,bytes32))' --rpc-url $RPC_URL"
echo "  cast call $GAME_ADDRESS 'challengedProofType()(uint8)' --rpc-url $RPC_URL"
