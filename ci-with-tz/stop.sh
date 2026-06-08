#!/usr/bin/env bash
set -euo pipefail

: "${TZ_PROJ_PATH:?TZ_PROJ_PATH must be set by the caller}"

echo "[*] Stopping anvil..."
pkill -f "anvil --block-time" 2>/dev/null || true
echo "[*] Stopping tz-proposer..."
pkill -f "tz-proposer" 2>/dev/null || true
echo "[*] Stopping L2 (TradeZone)..."
(cd "$TZ_PROJ_PATH" && ./dev/scripts/ci-env/stop.sh --clean) || true
