#!/bin/bash
# ci-env status — show all service states.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DATA="$PROJECT_ROOT/dev/data"

TOPOLOGY="unknown"
TZ_MODE=false
if [ -f "$DATA/.topology" ]; then
  TOPOLOGY=$(head -1 "$DATA/.topology")
  grep -q "tz" "$DATA/.topology" && TZ_MODE=true
fi

echo "=== Service Status ==="
echo "  Topology: $TOPOLOGY"
echo ""

# Proposer
PROP_LABEL="Proposer"
PROP_PORT="${PROPOSER_METRICS_PORT:-9000}"
$TZ_MODE && PROP_LABEL="tz-proposer"
if pid_alive "$DATA/.proposer.pid"; then
  pid=$(cat "$DATA/.proposer.pid")
  printf "  ${GREEN}●${NC} %-16s PID=%-6s metrics=:%s\n" "$PROP_LABEL" "$pid" "$PROP_PORT"
else
  printf "  ${RED}●${NC} %-16s STOPPED\n" "$PROP_LABEL"
fi

# Challenger
CHAL_LABEL="Challenger"
CHAL_PORT="${CHALLENGER_METRICS_PORT:-9001}"
$TZ_MODE && CHAL_LABEL="tz-challenger"
if pid_alive "$DATA/.challenger.pid"; then
  pid=$(cat "$DATA/.challenger.pid")
  printf "  ${GREEN}●${NC} %-16s PID=%-6s metrics=:%s\n" "$CHAL_LABEL" "$pid" "$CHAL_PORT"
else
  printf "  ${RED}●${NC} %-16s STOPPED\n" "$CHAL_LABEL"
fi

echo ""
echo "=== Docker ==="

# Prometheus
PROM_ST=$(docker inspect prometheus --format '{{.State.Status}}' 2>/dev/null || true)
PROM_ST=$(echo "$PROM_ST" | tr -d '[:space:]')
[ -z "$PROM_ST" ] && PROM_ST="stopped"
if [ "$PROM_ST" = "running" ]; then
  printf "  ${GREEN}●${NC} %-16s %s :%s\n" "Prometheus" "$PROM_ST" "${FP_PROMETHEUS_PORT:-9090}"
else
  printf "  ${RED}●${NC} %-16s %s\n" "Prometheus" "$PROM_ST"
fi

# Grafana
GF_ST=$(docker inspect grafana --format '{{.State.Status}}' 2>/dev/null || true)
GF_ST=$(echo "$GF_ST" | tr -d '[:space:]')
[ -z "$GF_ST" ] && GF_ST="stopped"
if [ "$GF_ST" = "running" ]; then
  printf "  ${GREEN}●${NC} %-16s %s :%s\n" "Grafana" "$GF_ST" "${FP_GRAFANA_PORT:-3000}"
else
  printf "  ${RED}●${NC} %-16s %s\n" "Grafana" "$GF_ST"
fi

# Env info
echo ""
echo "=== Environment ==="
if [ -f "$DATA/.test-env" ]; then
  # shellcheck disable=SC1091
  source "$DATA/.test-env" 2>/dev/null
  echo "  L1_RPC:    ${L1_RPC:-<not set>}"
  echo "  L2_RPC:    ${L2_RPC:-<not set>}"
  echo "  GAME_TYPE: ${GAME_TYPE:-<not set>}"
  echo "  MOCK_MODE: ${MOCK_MODE:-<not set>}"
else
  echo "  No .test-env found (env not started yet)"
fi

# Log tail hints
echo ""
echo "=== Logs ==="
echo "  Proposer:   tail -f $DATA/proposer.log"
echo "  Challenger: tail -f $DATA/challenger.log"
