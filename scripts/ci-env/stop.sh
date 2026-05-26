#!/bin/bash
# ci-env stop — stop all services. Auto-detects topology.
# Usage: bash stop.sh [--clean]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DATA="$PROJECT_ROOT/dev/data"
FP_DIR="$PROJECT_ROOT/fault-proof"
CLEAN=false
[ "${1:-}" = "--clean" ] || [ "${1:-}" = "-c" ] && CLEAN=true

TOPOLOGY="unknown"
[ -f "$DATA/.topology" ] && TOPOLOGY=$(head -1 "$DATA/.topology")

info "Stopping services (topology: $TOPOLOGY)..."

# Challenger first (reverse start order)
stop_pid "$DATA/.challenger.pid" "Challenger"
stop_pid "$DATA/.proposer.pid" "Proposer"

# Stop monitoring (Prometheus + Grafana) if running
if docker ps --filter name=prometheus --filter name=grafana -q 2>/dev/null | grep -q .; then
  info "Stopping monitoring..."
  cd "$FP_DIR"
  [ ! -f .env.proposer ] && touch .env.proposer
  [ ! -f .env.challenger ] && touch .env.challenger
  docker compose -f docker-compose.yml down 2>/dev/null || true
fi

# Orphan cleanup
kill_orphans proposer
kill_orphans challenger
kill_orphans tz-proposer
kill_orphans tz-challenger

ok "All services stopped"

if $CLEAN; then
  info "Cleaning data..."
  rm -f "$DATA"/.*.pid "$DATA"/*.log "$DATA"/.test-env "$DATA"/.topology
  rm -rf "$DATA"/proposer-backup*
  # Docker volumes
  cd "$FP_DIR" 2>/dev/null && {
    [ ! -f .env.proposer ] && touch .env.proposer
    [ ! -f .env.challenger ] && touch .env.challenger
    docker compose -f docker-compose.yml down -v 2>/dev/null || true
  }
  ok "Data cleaned"
fi
