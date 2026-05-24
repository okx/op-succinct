#!/bin/bash
# Logging and color utilities. Source this — do not execute directly.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }

pid_alive() {
  [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null
}

launch_bg() {
  local pidfile="$1" log="$2"
  shift 2
  "$@" </dev/null >>"$log" 2>&1 &
  echo $! > "$pidfile"
  disown
}

stop_pid() {
  local pf="$1" label="$2" timeout="${3:-5}"
  [ -f "$pf" ] || { echo "  $label: not running"; return 0; }
  local pid; pid=$(cat "$pf")
  kill -0 "$pid" 2>/dev/null || { rm -f "$pf"; echo "  $label: stale PID"; return 0; }
  echo -n "  $label: stopping PID $pid..."
  kill "$pid" 2>/dev/null
  local i=0; while [ "$i" -lt "$timeout" ] && kill -0 "$pid" 2>/dev/null; do sleep 1; i=$((i+1)); done
  kill -0 "$pid" 2>/dev/null && { kill -9 "$pid" 2>/dev/null; echo " force-killed"; } || echo " ok"
  rm -f "$pf"
}

wait_http() {
  local url="$1" label="$2" max="${3:-60}"
  echo -n "  Waiting $label"
  local i=0; while [ "$i" -lt "$max" ]; do
    curl -sf "$url" >/dev/null 2>&1 && { echo " ready(${i}s)"; return 0; }
    echo -n "."; sleep 1; i=$((i+1))
  done
  echo " TIMEOUT(${max}s)"; return 1
}

wait_port() {
  local port="$1" label="$2" max="${3:-30}"
  echo -n "  Waiting $label(:$port)"
  local i=0; while [ "$i" -lt "$max" ]; do
    nc -z 127.0.0.1 "$port" 2>/dev/null && { echo " ready(${i}s)"; return 0; }
    echo -n "."; sleep 1; i=$((i+1))
  done
  echo " TIMEOUT(${max}s)"; return 1
}

wait_process() {
  local pidfile="$1" label="$2" max="${3:-10}"
  echo -n "  Waiting $label"
  sleep 2
  if pid_alive "$pidfile"; then
    echo " alive"
    return 0
  fi
  echo " DIED"
  return 1
}

kill_orphans() {
  local name="$1"
  local pids; pids=$(pgrep -x "$name" 2>/dev/null) || true
  [ -n "$pids" ] && { kill $pids 2>/dev/null; sleep 1; kill -9 $pids 2>/dev/null; } || true
}

load_env() {
  local envfile="$1"
  if [ ! -f "$envfile" ]; then
    err "Env file not found: $envfile"
    return 1
  fi
  info "Loading env from $envfile"
  set -a
  # shellcheck disable=SC1090
  source "$envfile"
  set +a
}
