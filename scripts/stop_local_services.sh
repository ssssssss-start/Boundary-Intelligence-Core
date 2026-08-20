#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

kill_port() {
  local port="$1"
  local pids
  pids="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    echo "Stopping process on port ${port}: ${pids}"
    kill $pids 2>/dev/null || true
  else
    echo "No process listening on port ${port}"
  fi
}

kill_port 8000
kill_port 8001

if [ "${1:-}" = "--docker" ]; then
  docker compose down
else
  echo "Docker containers are still running. Use './scripts/stop_local_services.sh --docker' to stop Mongo/Milvus too."
fi
