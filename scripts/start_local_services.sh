#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

choose_python() {
  if [ -n "${PYTHON_BIN:-}" ]; then
    printf '%s\n' "$PYTHON_BIN"
    return
  fi
  for candidate in /opt/homebrew/bin/python3.11 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  return 1
}

update_env_value() {
  local key="$1"
  local value="$2"
  local tmp_file
  tmp_file="$(mktemp)"
  if grep -q "^${key}=" .env 2>/dev/null; then
    awk -v key="$key" -v value="$value" 'BEGIN { FS=OFS="=" } $1 == key { print key "=" value; next } { print }' .env > "$tmp_file"
  else
    cat .env > "$tmp_file"
    printf '%s=%s\n' "$key" "$value" >> "$tmp_file"
  fi
  mv "$tmp_file" .env
}

kill_port() {
  local port="$1"
  local pids
  pids="$(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    echo "Stopping process on port ${port}: ${pids}"
    kill $pids 2>/dev/null || true
    sleep 2
  fi
}

PYTHON="$(choose_python)" || {
  echo "Python 3.11+ not found. Please install Python 3.11 first."
  exit 1
}

"$PYTHON" - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ is required")
PY

if [ ! -f .env ]; then
  cp .env.example .env
fi

update_env_value "KOKORO_TTS_PYTHON" "./.venv/bin/python"
update_env_value "KOKORO_TTS_MODEL_DIR" "tts/kokoro/kokoro-int8-multi-lang-v1_1"
update_env_value "KOKORO_TTS_WORKER" "tts/kokoro/kokoro_worker.py"

if [ ! -x .venv/bin/python ]; then
  "$PYTHON" -m venv .venv
fi

./.venv/bin/python -m ensurepip --upgrade
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements.txt

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not installed or not in PATH."
  exit 1
fi

docker compose up -d

kill_port 8000
kill_port 8001

nohup ./.venv/bin/python -m app.import_process.api.file_import_service > runtime_8000.out.log 2> runtime_8000.err.log &
nohup ./.venv/bin/python -m app.query_process.api.query_service > runtime_8001.out.log 2> runtime_8001.err.log &

sleep 5
echo "Checking query service..."
curl -fsS http://127.0.0.1:8001/health
echo
echo "Started:"
echo "- Web chat:        http://127.0.0.1:8001/chat.html"
echo "- Import/admin UI: http://127.0.0.1:8000/import.html"
echo "- Mini program backend: http://127.0.0.1:8001"
echo
echo "Logs:"
echo "- runtime_8000.err.log"
echo "- runtime_8001.err.log"
