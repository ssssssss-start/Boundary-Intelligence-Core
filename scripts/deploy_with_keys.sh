#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

ENV_FILE=".env"

env_value() {
  local key="$1"
  if [ ! -f "$ENV_FILE" ]; then
    return 0
  fi
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); print; exit }' "$ENV_FILE" \
    | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

update_env_value() {
  local key="$1"
  local value="$2"
  local tmp_file
  tmp_file="$(mktemp)"
  if [ -f "$ENV_FILE" ] && grep -q "^${key}=" "$ENV_FILE"; then
    awk -v key="$key" -v value="$value" 'BEGIN { FS=OFS="=" } $1 == key { print key "=" value; next } { print }' "$ENV_FILE" > "$tmp_file"
  else
    [ -f "$ENV_FILE" ] && cat "$ENV_FILE" > "$tmp_file"
    printf '%s=%s\n' "$key" "$value" >> "$tmp_file"
  fi
  mv "$tmp_file" "$ENV_FILE"
}

is_blank_or_placeholder() {
  local value
  value="$(printf '%s' "${1:-}" | tr -d '[:space:]')"
  [ -z "$value" ] && return 0
  case "$value" in
    your_*|YOUR_*|replace-*|replace_with_*|changeme|CHANGE_ME) return 0 ;;
  esac
  return 1
}

mask_key() {
  local value="$1"
  local len=${#value}
  if [ "$len" -le 8 ]; then
    printf '已配置'
  else
    printf '****%s' "${value: -4}"
  fi
}

prompt_secret() {
  local label="$1"
  local value=""
  if [ ! -t 0 ]; then
    echo "缺少 ${label}，且当前不是交互式终端。" >&2
    return 1
  fi
  read -r -s -p "请输入 ${label}: " value
  echo
  if is_blank_or_placeholder "$value"; then
    echo "${label} 不能为空。" >&2
    return 1
  fi
  printf '%s' "$value"
}

ensure_key() {
  local env_key="$1"
  local label="$2"
  local supplied="${3:-}"
  local current
  current="$(env_value "$env_key")"

  if ! is_blank_or_placeholder "$supplied"; then
    update_env_value "$env_key" "$supplied"
    echo "${label}: 已从环境变量写入 ($(mask_key "$supplied"))"
    return 0
  fi

  if ! is_blank_or_placeholder "$current"; then
    echo "${label}: 使用 .env 中已有配置 ($(mask_key "$current"))"
    return 0
  fi

  local entered
  entered="$(prompt_secret "$label")"
  update_env_value "$env_key" "$entered"
  echo "${label}: 已写入 .env ($(mask_key "$entered"))"
}

if [ ! -f "$ENV_FILE" ]; then
  if [ ! -f ".env.example" ]; then
    echo "缺少 .env.example，无法生成 .env。" >&2
    exit 1
  fi
  cp .env.example "$ENV_FILE"
  echo "已从 .env.example 生成 .env"
fi

update_env_value "OPENAI_BASE_URL" "${OPENAI_BASE_URL:-https://api.deepseek.com}"
update_env_value "LLM_DEFAULT_MODEL" "${LLM_DEFAULT_MODEL:-deepseek-chat}"
update_env_value "VL_MODEL" "${VL_MODEL:-deepseek-chat}"
update_env_value "VISION_BASE_URL" "${VISION_BASE_URL:-https://dashscope.aliyuncs.com/compatible-mode/v1}"
update_env_value "VISION_MODEL" "${VISION_MODEL:-qwen-vl-plus}"
update_env_value "VISION_TEMPERATURE" "${VISION_TEMPERATURE:-0.1}"
update_env_value "VISION_MAX_TOKENS" "${VISION_MAX_TOKENS:-1400}"
update_env_value "VISION_IMAGE_MAX_BYTES" "${VISION_IMAGE_MAX_BYTES:-8388608}"

ensure_key "OPENAI_API_KEY" "DeepSeek 文本模型 OPENAI_API_KEY" "${DEEPSEEK_API_KEY:-${OPENAI_API_KEY:-}}"
ensure_key "VISION_API_KEY" "Qwen 视觉模型 VISION_API_KEY" "${QWEN_API_KEY:-${DASHSCOPE_API_KEY:-${VISION_API_KEY:-}}}"

echo "配置完成，开始启动本地服务..."
bash scripts/start_local_services.sh
