import base64
import json
import logging
import os
from typing import Any

import httpx

from app.conf.lm_config import lm_config


logger = logging.getLogger(__name__)


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip().strip('"').strip("'")


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _normalize_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _normalize_score(value: Any) -> float:
    try:
        score = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    if score > 1:
        score = score / 100.0
    return max(0.0, min(1.0, score))


def _image_mime(filename: str, content_type: str | None = None) -> str:
    content_type = (content_type or "").strip().lower()
    if content_type in {"image/png", "image/jpeg", "image/webp"}:
        return content_type
    lower = (filename or "").lower()
    if lower.endswith((".jpg", ".jpeg")):
        return "image/jpeg"
    if lower.endswith(".webp"):
        return "image/webp"
    return "image/png"


def _extract_json(content: str) -> dict[str, Any]:
    text = (content or "").strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        text = text[start : end + 1]
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("vision result is not a JSON object")
    return parsed


def _provider_config() -> dict[str, Any]:
    vision_base_url = _env("VISION_BASE_URL")
    vision_api_key = _env("VISION_API_KEY")
    vision_model = _env("VISION_MODEL")
    uses_explicit_vision_provider = bool(vision_base_url or vision_api_key or vision_model)

    return {
        "api_key": vision_api_key if uses_explicit_vision_provider else lm_config.api_key,
        "base_url": vision_base_url if uses_explicit_vision_provider else lm_config.base_url,
        "model": vision_model if uses_explicit_vision_provider else (lm_config.lv_model or lm_config.llm_model),
        "temperature": _env_float("VISION_TEMPERATURE", lm_config.llm_temperature),
        "max_tokens": int(_env("VISION_MAX_TOKENS", "1400") or "1400"),
    }


def _unavailable_result(reason: str) -> dict[str, Any]:
    return {
        "vision_status": "unavailable",
        "reason": reason,
        "risk_level": "unknown",
        "risk_score": 0.0,
        "scene_type": "",
        "fraud_types": [],
        "ocr_text": "",
        "matched_signals": [],
        "summary": "截图识别暂不可用。",
        "conclusion": "请先配置视觉模型，或把截图里的文字复制到聊天框让我继续判断。",
    }


def _failed_result(reason: str) -> dict[str, Any]:
    return {
        "vision_status": "failed",
        "reason": reason,
        "risk_level": "unknown",
        "risk_score": 0.0,
        "scene_type": "",
        "fraud_types": [],
        "ocr_text": "",
        "matched_signals": [],
        "summary": "截图识别失败。",
        "conclusion": "可以重试上传，或把截图里的文字复制到聊天框继续分析。",
    }


async def analyze_image_fraud_risk(
    image_bytes: bytes,
    filename: str = "",
    content_type: str | None = None,
) -> dict[str, Any]:
    """Use a vision-capable OpenAI-compatible model to OCR and assess fraud risk."""
    config = _provider_config()
    if not config["api_key"] or not config["base_url"] or not config["model"]:
        missing = [
            name
            for name, value in {
                "VISION_API_KEY": config["api_key"],
                "VISION_BASE_URL": config["base_url"],
                "VISION_MODEL": config["model"],
            }.items()
            if not value
        ]
        return _unavailable_result(f"缺少视觉模型配置：{', '.join(missing)}")

    mime = _image_mime(filename, content_type)
    image_b64 = base64.b64encode(image_bytes).decode("utf-8")
    data_url = f"data:{mime};base64,{image_b64}"

    system_prompt = (
        "你是智能反诈助手的视觉 OCR 与截图风险分析模块。"
        "请读取图片中的可见文字，判断是否存在诈骗、诱导转账、诱导下载、验证码、屏幕共享、押金、保证金、退款、"
        "贷款、刷单、投资理财、冒充客服/公检法/熟人等风险。必须只返回 JSON，不要输出 Markdown。"
    )
    user_prompt = (
        "请分析这张截图，返回严格 JSON："
        "{"
        "\"risk_level\":\"low|medium|high|critical|unknown\","
        "\"risk_score\":0到1的小数,"
        "\"scene_type\":\"截图场景\","
        "\"fraud_types\":[\"可能的诈骗类型\"],"
        "\"ocr_text\":\"完整 OCR 文字，保留关键账号、金额、链接、验证码上下文；看不清则说明\","
        "\"matched_signals\":[\"命中的风险信号\"],"
        "\"summary\":\"一句话概括截图内容\","
        "\"conclusion\":\"给用户的初步判断和下一步建议\""
        "}。如果图片不是诈骗，也要说明依据，不要编造看不到的信息。"
    )
    payload = {
        "model": config["model"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": user_prompt},
                    {"type": "image_url", "image_url": {"url": data_url}},
                ],
            },
        ],
        "temperature": config["temperature"],
        "max_tokens": config["max_tokens"],
    }
    headers = {
        "Authorization": f"Bearer {config['api_key']}",
        "Content-Type": "application/json",
    }
    url = f"{str(config['base_url']).rstrip('/')}/chat/completions"

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()
        content = body["choices"][0]["message"]["content"]
        if not isinstance(content, str):
            return _failed_result("视觉模型未返回文本内容")
        parsed = _extract_json(content)
    except Exception as exc:
        logger.warning("Vision OCR analysis failed: %s", exc)
        return _failed_result(str(exc))

    risk_level = str(parsed.get("risk_level") or "unknown").strip().lower()
    return {
        "vision_status": "ok",
        "provider": {
            "base_url": config["base_url"],
            "model": config["model"],
        },
        "risk_level": risk_level,
        "risk_score": _normalize_score(parsed.get("risk_score")),
        "scene_type": str(parsed.get("scene_type") or ""),
        "fraud_types": _normalize_list(parsed.get("fraud_types")),
        "ocr_text": str(parsed.get("ocr_text") or ""),
        "matched_signals": _normalize_list(parsed.get("matched_signals")),
        "summary": str(parsed.get("summary") or ""),
        "conclusion": str(parsed.get("conclusion") or ""),
    }
