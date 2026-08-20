"""Query graph node utilities."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from langchain_core.messages import HumanMessage, SystemMessage

from app.core.logger import logger
from app.lm.lm_utils import get_llm_client
from app.utils.task_utils import add_done_task, add_running_task


def mark_node_start(state: Dict[str, Any], node_name: str) -> None:
    session_id = state.get("session_id", "")
    if session_id:
        add_running_task(session_id, node_name, state.get("is_stream", False))


def mark_node_done(state: Dict[str, Any], node_name: str) -> None:
    session_id = state.get("session_id", "")
    if session_id:
        add_done_task(session_id, node_name, state.get("is_stream", False))


def append_warning(state: Dict[str, Any], message: str) -> None:
    warnings = state.get("warnings") or []
    warnings.append(message)
    state["warnings"] = warnings
    logger.warning(message)


def get_message_content(resp: Any) -> str:
    return (getattr(resp, "content", "") or "").strip()


def extract_json_object(text: str) -> Dict[str, Any]:
    if not text:
        return {}
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()
    try:
        data = json.loads(cleaned)
        return data if isinstance(data, dict) else {}
    except Exception:
        pass

    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if not match:
        return {}
    try:
        data = json.loads(match.group(0))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def invoke_json_llm(system_prompt: str, human_prompt: str) -> tuple[Dict[str, Any], str]:
    llm = get_llm_client(json_mode=True)
    resp = llm.invoke([
        SystemMessage(content=system_prompt),
        HumanMessage(content=human_prompt),
    ])
    raw_text = get_message_content(resp)
    return extract_json_object(raw_text), raw_text


def ensure_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def build_history_text(history: List[Dict[str, Any]], max_chars: int = 3000) -> str:
    parts: List[str] = []
    for item in history or []:
        role = item.get("role", "")
        text = item.get("text") or item.get("content", "")
        if not text:
            continue
        role_name = "用户" if role == "user" else "助手" if role == "assistant" else role
        parts.append(f"{role_name}：{text}")
    return "\n".join(parts)[-max_chars:]
