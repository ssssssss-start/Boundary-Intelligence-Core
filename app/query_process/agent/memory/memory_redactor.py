"""Redaction helpers for conversation memory.

The memory layer stores redacted text by default. Raw chat persistence is still
kept by the legacy chat_message path for compatibility, but every new memory
object should prefer these redacted fields.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List


URL_RE = re.compile(r"https?://[^\s]+|[A-Za-z0-9.-]+\.(?:com|cn|net|top|xyz|vip|click)[^\s]*", re.I)
PHONE_RE = re.compile(r"(?<!\d)(1[3-9]\d{9})(?!\d)")
ID_CARD_RE = re.compile(r"(?<!\d)(\d{6}\d{8}\d{3}[\dXx])(?!\d)")
BANK_CARD_RE = re.compile(r"(?<!\d)(\d{13,19})(?!\d)")
CODE_RE = re.compile(r"(?<!\d)(?:验证码|动态码|短信码)[:：\s]*(\d{4,8})(?!\d)")
AMOUNT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(万|w|W|元|块)")
QQ_RE = re.compile(r"(?<!\d)([1-9]\d{4,11})(?!\d)")


def _mask_middle(value: str, keep_start: int = 3, keep_end: int = 4) -> str:
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return value[:keep_start] + "*" * (len(value) - keep_start - keep_end) + value[-keep_end:]


def extract_entities(text: str) -> Dict[str, List[Any]]:
    """Extract lightweight entities needed by route/memory decisions."""
    text = text or ""
    amounts = []
    for number, unit in AMOUNT_RE.findall(text):
        normalized_unit = "万" if unit in {"w", "W"} else unit
        amounts.append(f"{number}{normalized_unit}")
    return {
        "urls": URL_RE.findall(text),
        "phones": PHONE_RE.findall(text),
        "id_cards": ID_CARD_RE.findall(text),
        "bank_cards": BANK_CARD_RE.findall(text),
        "verification_codes": CODE_RE.findall(text),
        "amounts": amounts,
        "qq_numbers": QQ_RE.findall(text),
    }


def redact_sensitive_text(text: str) -> str:
    """Return text with common sensitive values masked."""
    text = text or ""
    text = CODE_RE.sub(lambda m: m.group(0).replace(m.group(1), "[code_hidden]"), text)
    text = PHONE_RE.sub(lambda m: _mask_middle(m.group(1), 3, 4), text)
    text = ID_CARD_RE.sub(lambda m: _mask_middle(m.group(1), 6, 4), text)
    text = BANK_CARD_RE.sub(lambda m: _mask_middle(m.group(1), 6, 4), text)
    return text


def sanitize_external_payload(value: Any) -> Any:
    """Recursively redact common credentials before sending payloads to an external LLM."""
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [sanitize_external_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_external_payload(item) for item in value)
    if isinstance(value, dict):
        return {key: sanitize_external_payload(item) for key, item in value.items()}
    return value


def text_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def build_turn_memory(session_id: str, case_id: str, user_text: str, turn_id: str, created_at: str) -> Dict[str, Any]:
    redacted = redact_sensitive_text(user_text)
    entities = extract_entities(user_text)
    sensitive_flags = {
        "has_phone": bool(entities["phones"]),
        "has_bank_card": bool(entities["bank_cards"]),
        "has_id_card": bool(entities["id_cards"]),
        "has_verification_code": bool(entities["verification_codes"]),
    }
    return {
        "turn_id": turn_id,
        "session_id": session_id,
        "case_id": case_id,
        "user_text_redacted": redacted,
        "text_hash": text_hash(user_text),
        "extracted_entities": entities,
        "sensitive_flags": sensitive_flags,
        "created_at": created_at,
    }
