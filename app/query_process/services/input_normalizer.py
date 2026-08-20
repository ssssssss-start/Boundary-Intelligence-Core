"""Input normalization helpers for anti-fraud rule evaluation.

The rule engine needs deterministic, reusable preprocessing instead of each
caller inventing its own regex snippets. Keep this module deliberately light:
it extracts stable signals only and leaves business scoring to
``scam_rule_engine``.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


URL_PATTERN = re.compile(
    r"https?://[^\s，。；]+|[A-Za-z0-9.-]+\.(?:com|cn|net|top|xyz|vip|click)[^\s，。；]*",
    re.IGNORECASE,
)

AMOUNT_PATTERN = re.compile(r"(\d+(?:\.\d+)?)\s*(万|w|W|元|块)")


def normalize_text(text: str) -> str:
    """Normalize whitespace and common punctuation without changing meaning."""
    value = str(text or "")
    value = re.sub(r"[\t\r\n]+", " ", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def extract_urls(text: str) -> List[str]:
    """Extract URLs and URL-like domains from user text."""
    return [match.group(0).rstrip("。；，,;") for match in URL_PATTERN.finditer(text or "")]


def extract_amounts(text: str) -> List[str]:
    """Extract numeric money mentions in a normalized display form."""
    amounts: List[str] = []
    for number, unit in AMOUNT_PATTERN.findall(text or ""):
        if unit in {"w", "W"}:
            unit = "万"
        amounts.append(f"{number}{unit}")
    return amounts


def compact_text(text: str) -> str:
    """Remove whitespace for short regex windows."""
    return re.sub(r"\s+", "", text or "")


def build_context_text(text: str, context: Dict[str, Any] | None = None) -> str:
    """Merge the current text with selected user-provided context.

    Only compact, user-originated context is used. Assistant prompts are not
    included here to avoid turning safety questions into user facts.
    """
    context = context or {}
    parts = [text or ""]
    for key in ["history_text", "memory_summary", "rewritten_query"]:
        if context.get(key):
            parts.append(str(context.get(key) or ""))

    for item in context.get("history") or []:
        if isinstance(item, dict) and item.get("role") == "user" and item.get("text"):
            parts.append(str(item.get("text") or ""))

    return normalize_text(" ".join(part for part in parts if part))

