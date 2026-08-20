"""Trusted web fallback for knowledge answers.

The local Mongo/Milvus knowledge base remains the primary source.  This module
only runs when the knowledge orchestrator decides local RAG is weak or missing,
and it never writes fetched web content into the formal knowledge collections.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from typing import Any, Dict, List

import httpx

from app.clients.mongo_business_utils import get_business_mongo_tool
from app.core.logger import logger


TRUSTED_DOMAINS = [
    "mps.gov.cn",
    "court.gov.cn",
    "spp.gov.cn",
    "12321.cn",
    "12377.cn",
    "miit.gov.cn",
    "gov.cn",
    "pbc.gov.cn",
    "cbirc.gov.cn",
    "nfra.gov.cn",
    "moe.gov.cn",
    "samr.gov.cn",
]


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _query_hash(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def _cache_payload(payload: Dict[str, Any]) -> None:
    try:
        tool = get_business_mongo_tool()
        tool.db["web_fallback_cache"].update_one(
            {"query_hash": payload["query_hash"]},
            {"$set": payload, "$setOnInsert": {"created_at": payload.get("created_at") or _now()}},
            upsert=True,
        )
    except Exception as exc:
        logger.warning(f"Web fallback cache write failed: {exc}")


def _empty_result(query: str, status: str, reason: str, provider: str = "tavily") -> Dict[str, Any]:
    payload = {
        "query": query,
        "query_hash": _query_hash(query),
        "provider": provider,
        "web_status": status,
        "reason": reason,
        "trusted_domains": TRUSTED_DOMAINS,
        "items": [],
        "created_at": _now(),
        "updated_at": _now(),
    }
    if status not in {"unavailable", "skipped"}:
        _cache_payload(payload)
    return payload


def search_trusted_web(query: str, *, limit: int = 5) -> Dict[str, Any]:
    """Search trusted public sources when local RAG is not good enough.

    Currently supports Tavily.  If no provider key is configured, callers get a
    structured unavailable result and should fall back to a general template.
    """
    query = str(query or "").strip()
    if not query:
        return _empty_result(query, "skipped", "empty_query")

    api_key = os.getenv("TAVILY_API_KEY") or os.getenv("WEB_SEARCH_API_KEY")
    if not api_key:
        return _empty_result(query, "unavailable", "missing_tavily_api_key")

    endpoint = os.getenv("TAVILY_SEARCH_URL") or "https://api.tavily.com/search"
    payload = {
        "api_key": api_key,
        "query": query,
        "search_depth": "advanced",
        "include_answer": False,
        "include_raw_content": False,
        "max_results": max(1, min(int(limit or 5), 8)),
        "include_domains": TRUSTED_DOMAINS,
    }

    try:
        with httpx.Client(timeout=12) as client:
            response = client.post(endpoint, json=payload)
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        logger.warning(f"Trusted web fallback failed: {exc}", exc_info=True)
        return _empty_result(query, "error", str(exc)[:240])

    items: List[Dict[str, Any]] = []
    for item in data.get("results") or []:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        items.append(
            {
                "title": str(item.get("title") or "")[:200],
                "url": url,
                "content": str(item.get("content") or item.get("snippet") or "")[:1000],
                "score": item.get("score", 0),
                "source_quality_tier": "trusted_web_fallback",
            }
        )

    result = {
        "query": query,
        "query_hash": _query_hash(query),
        "provider": "tavily",
        "web_status": "completed" if items else "empty",
        "reason": "",
        "trusted_domains": TRUSTED_DOMAINS,
        "items": items,
        "created_at": _now(),
        "updated_at": _now(),
    }
    _cache_payload(result)
    return result


__all__ = ["TRUSTED_DOMAINS", "search_trusted_web"]
