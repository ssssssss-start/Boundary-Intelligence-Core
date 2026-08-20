"""Fraud-type taxonomy helpers.

The runtime still exposes Chinese ``fraud_type`` names for compatibility, but
new database records also carry a stable ``fraud_type_id``.  This module keeps
the mapping in one place so import scripts, audits, and future services do not
need to guess from display text.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCAM_TYPES_PATH = PROJECT_ROOT / "data" / "knowledge" / "scam_types.json"


CANONICAL_NAME_ALIASES: Dict[str, str] = {
    "AI 换脸冒充亲友诈骗": "AI换脸冒充熟人诈骗",
    "ai换脸冒充亲友诈骗": "AI换脸冒充熟人诈骗",
    "两卡出租出借诈骗": "两卡出租出借与跑分诈骗",
    "跑腿取现/洗钱工具人风险": "两卡出租出借与跑分诈骗",
    "虚假贷款诈骗": "网络贷款诈骗",
    "虚假网络贷款诈骗": "网络贷款诈骗",
    "冒充老师收费诈骗": "冒充老师辅导员收费诈骗",
    "冒充领导/熟人诈骗": "冒充领导或熟人借钱诈骗",
    "冒充熟人诈骗": "冒充领导或熟人借钱诈骗",
    "二手票务交易诈骗": "校园二手/票务交易诈骗",
    "奖助学金/补贴诈骗": "奖助学金/学费退费诈骗",
    "机票退改签诈骗": "机票火车票退改签诈骗",
    "租房押金诈骗": "租房合租押金诈骗",
    "裸聊敲诈诈骗": "裸聊敲诈勒索诈骗",
    "婚恋/交友诈骗": "情感交友诱导投资诈骗",
    "杀猪盘诈骗": "情感交友诱导投资诈骗",
    "假冒证券公司投资诈骗": "虚假投资理财诈骗",
    "虚假购物/服务诈骗": "虚假购物服务诈骗",
    "冒充电商物流客服诈骗": "冒充客服诈骗",
    "虚假招聘/实习诈骗": "求职实习招聘诈骗",
}

EXTRA_CANONICAL_TYPES: List[Dict[str, Any]] = [
    {
        "fraud_type_id": "scam_fake_shopping_service",
        "standard_name": "虚假购物服务诈骗",
        "aliases": ["虚假购物服务诈骗", "虚假购物/服务诈骗", "虚假购物", "虚假服务", "低价购物", "私下付款"],
        "parent_category": "交易服务类",
        "runtime_enabled": True,
        "education_enabled": False,
        "source_refs": ["local:legacy_runtime_knowledge"],
    }
]


DOMAIN_BY_NAME_KEYWORDS: List[tuple[str, str]] = [
    ("投资|贷款|征信|两卡|跑分|虚拟货币|医保|洗钱", "金融资金类"),
    ("冒充|AI换脸|公检法|客服|老师|领导|熟人", "身份冒充类"),
    ("刷单|购物|票务|租房|直播|中奖|游戏", "交易服务类"),
    ("求职|奖助学金|考试|校园", "校园与求职类"),
    ("钓鱼|验证码|屏幕共享|远程控制", "账号与技术攻击类"),
    ("跨境|裸聊|养老|民族资产|情感", "复合场景类"),
]


def normalize_label(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[\s　·/／\\|_-]+", "", text)
    return text


def _load_scam_types() -> List[Dict[str, Any]]:
    if not SCAM_TYPES_PATH.exists():
        return []
    data = json.loads(SCAM_TYPES_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def _domain_for_name(name: str) -> str:
    for pattern, domain in DOMAIN_BY_NAME_KEYWORDS:
        if re.search(pattern, name):
            return domain
    return "其他反诈场景"


@lru_cache(maxsize=1)
def fraud_type_registry() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    canonical_by_name = {
        str(item.get("name") or ""): str(item.get("scam_id") or "")
        for item in _load_scam_types()
        if item.get("name") and item.get("scam_id")
    }
    reverse_aliases: Dict[str, List[str]] = {}
    for alias, canonical_name in CANONICAL_NAME_ALIASES.items():
        reverse_aliases.setdefault(canonical_name, []).append(alias)

    for item in _load_scam_types():
        scam_id = str(item.get("scam_id") or "").strip()
        name = str(item.get("name") or "").strip()
        if not scam_id or not name:
            continue
        aliases = sorted(
            {
                name,
                scam_id,
                *(str(value).strip() for value in item.get("aliases") or [] if str(value).strip()),
                *reverse_aliases.get(name, []),
            }
        )
        rows.append(
            {
                "fraud_type_id": scam_id,
                "standard_name": name,
                "aliases": aliases,
                "parent_category": _domain_for_name(name),
                "runtime_enabled": True,
                "education_enabled": True,
                "source_refs": item.get("source_refs") or [],
            }
        )

    for extra in EXTRA_CANONICAL_TYPES:
        if any(row["fraud_type_id"] == extra["fraud_type_id"] for row in rows):
            continue
        rows.append(
            {
                **extra,
                "aliases": sorted({extra["standard_name"], extra["fraud_type_id"], *extra.get("aliases", [])}),
            }
        )

    # Keep aliases whose canonical target exists even if the source JSON omits
    # the display variant.  This protects game-level and report-intel imports.
    known_ids = {row["fraud_type_id"] for row in rows}
    for alias, canonical_name in CANONICAL_NAME_ALIASES.items():
        fraud_type_id = canonical_by_name.get(canonical_name)
        if not fraud_type_id or fraud_type_id not in known_ids:
            continue
        for row in rows:
            if row["fraud_type_id"] == fraud_type_id and alias not in row["aliases"]:
                row["aliases"].append(alias)
                row["aliases"].sort()
                break

    return rows


@lru_cache(maxsize=1)
def _alias_index() -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for row in fraud_type_registry():
        values: Iterable[str] = [row["fraud_type_id"], row["standard_name"], *row.get("aliases", [])]
        for value in values:
            normalized = normalize_label(value)
            if normalized:
                index[normalized] = row
    return index


def resolve_fraud_type(value: Any) -> Optional[Dict[str, Any]]:
    text = str(value or "").strip()
    if not text:
        return None
    return _alias_index().get(normalize_label(text))


def fraud_type_id_for(value: Any) -> str:
    row = resolve_fraud_type(value)
    return str(row.get("fraud_type_id") or "") if row else ""


def standard_name_for(value: Any) -> str:
    row = resolve_fraud_type(value)
    return str(row.get("standard_name") or "") if row else str(value or "").strip()


def fraud_type_metadata(value: Any) -> Dict[str, Any]:
    """Return one stable, serialisable taxonomy record for a runtime label.

    Runtime callers historically exchanged display names such as ``杀猪盘诈骗``
    or ``冒充熟人诈骗``.  The registry is now the source of truth while those
    labels remain accepted as aliases.  Unknown labels are represented without
    inventing an ID so callers can still surface the original evidence.
    """
    row = resolve_fraud_type(value)
    if not row:
        return {
            "fraud_type_id": "",
            "primary_type": str(value or "").strip(),
            "standard_name": str(value or "").strip(),
            "parent_category": "",
            "aliases": [],
            "known": False,
        }
    return {
        "fraud_type_id": str(row.get("fraud_type_id") or ""),
        "primary_type": str(row.get("standard_name") or ""),
        "standard_name": str(row.get("standard_name") or ""),
        "parent_category": str(row.get("parent_category") or ""),
        "aliases": list(row.get("aliases") or []),
        "known": True,
    }


def canonicalize_fraud_types(values: Iterable[Any], *, limit: int = 8) -> List[Dict[str, Any]]:
    """Deduplicate candidate labels by stable ID while retaining raw aliases."""
    result: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        metadata = fraud_type_metadata(value)
        key = metadata["fraud_type_id"] or normalize_label(metadata["primary_type"])
        if not key or key in seen:
            continue
        seen.add(key)
        result.append({**metadata, "raw_label": str(value or "").strip()})
        if len(result) >= limit:
            break
    return result


def canonical_type_name(value: Any) -> str:
    """Return the registry display name, preserving unknown labels."""
    return fraud_type_metadata(value)["primary_type"]
