"""Migrate anti-fraud knowledge to the LLM-first semantic risk workflow.

Run:
    python scripts/migrate_semantic_risk_knowledge.py

The migration keeps structured rules and knowledge, removes legacy regex
fields from stored feature documents, imports semantic policy records, and
marks old user-visible template collections as deprecated.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from pymongo import UpdateOne


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.clients.mongo_business_utils import get_business_mongo_tool  # noqa: E402


KNOWLEDGE_DIR = ROOT / "data" / "knowledge"
STRUCTURED_COLLECTIONS: Dict[str, Tuple[str, str]] = {
    "scam_types": ("scam_types.json", "scam_id"),
    "scam_features": ("scam_features.json", "feature_id"),
    "risk_rules": ("risk_rules.json", "rule_id"),
    "semantic_risk_policy": ("semantic_risk_policy.json", "policy_id"),
    "knowledge_dialogue_policy": ("knowledge_dialogue_policy.json", "policy_id"),
    "prevention_advice": ("prevention_advice.json", "advice_id"),
    "typical_cases": ("typical_cases.json", "case_id"),
    "law_clauses": ("law_clauses.json", "law_id"),
    "report_guides": ("report_guides.json", "guide_id"),
    "stage_definitions": ("stage_definitions.json", "stage_id"),
    "evidence_guides": ("evidence_guides.json", "guide_id"),
}


def _strip_legacy_regex(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_legacy_regex(item)
            for key, item in value.items()
            if key not in {"regex_patterns", "advice_template_id"}
        }
    if isinstance(value, list):
        return [_strip_legacy_regex(item) for item in value]
    return value


def _load_rows(file_name: str) -> List[Dict[str, Any]]:
    path = KNOWLEDGE_DIR / file_name
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} 顶层必须是数组")
    return [_strip_legacy_regex(item) for item in data if isinstance(item, dict)]


def _upsert_collection(collection, rows: List[Dict[str, Any]], unique_field: str, source: str) -> int:
    if not rows:
        return 0
    now = datetime.now().isoformat(timespec="seconds")
    ops = []
    for row in rows:
        unique_value = row.get(unique_field)
        if not unique_value:
            continue
        doc = dict(row)
        doc.pop("_id", None)
        if collection.name == "scam_types" and doc.get("scam_id"):
            doc.setdefault("scam_type_id", doc["scam_id"])
        if collection.name == "scam_features" and doc.get("scam_id"):
            doc.setdefault("scam_type_id", doc["scam_id"])
        doc["source"] = source
        doc["updated_at"] = now
        doc.setdefault("created_at", now)
        query = {unique_field: unique_value}
        if collection.name == "scam_types" and unique_field == "scam_id":
            query = {"$or": [{"scam_id": unique_value}, {"scam_type_id": unique_value}]}
        ops.append(UpdateOne(query, {"$set": doc}, upsert=True))
    if not ops:
        return 0
    result = collection.bulk_write(ops, ordered=True)
    return int(result.upserted_count + result.modified_count + result.matched_count)


def _mark_legacy_templates_deprecated(db) -> Dict[str, int]:
    now = datetime.now().isoformat(timespec="seconds")
    marker = {
        "deprecated": True,
        "runtime_replaced_by": "semantic_risk_agent",
        "deprecated_reason": "用户可见劝阻话术改为 LLM 实时生成，模板库仅保留历史兼容。",
        "updated_at": now,
    }
    counts: Dict[str, int] = {}
    for collection_name in ["dissuasion_templates", "advice_templates"]:
        result = db[collection_name].update_many({}, {"$set": marker})
        counts[collection_name] = int(result.modified_count)
    return counts


def _repair_legacy_alias_ids(db) -> None:
    for doc in list(
        db["scam_types"].find(
            {"scam_id": {"$exists": True}, "$or": [{"scam_type_id": {"$exists": False}}, {"scam_type_id": None}]},
            {"_id": 1, "scam_id": 1},
        )
    ):
        existing = db["scam_types"].find_one(
            {"_id": {"$ne": doc["_id"]}, "scam_type_id": doc["scam_id"]},
            {"_id": 1},
        )
        if existing:
            db["scam_types"].delete_one({"_id": doc["_id"]})
        else:
            db["scam_types"].update_one({"_id": doc["_id"]}, {"$set": {"scam_type_id": doc["scam_id"]}})

    for doc in db["scam_features"].find(
        {"scam_id": {"$exists": True}, "$or": [{"scam_type_id": {"$exists": False}}, {"scam_type_id": None}]},
        {"_id": 1, "scam_id": 1},
    ):
        db["scam_features"].update_one({"_id": doc["_id"]}, {"$set": {"scam_type_id": doc["scam_id"]}})


def main() -> int:
    tool = get_business_mongo_tool()
    _repair_legacy_alias_ids(tool.db)
    total = 0
    for collection_name, (file_name, unique_field) in STRUCTURED_COLLECTIONS.items():
        rows = _load_rows(file_name)
        count = _upsert_collection(
            tool.db[collection_name],
            rows,
            unique_field,
            source=f"semantic_migration:{file_name}",
        )
        total += count
        print(f"{collection_name}: {count} 条 upsert")

    unset_result = tool.db["scam_features"].update_many(
        {"regex_patterns": {"$exists": True}},
        {
            "$unset": {"regex_patterns": ""},
            "$set": {
                "updated_at": datetime.now().isoformat(timespec="seconds"),
                "regex_migrated_to_semantic_policy": True,
            },
        },
    )
    print(f"scam_features: 移除 Mongo regex_patterns {unset_result.modified_count} 条")

    legacy_counts = _mark_legacy_templates_deprecated(tool.db)
    for collection_name, count in legacy_counts.items():
        print(f"{collection_name}: deprecated 标记 {count} 条")

    print(f"语义风险知识迁移完成，总计 {total} 条结构化知识 upsert。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
