"""Import local anti-fraud knowledge JSON seed files into MongoDB.

Run:
    uv run python scripts/import_knowledge_seed.py

MongoDB remains optional for local development. If Mongo is not configured or
unavailable, the runtime automatically falls back to JSON files.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from pymongo import UpdateOne


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.clients.mongo_business_utils import get_business_mongo_tool  # noqa: E402


KNOWLEDGE_DIR = ROOT / "data" / "knowledge"
COLLECTIONS = {
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


def _load_rows(file_name: str) -> List[Dict[str, Any]]:
    path = KNOWLEDGE_DIR / file_name
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} 顶层必须是数组")
    return [item for item in data if isinstance(item, dict)]


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


def _upsert_collection(collection: str, rows: List[Dict[str, Any]], unique_field: str) -> int:
    if not rows:
        return 0
    tool = get_business_mongo_tool()
    now = datetime.now().isoformat(timespec="seconds")
    ops = []
    for row in rows:
        unique_value = row.get(unique_field)
        if not unique_value:
            continue
        doc = _strip_legacy_regex(dict(row))
        doc.pop("_id", None)
        if collection == "scam_types" and doc.get("scam_id"):
            doc.setdefault("scam_type_id", doc["scam_id"])
        if collection == "scam_features" and doc.get("scam_id"):
            doc.setdefault("scam_type_id", doc["scam_id"])
        doc["source"] = "local_knowledge_seed"
        doc["updated_at"] = now
        doc.setdefault("created_at", now)
        query = {unique_field: unique_value}
        if collection == "scam_types" and unique_field == "scam_id":
            query = {"$or": [{"scam_id": unique_value}, {"scam_type_id": unique_value}]}
        ops.append(UpdateOne(query, {"$set": doc}, upsert=True))
    if not ops:
        return 0
    result = tool.db[collection].bulk_write(ops, ordered=False)
    return int(result.upserted_count + result.modified_count + result.matched_count)


def main() -> int:
    try:
        get_business_mongo_tool()
    except Exception as exc:
        print(f"MongoDB 不可用，未导入；运行时会使用本地 JSON 降级：{exc}")
        return 0

    total = 0
    for collection, (file_name, unique_field) in COLLECTIONS.items():
        rows = _load_rows(file_name)
        count = _upsert_collection(collection, rows, unique_field)
        total += count
        print(f"{collection}: {count} 条 upsert")
    print(f"知识库导入完成，总计 {total} 条 upsert。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
