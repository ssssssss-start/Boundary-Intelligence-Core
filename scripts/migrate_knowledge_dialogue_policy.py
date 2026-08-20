"""Import knowledge dialogue teaching policy into MongoDB.

Run:
    python scripts/migrate_knowledge_dialogue_policy.py

The runtime can fall back to data/knowledge/knowledge_dialogue_policy.json, but
Mongo keeps the teaching policy editable and indexable for production use.
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


POLICY_PATH = ROOT / "data" / "knowledge" / "knowledge_dialogue_policy.json"


def _load_rows() -> List[Dict[str, Any]]:
    data = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{POLICY_PATH} 顶层必须是数组")
    rows = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if not item.get("policy_id"):
            raise ValueError(f"存在缺少 policy_id 的策略：{item}")
        rows.append(item)
    return rows


def main() -> int:
    tool = get_business_mongo_tool()
    collection = tool.db["knowledge_dialogue_policy"]
    rows = _load_rows()
    now = datetime.now().isoformat(timespec="seconds")
    ops = []
    for row in rows:
        doc = dict(row)
        doc.pop("_id", None)
        doc["source"] = str(POLICY_PATH.relative_to(ROOT)).replace("\\", "/")
        doc["updated_at"] = now
        doc.setdefault("created_at", now)
        ops.append(UpdateOne({"policy_id": doc["policy_id"]}, {"$set": doc}, upsert=True))
    if ops:
        result = collection.bulk_write(ops, ordered=True)
        count = int(result.upserted_count + result.modified_count + result.matched_count)
    else:
        count = 0
    print(json.dumps({"collection": "knowledge_dialogue_policy", "upserted_or_matched": count}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
