from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from bson import json_util

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def _write_json(path: Path, value: Any, *, bson: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if bson:
        path.write_text(json_util.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def export_mongo(snapshot_dir: Path) -> Dict[str, Any]:
    from app.clients.mongo_business_utils import get_business_mongo_tool

    tool = get_business_mongo_tool()
    mongo_dir = snapshot_dir / "mongo"
    collections: List[Dict[str, Any]] = []
    for name in sorted(tool.db.list_collection_names()):
        docs = list(tool.db[name].find({}))
        indexes = []
        try:
            for index in tool.db[name].list_indexes():
                index_doc = dict(index)
                index_doc.pop("v", None)
                indexes.append(index_doc)
        except Exception:
            indexes = []
        _write_json(
            mongo_dir / f"{name}.json",
            {
                "collection": name,
                "count": len(docs),
                "indexes": indexes,
                "documents": docs,
            },
            bson=True,
        )
        collections.append({"name": name, "count": len(docs), "file": f"mongo/{name}.json"})
    return {"db_name": tool.db.name, "collections": collections}


def _milvus_rows(client: Any, collection_name: str, row_count: int) -> List[Dict[str, Any]]:
    if row_count <= 0:
        return []
    # Current collections are small. Keep the exporter simple and explicit.
    rows = client.query(
        collection_name=collection_name,
        filter="",
        output_fields=["*"],
        limit=max(1, row_count),
    )
    cleaned: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item.pop("knowledge_pk", None)
        cleaned.append(item)
    return cleaned


def export_milvus(snapshot_dir: Path) -> Dict[str, Any]:
    from app.clients.milvus_utils import get_milvus_client

    client = get_milvus_client()
    if client is None:
        return {"available": False, "collections": [], "error": "Milvus client initialization failed"}

    milvus_dir = snapshot_dir / "milvus"
    collections: List[Dict[str, Any]] = []
    for name in sorted(client.list_collections()):
        stats = client.get_collection_stats(name)
        row_count = int(stats.get("row_count", 0) or 0)
        rows = _milvus_rows(client, name, row_count)
        vector_dimension = len(rows[0].get("dense_vector") or []) if rows else 1024
        payload = {
            "collection": name,
            "count": len(rows),
            "vector_dimension": vector_dimension,
            "rows": rows,
        }
        _write_json(milvus_dir / f"{name}.json", payload)
        collections.append(
            {
                "name": name,
                "count": len(rows),
                "vector_dimension": vector_dimension,
                "file": f"milvus/{name}.json",
            }
        )
    return {"available": True, "collections": collections}


def main() -> None:
    parser = argparse.ArgumentParser(description="Export MongoDB and Milvus data for delivery package.")
    parser.add_argument("--out", default="database_snapshot", help="Snapshot output directory.")
    args = parser.parse_args()

    snapshot_dir = Path(args.out).resolve()
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    manifest: Dict[str, Any] = {
        "exported_at": datetime.now().isoformat(timespec="seconds"),
        "mongo": export_mongo(snapshot_dir),
        "milvus": export_milvus(snapshot_dir),
    }
    _write_json(snapshot_dir / "manifest.json", manifest)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
