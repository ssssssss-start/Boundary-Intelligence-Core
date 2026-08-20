from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

from bson import json_util

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def _chunks(items: List[Dict[str, Any]], size: int = 500) -> Iterable[List[Dict[str, Any]]]:
    for index in range(0, len(items), size):
        yield items[index:index + size]


def restore_mongo(snapshot_dir: Path, *, drop: bool) -> Dict[str, Any]:
    from app.clients.mongo_business_utils import get_business_mongo_tool, init_business_collections

    tool = get_business_mongo_tool()
    mongo_dir = snapshot_dir / "mongo"
    restored: List[Dict[str, Any]] = []
    for path in sorted(mongo_dir.glob("*.json")):
        payload = json_util.loads(path.read_text(encoding="utf-8"))
        name = str(payload.get("collection") or path.stem)
        docs = list(payload.get("documents") or [])
        collection = tool.db[name]
        if drop:
            collection.drop()
        if docs:
            for batch in _chunks(docs):
                collection.insert_many(batch, ordered=False)
        restored.append({"name": name, "count": len(docs)})
    init_business_collections()
    return {"db_name": tool.db.name, "collections": restored}


def restore_milvus(snapshot_dir: Path, *, drop: bool) -> Dict[str, Any]:
    from app.clients.milvus_utils import get_milvus_client
    from app.import_process.agent.nodes.node_import_fraud_knowledge_milvus import _create_collection, _to_milvus_rows

    client = get_milvus_client()
    if client is None:
        raise RuntimeError("Milvus client initialization failed")

    milvus_dir = snapshot_dir / "milvus"
    restored: List[Dict[str, Any]] = []
    for path in sorted(milvus_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        name = str(payload.get("collection") or path.stem)
        rows = list(payload.get("rows") or [])
        vector_dimension = int(payload.get("vector_dimension") or (len(rows[0].get("dense_vector") or []) if rows else 1024))
        if client.has_collection(name):
            if drop:
                client.drop_collection(name)
            else:
                restored.append({"name": name, "count": 0, "skipped": "collection already exists"})
                continue
        _create_collection(client, name, vector_dimension)
        insert_rows = _to_milvus_rows(rows)
        for batch in _chunks(insert_rows, size=100):
            client.insert(collection_name=name, data=batch)
        restored.append({"name": name, "count": len(insert_rows), "vector_dimension": vector_dimension})
    return {"collections": restored}


def main() -> None:
    parser = argparse.ArgumentParser(description="Restore delivery package MongoDB and Milvus snapshots.")
    parser.add_argument("--snapshot", default="database_snapshot", help="Snapshot directory.")
    parser.add_argument("--no-drop", action="store_true", help="Do not drop existing collections before restore.")
    parser.add_argument("--skip-mongo", action="store_true")
    parser.add_argument("--skip-milvus", action="store_true")
    args = parser.parse_args()

    snapshot_dir = Path(args.snapshot).resolve()
    if not snapshot_dir.exists():
        raise FileNotFoundError(f"Snapshot directory not found: {snapshot_dir}")
    drop = not args.no_drop
    result: Dict[str, Any] = {"snapshot": str(snapshot_dir), "drop_existing": drop}
    if not args.skip_mongo:
        result["mongo"] = restore_mongo(snapshot_dir, drop=drop)
    if not args.skip_milvus:
        result["milvus"] = restore_milvus(snapshot_dir, drop=drop)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
