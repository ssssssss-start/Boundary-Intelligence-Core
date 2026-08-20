import os
from typing import Any, Dict, List

from pymilvus import DataType

from app.clients.milvus_utils import get_milvus_client
from app.conf.milvus_config import milvus_config
from app.core.logger import logger
from app.import_process.agent.state import ImportGraphState
from app.utils.normalize_sparse_vector import normalize_sparse_vector
from app.utils.task_utils import add_done_task, add_running_task


NODE_NAME = "node_import_fraud_knowledge_milvus"
DEFAULT_COLLECTION_NAME = "anti_fraud_knowledge"


def _collection_name(state: ImportGraphState) -> str:
    return (
        state.get("collection_name")
        or os.getenv("ANTI_FRAUD_COLLECTION")
        or os.getenv("FRAUD_KNOWLEDGE_COLLECTION")
        or milvus_config.anti_fraud_collection
        or DEFAULT_COLLECTION_NAME
    )


def _create_collection(client, collection_name: str, vector_dimension: int) -> None:
    schema = client.create_schema(auto_id=True, enable_dynamic_field=False)
    schema.add_field(field_name="knowledge_pk", datatype=DataType.INT64, is_primary=True, auto_id=True)
    schema.add_field(field_name="knowledge_id", datatype=DataType.VARCHAR, max_length=128)
    schema.add_field(field_name="knowledge_type", datatype=DataType.VARCHAR, max_length=64)
    schema.add_field(field_name="fraud_type", datatype=DataType.VARCHAR, max_length=128)
    schema.add_field(field_name="title", datatype=DataType.VARCHAR, max_length=1024)
    schema.add_field(field_name="summary", datatype=DataType.VARCHAR, max_length=4096)
    schema.add_field(field_name="risk_tags_text", datatype=DataType.VARCHAR, max_length=2048)
    schema.add_field(field_name="priority", datatype=DataType.INT64)
    schema.add_field(field_name="sparse_vector", datatype=DataType.SPARSE_FLOAT_VECTOR)
    schema.add_field(field_name="dense_vector", datatype=DataType.FLOAT_VECTOR, dim=vector_dimension)

    index_params = client.prepare_index_params()
    index_params.add_index(
        field_name="dense_vector",
        index_name="dense_vector_index",
        index_type="AUTOINDEX",
        metric_type="COSINE",
    )
    index_params.add_index(
        field_name="sparse_vector",
        index_name="sparse_vector_index",
        index_type="SPARSE_INVERTED_INDEX",
        metric_type="IP",
    )

    client.create_collection(collection_name=collection_name, schema=schema, index_params=index_params)


def _to_milvus_rows(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    fields = [
        "knowledge_id",
        "knowledge_type",
        "fraud_type",
        "title",
        "summary",
        "risk_tags_text",
        "priority",
        "dense_vector",
        "sparse_vector",
    ]
    for item in records:
        row = {field: item.get(field, "") for field in fields}
        row["sparse_vector"] = normalize_sparse_vector(row["sparse_vector"])
        rows.append(row)
    return rows


def node_import_fraud_knowledge_milvus(state: ImportGraphState) -> ImportGraphState:
    task_id = state.get("task_id", "")
    if task_id:
        add_running_task(task_id, NODE_NAME)
    logger.info("开始导入反诈知识到 Milvus")

    records = state.get("valid_fraud_knowledge") or []
    if not records:
        raise ValueError("没有可导入 Milvus 的反诈知识记录")
    if "dense_vector" not in records[0]:
        raise ValueError("反诈知识缺少 dense_vector，请先执行向量化节点")

    collection_name = _collection_name(state)
    vector_dimension = len(records[0]["dense_vector"])
    client = get_milvus_client()
    if client is None:
        raise RuntimeError("Milvus 客户端初始化失败")

    # MVP 数据量小，采用全量重建，避免重复导入和脏数据残留。
    if client.has_collection(collection_name=collection_name):
        logger.info(f"Milvus 集合 {collection_name} 已存在，开始删除并重建")
        client.drop_collection(collection_name=collection_name)

    _create_collection(client, collection_name, vector_dimension)
    rows = _to_milvus_rows(records)
    insert_result = client.insert(collection_name=collection_name, data=rows)
    imported_count = len(rows)

    state["collection_name"] = collection_name
    state["imported_count"] = imported_count
    logger.info(f"反诈知识导入完成，集合 {collection_name}，数量 {imported_count}，结果：{insert_result}")

    if task_id:
        add_done_task(task_id, NODE_NAME)
    return state
