from typing import Any, Dict, List
from typing_extensions import TypedDict


class ImportGraphState(TypedDict, total=False):
    """
    反诈知识结构化导入工作流状态。

    MVP 导入链路：
    anti_fraud_knowledge_v2.json
    → 结构校验
    → 写入 MongoDB anti_fraud_knowledge
    → 生成 embedding_text
    → BGE-M3 向量化
    → 写入 Milvus anti_fraud_knowledge
    """

    task_id: str
    knowledge_file_path: str
    collection_name: str

    fraud_knowledge: List[Dict[str, Any]]
    valid_fraud_knowledge: List[Dict[str, Any]]
    invalid_fraud_knowledge: List[Dict[str, Any]]

    total_count: int
    valid_count: int
    invalid_count: int
    mongo_imported_count: int
    imported_count: int

    warnings: List[str]
    errors: List[str]


def create_default_state(**kwargs) -> ImportGraphState:
    state: ImportGraphState = {
        "task_id": "",
        "knowledge_file_path": "",
        "collection_name": "anti_fraud_knowledge",
        "fraud_knowledge": [],
        "valid_fraud_knowledge": [],
        "invalid_fraud_knowledge": [],
        "total_count": 0,
        "valid_count": 0,
        "invalid_count": 0,
        "mongo_imported_count": 0,
        "imported_count": 0,
        "warnings": [],
        "errors": [],
    }
    state.update(kwargs)
    return state


def get_default_state(**kwargs) -> ImportGraphState:
    """兼容旧导入服务调用名。"""
    return create_default_state(**kwargs)
