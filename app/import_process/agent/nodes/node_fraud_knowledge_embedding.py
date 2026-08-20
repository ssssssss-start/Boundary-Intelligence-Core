from typing import Any, Dict, List

from app.core.logger import logger
from app.import_process.agent.state import ImportGraphState
from app.lm.embedding_utils import generate_embeddings
from app.utils.task_utils import add_done_task, add_running_task


NODE_NAME = "node_fraud_knowledge_embedding"


def node_fraud_knowledge_embedding(state: ImportGraphState) -> ImportGraphState:
    task_id = state.get("task_id", "")
    if task_id:
        add_running_task(task_id, NODE_NAME)
    logger.info("开始为反诈知识生成 BGE-M3 向量")

    records = state.get("valid_fraud_knowledge") or []
    if not records:
        raise ValueError("没有可向量化的反诈知识记录")

    texts = [item.get("embedding_text", "") for item in records]
    if any(not text for text in texts):
        raise ValueError("存在 embedding_text 为空的反诈知识记录")

    vectors = generate_embeddings(texts)
    dense_vectors = vectors.get("dense") or []
    sparse_vectors = vectors.get("sparse") or []
    if len(dense_vectors) != len(records) or len(sparse_vectors) != len(records):
        raise ValueError("向量数量与知识记录数量不一致")

    output: List[Dict[str, Any]] = []
    for index, item in enumerate(records):
        item_copy = dict(item)
        item_copy["dense_vector"] = dense_vectors[index]
        item_copy["sparse_vector"] = sparse_vectors[index]
        output.append(item_copy)

    state["valid_fraud_knowledge"] = output

    logger.info(f"反诈知识向量生成完成，共 {len(output)} 条")
    if task_id:
        add_done_task(task_id, NODE_NAME)
    return state
