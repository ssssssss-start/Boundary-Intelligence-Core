from typing import Any, Dict, List

from app.anti_fraud.schema import build_embedding_text
from app.core.logger import logger
from app.import_process.agent.state import ImportGraphState
from app.utils.task_utils import add_done_task, add_running_task


NODE_NAME = "node_build_embedding_text"


def node_build_embedding_text(state: ImportGraphState) -> ImportGraphState:
    task_id = state.get("task_id", "")
    if task_id:
        add_running_task(task_id, NODE_NAME)
    logger.info("开始生成反诈知识 embedding_text")

    records = state.get("valid_fraud_knowledge") or []
    output: List[Dict[str, Any]] = []

    for item in records:
        item_copy = dict(item)
        embedding_text = build_embedding_text(item_copy)
        if not embedding_text:
            raise ValueError(f"知识记录 embedding_text 为空：{item_copy.get('knowledge_id')}")
        item_copy["embedding_text"] = embedding_text
        item_copy["risk_tags_text"] = ",".join(item_copy.get("risk_tags") or [])
        item_copy["applicable_routes_text"] = ",".join(item_copy.get("applicable_routes") or [])
        item_copy["case_types_text"] = ",".join(str(value) for value in item_copy.get("applicable_case_types") or [])
        item_copy["intervention_goals_text"] = ",".join(item_copy.get("intervention_goals") or [])
        output.append(item_copy)

    state["valid_fraud_knowledge"] = output

    logger.info(f"embedding_text 生成完成，共 {len(output)} 条")
    if task_id:
        add_done_task(task_id, NODE_NAME)
    return state
