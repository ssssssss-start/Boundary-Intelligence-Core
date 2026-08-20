from app.clients.mongo_business_utils import upsert_anti_fraud_knowledge
from app.core.logger import logger
from app.import_process.agent.state import ImportGraphState
from app.utils.task_utils import add_done_task, add_running_task


NODE_NAME = "node_import_fraud_knowledge_mongo"


def node_import_fraud_knowledge_mongo(state: ImportGraphState) -> ImportGraphState:
    task_id = state.get("task_id", "")
    if task_id:
        add_running_task(task_id, NODE_NAME)
    logger.info("开始导入反诈知识到 MongoDB 业务主库")

    records = state.get("valid_fraud_knowledge") or []
    if not records:
        raise ValueError("没有可导入 MongoDB 的反诈知识记录")

    imported_count = upsert_anti_fraud_knowledge(records, source_file=state.get("knowledge_file_path", ""))
    state["mongo_imported_count"] = imported_count

    logger.info(f"反诈知识导入 MongoDB 完成，数量：{imported_count}")
    if task_id:
        add_done_task(task_id, NODE_NAME)
    return state
