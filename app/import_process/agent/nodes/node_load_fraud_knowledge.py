import json
from pathlib import Path
from typing import Any, Dict

from app.core.logger import logger
from app.import_process.agent.state import ImportGraphState
from app.utils.task_utils import add_done_task, add_running_task


NODE_NAME = "node_load_fraud_knowledge"


def _default_knowledge_path() -> Path:
    project_root = Path(__file__).resolve().parents[4]
    return project_root / "data" / "anti_fraud_knowledge_v2.json"


def node_load_fraud_knowledge(state: ImportGraphState) -> ImportGraphState:
    task_id = state.get("task_id", "")
    if task_id:
        add_running_task(task_id, NODE_NAME)
    logger.info("开始读取反诈结构化知识数据")

    input_path = (
        state.get("knowledge_file_path")
        or state.get("file_path")
        or state.get("md_path")
        or state.get("path")
        or _default_knowledge_path()
    )
    file_path = Path(input_path).resolve()
    if not file_path.exists():
        raise FileNotFoundError(f"反诈知识数据文件不存在：{file_path}")

    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("反诈知识数据文件顶层必须是 JSON 数组")

    state["knowledge_file_path"] = str(file_path)
    state["fraud_knowledge"] = data
    state["total_count"] = len(data)

    logger.info(f"反诈知识数据读取完成，共 {len(data)} 条")
    if task_id:
        add_done_task(task_id, NODE_NAME)
    return state
