from typing import Any, Dict, List

from app.anti_fraud.schema import (
    FRAUD_TYPES,
    FRAUD_STAGES,
    INTERVENTION_GOALS,
    KNOWLEDGE_TYPES,
    REQUIRED_KNOWLEDGE_FIELDS,
    ROUTES,
    RISK_FEATURES,
    RISK_LEVELS,
)
from app.core.logger import logger
from app.import_process.agent.state import ImportGraphState
from app.utils.task_utils import add_done_task, add_running_task


NODE_NAME = "node_validate_fraud_knowledge"


def _validate_item(item: Dict[str, Any], index: int) -> List[str]:
    errors: List[str] = []
    for field in REQUIRED_KNOWLEDGE_FIELDS:
        value = item.get(field)
        if value is None or value == "" or value == []:
            errors.append(f"第 {index} 条缺少必填字段：{field}")

    knowledge_type = item.get("knowledge_type")
    if knowledge_type and knowledge_type not in KNOWLEDGE_TYPES:
        errors.append(f"第 {index} 条 knowledge_type 非法：{knowledge_type}")

    fraud_type = item.get("fraud_type")
    if fraud_type and fraud_type not in FRAUD_TYPES:
        errors.append(f"第 {index} 条 fraud_type 非法：{fraud_type}")

    fraud_stage = item.get("fraud_stage")
    if fraud_stage and fraud_stage not in FRAUD_STAGES:
        errors.append(f"第 {index} 条 fraud_stage 非法：{fraud_stage}")

    risk_level = item.get("risk_level")
    if risk_level and risk_level not in RISK_LEVELS:
        errors.append(f"第 {index} 条 risk_level 非法：{risk_level}")

    risk_tags = item.get("risk_tags")
    if risk_tags is not None:
        if not isinstance(risk_tags, list):
            errors.append(f"第 {index} 条 risk_tags 必须是数组")
        else:
            invalid_tags = [tag for tag in risk_tags if tag not in RISK_FEATURES]
            if invalid_tags:
                errors.append(f"第 {index} 条 risk_tags 存在非法标签：{invalid_tags}")

    routes = item.get("applicable_routes")
    if routes is not None:
        if not isinstance(routes, list):
            errors.append(f"第 {index} 条 applicable_routes 必须是数组")
        else:
            invalid_routes = [route for route in routes if route not in ROUTES]
            if invalid_routes:
                errors.append(f"第 {index} 条 applicable_routes 存在非法值：{invalid_routes}")

    case_types = item.get("applicable_case_types")
    if case_types is not None:
        if not isinstance(case_types, list):
            errors.append(f"第 {index} 条 applicable_case_types 必须是数组")
        else:
            invalid_case_types = [case_type for case_type in case_types if case_type not in [1, 2, 3]]
            if invalid_case_types:
                errors.append(f"第 {index} 条 applicable_case_types 存在非法值：{invalid_case_types}")

    goals = item.get("intervention_goals")
    if goals is not None:
        if not isinstance(goals, list):
            errors.append(f"第 {index} 条 intervention_goals 必须是数组")
        else:
            invalid_goals = [goal for goal in goals if goal not in INTERVENTION_GOALS]
            if invalid_goals:
                errors.append(f"第 {index} 条 intervention_goals 存在非法值：{invalid_goals}")

    priority = item.get("priority")
    if priority is not None:
        if not isinstance(priority, int):
            errors.append(f"第 {index} 条 priority 必须是整数")
        elif priority < 0 or priority > 100:
            errors.append(f"第 {index} 条 priority 必须在 0 到 100 之间")

    return errors


def node_validate_fraud_knowledge(state: ImportGraphState) -> ImportGraphState:
    task_id = state.get("task_id", "")
    if task_id:
        add_running_task(task_id, NODE_NAME)
    logger.info("开始校验反诈知识结构和枚举")

    records = state.get("fraud_knowledge") or []
    if not isinstance(records, list):
        raise ValueError("state.fraud_knowledge 必须是列表")

    valid: List[Dict[str, Any]] = []
    invalid: List[Dict[str, Any]] = []
    all_errors: List[str] = []
    seen_ids = set()

    for index, item in enumerate(records, start=1):
        item_errors: List[str] = []
        if not isinstance(item, dict):
            item_errors.append(f"第 {index} 条必须是对象")
            item = {"raw": item}
        else:
            item_errors.extend(_validate_item(item, index))
            knowledge_id = item.get("knowledge_id")
            if knowledge_id in seen_ids:
                item_errors.append(f"第 {index} 条 knowledge_id 重复：{knowledge_id}")
            seen_ids.add(knowledge_id)

        if item_errors:
            invalid.append({"index": index, "item": item, "errors": item_errors})
            all_errors.extend(item_errors)
        else:
            valid.append(item)

    state["valid_fraud_knowledge"] = valid
    state["invalid_fraud_knowledge"] = invalid
    state["valid_count"] = len(valid)
    state["invalid_count"] = len(invalid)
    state["errors"] = all_errors

    if invalid:
        raise ValueError("反诈知识数据校验失败：\n" + "\n".join(all_errors[:20]))

    logger.info(f"反诈知识校验通过，有效记录 {len(valid)} 条")
    if task_id:
        add_done_task(task_id, NODE_NAME)
    return state
