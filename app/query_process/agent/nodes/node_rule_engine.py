"""规则引擎节点。

规则引擎是系统的确定性风险判断层。它不依赖 LLM 直接裁决，
而是根据标准化风险特征、诈骗类型和阶段去匹配可配置规则。

规则来源优先级：
1. MongoDB risk_rules（运行时可扩展，便于后台管理）。
2. JSON 种子文件（Mongo 不可用或未初始化时兜底）。
"""

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Set

from app.anti_fraud.schema import RISK_FEATURE_ALIASES, RISK_FEATURES, normalize_risk_features
from app.clients.mongo_business_utils import get_enabled_risk_rules, seed_risk_rules_from_json
from app.core.logger import logger
from app.query_process.agent.nodes.common import append_warning, ensure_list, mark_node_done, mark_node_start


NODE_NAME = "node_rule_engine"


def _default_intervention_goal(rule: Dict[str, Any]) -> str:
    """根据规则文本推断默认干预目标。

    老规则可能没有 intervention_goal 字段。这里补一个保守默认值，
    保证后续干预决策和答辩展示字段完整。
    """
    text = " ".join([
        str(rule.get("fraud_type", "")),
        str(rule.get("rule_name", "")),
        str(rule.get("suggested_action", "")),
    ])
    if any(word in text for word in ["验证码", "动态码", "短信码"]):
        return "stop_code_leak"
    if any(word in text for word in ["屏幕共享", "远程", "会议"]):
        return "stop_screen_share"
    if any(word in text for word in ["下载", "APP", "App", "app"]):
        return "stop_app_install"
    if any(word in text for word in ["报警", "110", "止损"]):
        return "call_police"
    if any(word in text for word in ["转账", "付款", "垫付", "充值", "缴费", "补单"]):
        return "stop_transfer"
    return "ask_clarification"


def _normalize_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    """统一 Mongo/JSON 规则字段。

    兼容 score 与 risk_score，补齐 enabled、intervention_goal 等运行时字段。
    """
    doc = dict(rule)
    score = int(doc.get("risk_score", doc.get("score", 0)) or 0)
    doc["risk_score"] = score
    doc.setdefault("score", score)
    doc.setdefault("enabled", True)
    doc.setdefault("intervention_goal", _default_intervention_goal(doc))
    doc.setdefault("explanation", "")
    doc.setdefault("suggested_action", "")
    return doc


@lru_cache(maxsize=1)
def _load_rules() -> List[Dict[str, Any]]:
    """加载风险规则，优先 Mongo，失败时降级 JSON。"""
    rules_path = Path(__file__).resolve().parents[2] / "rules" / "anti_fraud_rules.json"
    try:
        mongo_rules = get_enabled_risk_rules()
        if mongo_rules:
            return [_normalize_rule(rule) for rule in mongo_rules]
        if rules_path.exists():
            seed_risk_rules_from_json(rules_path)
            mongo_rules = get_enabled_risk_rules()
            if mongo_rules:
                return [_normalize_rule(rule) for rule in mongo_rules]
    except Exception as e:
        logger.warning(f"MongoDB 风险规则读取失败，降级使用 JSON 规则：{e}")

    if not rules_path.exists():
        raise FileNotFoundError(f"反诈规则文件不存在：{rules_path}")

    with rules_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("反诈规则文件顶层必须是 JSON 数组")
    return [_normalize_rule(rule) for rule in data]


def _collect_text(state: Dict[str, Any]) -> str:
    """收集可用于风险特征归一化的文本上下文。"""
    entities = state.get("entities") or {}
    entity_values: List[str] = []
    if isinstance(entities, dict):
        for value in entities.values():
            entity_values.extend(ensure_list(value))
    parts = [
        state.get("original_query", ""),
        state.get("history_text", ""),
        " ".join(ensure_list(state.get("keywords"))),
        " ".join(ensure_list(state.get("risk_features"))),
        " ".join(entity_values),
    ]
    return " ".join(parts)


def _normalize_features(state: Dict[str, Any]) -> Set[str]:
    """把 LLM/兜底抽取的风险特征转换为标准特征集合。"""
    features = normalize_risk_features(ensure_list(state.get("risk_features")), _collect_text(state))
    return set(features)


def _stage_match(rule: Dict[str, Any], stages: List[str]) -> bool:
    """判断规则适用阶段是否与当前疑似阶段相交。"""
    rule_stages = rule.get("stages") or []
    if not rule_stages:
        return True
    if not stages or stages == ["未知"]:
        return True
    return bool(set(rule_stages) & set(stages))


def _validate_rule(rule: Dict[str, Any]) -> None:
    """校验规则结构和条件特征是否合法。"""
    for field in ["rule_id", "rule_name", "fraud_type", "conditions", "risk_level"]:
        if field not in rule:
            raise ValueError(f"规则缺少字段 {field}：{rule}")
    if "risk_score" not in rule and "score" not in rule:
        raise ValueError(f"规则缺少字段 risk_score/score：{rule}")

    conditions = rule.get("conditions") or {}
    for group in ["all", "any"]:
        for feature in conditions.get(group, []) or []:
            if RISK_FEATURE_ALIASES.get(str(feature), str(feature)) not in RISK_FEATURES:
                raise ValueError(f"规则 {rule.get('rule_id')} 使用了非法风险特征：{feature}")


def _rule_score(rule: Dict[str, Any]) -> int:
    """读取规则分数，兼容 risk_score/score 两种字段名。"""
    return int(rule.get("risk_score", rule.get("score", 0)) or 0)


def node_rule_engine(state: Dict[str, Any]) -> Dict[str, Any]:
    """执行规则匹配并写入 matched_rules。

    该节点保留为旧流程兼容入口；实际规则研判统一委托给
    ``ScamRuleEngine``，避免主流程、/risk/check 和旧节点各自维护一套
    匹配逻辑。
    """
    mark_node_start(state, NODE_NAME)
    logger.info("开始执行反诈规则引擎节点")

    if (
        state.get("case_closed")
        or state.get("case_status") == "resolved"
        or state.get("safety_status") in {"prevented", "learning"}
        or int(state.get("case_context_type") or 3) == 3
    ):
        # 场景已关闭或本轮是纯学习时，不再把旧风险特征送入规则引擎。
        state["normalized_risk_features"] = []
        state["matched_rules"] = []
        mark_node_done(state, NODE_NAME)
        return state

    try:
        from app.query_process.services.scam_rule_engine import evaluate_rule_state

        result = evaluate_rule_state(state)
    except Exception as e:
        append_warning(state, f"反诈规则引擎执行失败，规则引擎将返回空命中：{e}")
        state["matched_rules"] = []
        state["normalized_risk_features"] = []
        mark_node_done(state, NODE_NAME)
        return state

    state["rule_engine"] = result
    state["matched_rules"] = result.get("matched_rules", [])
    state["normalized_risk_features"] = result.get("normalized_risk_features", [])
    state["possible_fraud_types"] = result.get("possible_fraud_types", state.get("possible_fraud_types", []))
    state["possible_fraud_stages"] = [result.get("risk_stage", "")] if result.get("risk_stage") else state.get("possible_fraud_stages", [])
    for warning in result.get("warnings", []):
        append_warning(state, warning)
    mark_node_done(state, NODE_NAME)
    return state
