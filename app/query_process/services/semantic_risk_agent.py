"""LLM-driven realtime anti-fraud risk agent.

The user-visible risk conversation now follows this contract:
- LLM extracts scene facts and missing facts from the dialogue.
- Structured knowledge and rules decide the risk boundary.
- LLM writes the final response from facts, knowledge, and decision constraints.

No state-machine question templates or regex slot-filling are used here.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from langchain_core.messages import HumanMessage, SystemMessage

from app.anti_fraud.taxonomy import canonicalize_fraud_types, fraud_type_metadata, fraud_type_id_for, standard_name_for
from app.clients.mongo_history_utils import save_case_state, save_risk_chat_message
from app.core.logger import logger
from app.lm.lm_utils import get_llm_client
from app.query_process.agent.nodes.common import extract_json_object, get_message_content
from app.query_process.services.anti_fraud_engine import build_anti_fraud_engine_result
from app.query_process.services.risk_video_card_service import attach_video_cards
from app.utils.sse_utils import SSEEvent, push_to_session
from app.utils.task_utils import set_task_result
from app.utils.timeout_utils import call_with_timeout, env_timeout


TRUE = "true"
FALSE = "false"
UNKNOWN = "unknown"

SEMANTIC_POLICY_COLLECTION = "semantic_risk_policy"

ACTION_LABELS = {
    "stopped_operation": "已停止危险操作",
    "no_more_transfer": "确认不再转账/充值",
    "stopped_contact": "已停止联系或拉黑对方",
    "changed_game_password": "已修改游戏账号密码",
    "checked_account_bindings": "已检查账号绑定/密保",
    "enabled_login_protection": "已开启登录保护或二次验证",
    "preserved_evidence": "已保存聊天、转账等证据",
    "reported_police": "已报警或完成笔录",
    "contacted_game_official_support": "已联系游戏平台官方客服/申诉",
    "contacted_bank_or_payment_platform": "已联系银行或支付平台",
}

CLOSED_CASE_STATUSES = {"prevented", "stop_loss_done", "education_ready", "closed", "observation"}

ASSISTANT_CLOSED_SCENE_TEXT = (
    "我是您的反诈骗小卫士 🛡️\n"
    "专门帮您识破冒充客服、刷单返利、虚假贷款这些骗局。\n"
    "您只要记住：陌生链接别乱点，可疑电话多核实，转账汇款先问我。\n"
    "有什么拿不准的情况，直接发给我，我帮您把关。\n\n"
    "请问您想咨询什么，或者有遇到可疑的事情吗？"
)

ACTION_TO_FACT_KEY = {
    "stopped_operation": "has_stopped_operation",
    "no_more_transfer": "has_stopped_operation",
    "changed_game_password": "has_changed_password_after_exposure",
    "checked_account_bindings": "has_checked_account_bindings",
    "preserved_evidence": "has_preserved_evidence",
    "reported_police": "has_reported_police",
    "contacted_game_official_support": "has_contacted_official_support",
    "contacted_bank_or_payment_platform": "has_contacted_bank_or_payment_platform",
}

GENERIC_SCAM_ALIAS_TERMS = {
    "保证金",
    "解冻费",
    "认证费",
    "税费",
    "手续费",
    "冻结",
    "提现",
    "不能提现",
    "提现失败",
    "账户冻结",
    "平台",
    "app",
    "APP",
    "银行卡",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _knowledge_dir() -> Path:
    return _project_root() / "data" / "knowledge"


@lru_cache(maxsize=16)
def _load_json_collection(name: str) -> List[Dict[str, Any]]:
    path = _knowledge_dir() / f"{name}.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else []


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _text_list(value: Any, limit: int = 10) -> List[str]:
    result: List[str] = []
    for item in _as_list(value):
        text = str(item or "").strip()
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def _tri_bool(value: Any) -> str:
    if value is True:
        return TRUE
    if value is False:
        return FALSE
    text = str(value or "").strip().lower()
    if text in {"true", "yes", "y", "是", "已", "已经", "likely_true", "可能是", "疑似是"}:
        return TRUE
    if text in {"false", "no", "n", "否", "没有", "没", "未", "likely_false", "可能不是"}:
        return FALSE
    return UNKNOWN


def _number(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _compact_text(text: str) -> str:
    return re.sub(r"\s+", "", text or "")


def _is_brief_ack_text(text: str) -> bool:
    normalized = re.sub(r"[\s，。,.!！?？、~～]+", "", text or "").lower()
    if not normalized or len(normalized) > 18:
        return False
    return bool(
        re.fullmatch(
            r"(好|好的|好嘞|行|可以|嗯|嗯嗯|收到|明白|明白了|我明白了|知道了|我知道了|了解|了解了|懂了|谢谢|谢谢你|ok|okay)",
            normalized,
        )
    )


def _normalize_action_id(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    key = re.sub(r"[\s\-]+", "_", text.lower())
    if key in ACTION_LABELS:
        return key
    compact = _compact_text(text)
    checks = [
        ("changed_game_password", ["修改密码", "改密码", "重置密码"]),
        ("checked_account_bindings", ["检查绑定", "绑定手机", "绑定邮箱", "密保", "安全中心", "绑定设置"]),
        ("enabled_login_protection", ["登录保护", "二次验证", "双重验证", "设备锁"]),
        ("preserved_evidence", ["保存证据", "保留证据", "聊天记录", "转账截图", "充值记录", "截图"]),
        ("reported_police", ["报警", "110", "派出所", "做了笔录", "做好了笔录", "报案"]),
        ("contacted_bank_or_payment_platform", ["联系银行", "支付平台", "止付", "冻结", "挂失"]),
        ("contacted_game_official_support", ["游戏官方客服", "游戏平台客服", "官方客服", "平台申诉", "账号申诉"]),
        ("stopped_contact", ["拉黑", "删除对方", "停止联系", "不再联系", "不联系对方"]),
        ("no_more_transfer", ["不再转账", "不会再转", "不转了", "不充值", "不充了", "不再充"]),
        ("stopped_operation", ["停止操作", "停下", "退出", "断开", "卸载"]),
    ]
    for action_id, words in checks:
        if any(word in compact for word in words):
            return action_id
    return ""


def _action_ids(value: Any, limit: int = 16) -> List[str]:
    result: List[str] = []
    for item in _as_list(value):
        action_id = _normalize_action_id(item)
        if action_id and action_id not in result:
            result.append(action_id)
        if len(result) >= limit:
            break
    return result


def _ensure_action_progress(analysis: Dict[str, Any]) -> Dict[str, Any]:
    progress = analysis.get("action_progress")
    if not isinstance(progress, dict):
        progress = {}
        analysis["action_progress"] = progress
    progress.setdefault("turn_act", "")
    progress.setdefault("completion_scope", "none")
    progress.setdefault("completed_actions", [])
    progress.setdefault("new_risk_signal", False)
    progress.setdefault("confidence", 0)
    progress.setdefault("reason", "")
    progress.setdefault("semantic_rewrite", "")
    return progress


def _add_completed_action(analysis: Dict[str, Any], action_id: Any) -> None:
    normalized = _normalize_action_id(action_id)
    if not normalized:
        return
    progress = _ensure_action_progress(analysis)
    completed = _action_ids(progress.get("completed_actions"), limit=24)
    if normalized not in completed:
        completed.append(normalized)
    progress["completed_actions"] = completed


def _merge_completed_actions(analysis: Dict[str, Any], actions: Iterable[Any]) -> None:
    for action in actions:
        _add_completed_action(analysis, action)


def _case_state_is_closed(case_state: Dict[str, Any]) -> bool:
    if not isinstance(case_state, dict) or not case_state:
        return False
    resolution = case_state.get("resolution") if isinstance(case_state.get("resolution"), dict) else {}
    if not resolution and isinstance(case_state.get("resolution_memory"), dict):
        resolution = case_state.get("resolution_memory") or {}
    return bool(
        str(case_state.get("case_status") or "") in CLOSED_CASE_STATUSES
        or bool(case_state.get("risk_resolved"))
        or bool(resolution.get("risk_resolved"))
    )


def _case_closure_summary_delivered(case_state: Dict[str, Any]) -> bool:
    if not isinstance(case_state, dict) or not case_state:
        return False
    resolution = case_state.get("resolution") if isinstance(case_state.get("resolution"), dict) else {}
    if not resolution and isinstance(case_state.get("resolution_memory"), dict):
        resolution = case_state.get("resolution_memory") or {}
    return bool(
        case_state.get("closure_summary_delivered")
        or resolution.get("closure_summary_delivered")
        or str(case_state.get("closure_summary_type") or "") == "personalized_scam_summary"
    )


def _semantic_new_case_signal(analysis: Dict[str, Any]) -> bool:
    scene = analysis.get("scene") if isinstance(analysis.get("scene"), dict) else {}
    progress = _ensure_action_progress(analysis)
    turn_act = str(progress.get("turn_act") or "")
    scene_type = str(scene.get("scene_type") or "")
    return bool(
        progress.get("new_risk_signal")
        or turn_act in {"risk_report", "new_risk_signal"}
        or (
            bool(scene.get("is_risk_scene"))
            and scene_type in {"personal_risk_scene", "post_loss_help", "realtime_dissuasion"}
            and turn_act not in {"followup_answer", "completion_confirmation", "smalltalk"}
        )
    )


def _reset_analysis_after_delivered_summary(analysis: Dict[str, Any]) -> Dict[str, Any]:
    progress = _ensure_action_progress(analysis)
    analysis["scene"] = {
        **(analysis.get("scene") if isinstance(analysis.get("scene"), dict) else {}),
        "scene_type": "post_closure_followup",
        "is_risk_scene": False,
        "user_intent": "followup_answer",
        "reason": "上一风险场景已经交付收尾总结，本轮语义没有新的风险事实，不再续接旧案。",
    }
    progress.update(
        {
            "turn_act": str(progress.get("turn_act") or "followup_answer"),
            "completion_scope": "none",
            "completed_actions": [],
            "new_risk_signal": False,
            "reason": (
                str(progress.get("reason") or "").strip()
                or "上一风险场景已经交付收尾总结，本轮不再产生旧案处置动作。"
            ),
        }
    )
    analysis["facts"] = {
        "case_summary": "",
        "counterparty_identity": "",
        "contact_channel": "",
        "platform_or_app": "",
        "requested_actions": [],
        "current_dangerous_actions": [],
        "user_actions": {},
        "loss": {"loss_confirmed": UNKNOWN, "loss_type": "none", "amount_or_value": "", "evidence": ""},
        "counterparty_behavior": [],
        "evidence": [],
    }
    analysis["fraud"] = {
        "primary_type": "",
        "candidate_types": [],
        "stage": "",
        "matched_feature_names": [],
        "feature_evidence": [],
    }
    analysis["ask_goal"] = ""
    analysis["missing_facts"] = []
    analysis["urgency"] = "none"
    analysis["post_closure_boundary"] = {
        "applied": True,
        "reason": "closure_summary_delivered=true 后旧案彻底结束；只有新的风险语义才能开启新案。",
    }
    return analysis


def _neutral_route_decision(reason: str) -> Dict[str, Any]:
    return {
        "primary_intent": "anti_fraud_qa",
        "secondary_intents": [],
        "workflow_mode": "knowledge_answer",
        "confidence": 1.0,
        "urgency": "none",
        "safety_override": False,
        "continue_current_workflow": False,
        "reason": reason,
        "need_clarification": False,
        "clarification_question": "",
        "clarification_options": [],
        "risk_signals": {},
        "safety_signals": {},
        "routing_decision": {"target": "knowledge_answer", "force_high_risk": False, "prefill_slots": {}},
    }


def _cleared_case_state_after_closure_summary(
    *,
    existing_case: Dict[str, Any],
    session_id: str,
    case_id: str,
    route_context: Dict[str, Any],
) -> Dict[str, Any]:
    now = datetime.now().isoformat(timespec="seconds")
    reason = "本案收尾总结已交付，风险工作记忆已重置，后续对话不再继承本案研判状态。"
    neutral_route = _neutral_route_decision(reason)
    cleared_route_context = {
        **(route_context or {}),
        "active_workflow": "idle",
        "workflow_status": "closed",
        "pending_question": {},
        "intent_lock": {"locked": False, "mode": "", "priority": 0, "until": "", "reason": ""},
        "last_route_decision": neutral_route,
        "post_closure_memory_reset": True,
        "updated_at": now,
    }
    return {
        **(existing_case or {}),
        "case_id": case_id or (existing_case or {}).get("case_id", ""),
        "session_id": session_id,
        "case_status": "closed",
        "case_context_type": 3,
        "case_context_label": "",
        "fraud_type": "",
        "fraud_stage": "",
        "risk_features": [],
        "normalized_risk_features": [],
        "risk_score": 0,
        "risk_level": "",
        "risk_class": "",
        "slots": {},
        "slot_memory": {},
        "slot_evidence": {},
        "exposure_memory": {},
        "current_unsafe_memory": {},
        "scam_memory": {},
        "scam_understanding": {},
        "risk_memory": {},
        "risk": {},
        "intervention_memory": {},
        "intervention": {},
        "education_memory": {},
        "semantic_risk_analysis": {},
        "semantic_risk_decision": {},
        "retrieved_docs": [],
        "matched_rules": [],
        "pending_question": {},
        "route_context": cleared_route_context,
        "route_memory": {
            "primary_intent": "anti_fraud_qa",
            "secondary_intents": [],
            "workflow_mode": "knowledge_answer",
            "intent_confidence": 1.0,
            "intent_hint": "",
            "intent_reason": reason,
            "route_decision": neutral_route,
            "updated_at": now,
        },
        "memory_summary": "",
        "risk_decay": {},
        "resolution": {
            "risk_resolved": True,
            "resolution_level": "closed_after_summary",
            "completed_actions": [],
            "missing_resolution_actions": [],
            "missing_action_ids": [],
            "ready_for_education": False,
            "post_resolution_education_delivered": True,
            "post_resolution_answer_mode": "summary_delivered_reset",
            "closure_summary_delivered": True,
            "judge_source": "semantic_closure_memory_reset",
            "reason": reason,
        },
        "resolution_memory": {
            "risk_resolved": True,
            "resolution_level": "closed_after_summary",
            "completed_actions": [],
            "missing_actions": [],
            "missing_action_ids": [],
            "unsafe_signals": [],
            "ready_for_education": False,
            "post_resolution_education_delivered": True,
            "post_resolution_answer_mode": "summary_delivered_reset",
            "closure_summary_delivered": True,
            "judge_source": "semantic_closure_memory_reset",
            "reason": reason,
            "closure_standard": {"can_close": True},
            "last_resolution_check_at": now,
        },
        "risk_resolved": True,
        "ready_for_education": False,
        "post_resolution_education_delivered": True,
        "post_resolution_answer_mode": "summary_delivered_reset",
        "closure_summary_delivered": True,
        "closure_summary_type": "personalized_scam_summary",
        "case_memory_cleared_after_closure": True,
        "last_answer": "",
        "last_updated_at": now,
    }


def _apply_completed_actions_to_facts(analysis: Dict[str, Any]) -> None:
    facts = analysis.setdefault("facts", {})
    user_actions = facts.setdefault("user_actions", {})
    progress = _ensure_action_progress(analysis)
    completed = _action_ids(progress.get("completed_actions"), limit=24)
    progress["completed_actions"] = completed
    for action_id in completed:
        fact_key = ACTION_TO_FACT_KEY.get(action_id)
        if fact_key:
            user_actions[fact_key] = TRUE
    if any(action in completed for action in ["stopped_contact", "no_more_transfer", "stopped_operation"]):
        user_actions["has_stopped_operation"] = TRUE
        user_actions["user_no_longer_believes_scammer"] = TRUE


def _compact_case_memory_for_prompt(memory_context: Dict[str, Any]) -> Dict[str, Any]:
    case_state = memory_context.get("case_state") if isinstance(memory_context.get("case_state"), dict) else {}
    if not case_state:
        return {}
    if _case_state_is_closed(case_state):
        resolution = case_state.get("resolution") if isinstance(case_state.get("resolution"), dict) else {}
        if not resolution and isinstance(case_state.get("resolution_memory"), dict):
            resolution = case_state.get("resolution_memory") or {}
        closure_summary_delivered = _case_closure_summary_delivered(case_state)
        return {
            "previous_case_is_closed": True,
            "case_status": case_state.get("case_status", ""),
            "risk_resolved": True,
            "post_resolution_education_delivered": bool(
                case_state.get("post_resolution_education_delivered")
                or resolution.get("post_resolution_education_delivered")
            ),
            "closure_summary_delivered": closure_summary_delivered,
            "case_followup_disabled": closure_summary_delivered,
            "memory_boundary": (
                "上一风险场景已经交付收尾总结，旧案彻底结束；普通确认、理解、感谢或继续说已处理不再续接旧案。"
                if closure_summary_delivered
                else "上一风险场景已经闭环，只能作为历史背景；本轮不要继承上一案诈骗类型、风险特征、槽位或完成动作。"
            ),
        }
    previous_analysis = case_state.get("semantic_risk_analysis") if isinstance(case_state.get("semantic_risk_analysis"), dict) else {}
    previous_facts = previous_analysis.get("facts") if isinstance(previous_analysis.get("facts"), dict) else {}
    previous_progress = previous_analysis.get("action_progress") if isinstance(previous_analysis.get("action_progress"), dict) else {}
    slots = {
        key: value
        for key, value in (case_state.get("slots") or {}).items()
        if value not in (None, "", [], {}, UNKNOWN)
    }
    return {
        "previous_case_is_closed": False,
        "fraud_type": case_state.get("fraud_type", ""),
        "fraud_stage": case_state.get("fraud_stage", ""),
        "risk_level": case_state.get("risk_level", ""),
        "risk_score": case_state.get("risk_score", 0),
        "risk_features": _text_list(case_state.get("risk_features"), limit=12),
        "slots": slots,
        "previous_user_actions": previous_facts.get("user_actions", {}),
        "previous_loss": previous_facts.get("loss", {}),
        "previous_requested_actions": previous_facts.get("requested_actions", []),
        "previous_action_progress": previous_progress,
        "previous_resolution": case_state.get("resolution") or case_state.get("resolution_memory") or {},
    }


def _merge_tri_bool(current: Any, previous: Any) -> str:
    current_value = _tri_bool(current)
    if current_value != UNKNOWN:
        return current_value
    return _tri_bool(previous)


def _set_action_if_unknown(actions: Dict[str, Any], key: str, value: Any) -> None:
    if _tri_bool(actions.get(key)) == UNKNOWN and _tri_bool(value) != UNKNOWN:
        actions[key] = _tri_bool(value)


def _first_amount(text: str) -> str:
    match = re.search(r"(\d+(?:\.\d+)?)\s*(?:元|块|人民币)?", text or "")
    return match.group(1) if match else ""


def _apply_direct_user_facts(analysis: Dict[str, Any], user_text: str) -> None:
    text = re.sub(r"\s+", "", user_text or "")
    facts = analysis.setdefault("facts", {})
    actions = facts.setdefault("user_actions", {})
    loss = facts.setdefault("loss", {})
    fraud = analysis.setdefault("fraud", {})
    requested_actions = _text_list(facts.get("requested_actions"), limit=8)

    if any(word in text for word in ["账号密码", "密码"]) and any(word in text for word in ["告诉对方", "告诉他", "发给对方", "发给他", "给了对方", "给对方", "已经告诉"]):
        actions["has_shared_account_password"] = TRUE
    if any(word in text for word in ["没给密码", "没有给密码", "没告诉密码", "没有告诉密码"]):
        actions["has_shared_account_password"] = FALSE
    if any(word in text for word in ["修改好密码", "改好密码", "已经修改密码", "已经改密码", "已修改密码", "已改密码"]):
        actions["has_changed_password_after_exposure"] = TRUE
        _add_completed_action(analysis, "changed_game_password")
    if any(word in text for word in ["还能正常登录", "可以正常登录", "能正常登录", "还能登录", "可以登录"]):
        actions["can_still_login_or_control_asset"] = TRUE
    if any(word in text for word in ["登不上", "登录不上", "不能登录", "无法登录", "被改密码"]):
        actions["can_still_login_or_control_asset"] = FALSE
    if any(word in text for word in ["账号还在自己手里", "账号现在还在自己手里", "账号现在还在我的手里", "账号还在我的手里", "账号还在手里", "账号在自己手里"]):
        actions["has_transferred_virtual_asset"] = FALSE
        actions["can_still_login_or_control_asset"] = TRUE
    if "手机号码还是我自己的" in text or "绑定手机还是我的" in text:
        actions["has_checked_account_bindings"] = TRUE
        _add_completed_action(analysis, "checked_account_bindings")
    if any(word in text for word in ["没有收到验证码", "没收到验证码", "未收到验证码"]):
        actions["has_shared_code"] = FALSE
    if any(word in text for word in ["我已经停止操作", "已经停止操作", "停止操作了", "没有继续", "没继续", "不再转账", "不会再转", "不再充值", "不充了"]):
        actions["has_stopped_operation"] = TRUE
        _add_completed_action(analysis, "stopped_operation")
    if any(word in text for word in ["拉黑对方", "把对方拉黑", "删除对方", "停止联系", "不再联系", "不联系对方"]):
        actions["has_stopped_operation"] = TRUE
        actions["user_no_longer_believes_scammer"] = TRUE
        _add_completed_action(analysis, "stopped_contact")
    if any(word in text for word in ["保存了所有聊天记录", "保存聊天记录", "保存了聊天记录", "保存证据", "保留证据", "转账截图", "充值记录", "截图保存"]):
        actions["has_preserved_evidence"] = TRUE
        _add_completed_action(analysis, "preserved_evidence")
    if any(word in text for word in ["报警", "打了110", "拨打110", "找了110", "派出所", "做好了笔录", "做了笔录", "报案"]):
        actions["has_reported_police"] = TRUE
        _add_completed_action(analysis, "reported_police")
    if any(word in text for word in ["联系游戏官方客服", "联系游戏平台客服", "游戏官方客服", "游戏平台客服", "账号申诉", "平台申诉"]):
        actions["has_contacted_official_support"] = TRUE
        _add_completed_action(analysis, "contacted_game_official_support")
    if any(word in text for word in ["联系银行", "联系支付平台", "支付平台客服", "申请止付", "止付", "冻结账户", "挂失"]):
        actions["has_contacted_bank_or_payment_platform"] = TRUE
        _add_completed_action(analysis, "contacted_bank_or_payment_platform")
    if any(word in text for word in ["开启登录保护", "开了登录保护", "开启二次验证", "开了二次验证", "双重验证"]):
        actions["has_enabled_login_protection"] = TRUE
        _add_completed_action(analysis, "enabled_login_protection")
    if any(
        word in text
        for word in [
            "我就充了",
            "我充了",
            "已经充了",
            "充值了",
            "已经充值",
            "转了",
            "转账了",
            "付了",
            "付款了",
            "交了",
            "垫了",
            "垫付了",
            "已垫付",
            "已经垫付",
        ]
    ):
        actions["has_paid"] = TRUE
        if _tri_bool(actions.get("has_unrecovered_money_loss")) == UNKNOWN:
            actions["has_unrecovered_money_loss"] = TRUE
        amount = _first_amount(text)
        if amount and not actions.get("paid_amount"):
            actions["paid_amount"] = amount
            loss.setdefault("amount_or_value", amount)
        loss["loss_confirmed"] = TRUE
        if loss.get("loss_type") in {"", "none", UNKNOWN, None}:
            loss["loss_type"] = "money"
    if any(word in text for word in ["不能提现", "提现不了", "无法提现", "提现失败", "提不出来", "账户冻结", "账号冻结"]):
        facts["withdrawal_status"] = "blocked"
        matched = _text_list(fraud.get("matched_feature_names"), limit=16)
        if "无法提现" not in matched:
            matched.append("无法提现")
        fraud["matched_feature_names"] = matched[:16]
    if any(word in text for word in ["返了几块", "返了几十", "小额返利", "收到返利", "返过钱", "返过佣金"]):
        actions["has_received_small_rebate"] = TRUE
    if any(word in text for word in ["没返", "没有返", "没收到返利", "没有收到返利", "没给过返利", "没有给过返利"]):
        actions["has_received_small_rebate"] = FALSE
    if any(word in text for word in ["下载了", "安装了", "下了app", "下了APP", "陌生app", "陌生APP", "任务app", "任务APP"]):
        actions["has_downloaded_app"] = TRUE
    if any(word in text for word in ["没下载", "没有下载", "没安装", "没有安装"]):
        actions["has_downloaded_app"] = FALSE
    if any(word in text for word in ["微信支付", "微信转账", "微信扫码", "微信红包", "支付宝", "银行卡", "银行转账", "网银", "平台充值"]):
        if not facts.get("payment_channel"):
            channel = "微信" if any(word in text for word in ["微信支付", "微信转账", "微信扫码", "微信红包"]) else ""
            channel = channel or ("支付宝" if "支付宝" in text else "")
            channel = channel or ("银行卡/银行转账" if any(word in text for word in ["银行卡", "银行转账", "网银"]) else "")
            channel = channel or ("平台充值" if "平台充值" in text else "")
            facts["payment_channel"] = channel or "用户已说明支付渠道"
    for match in re.finditer(r"(?:要我|让我|要求我)?再?充(?:值)?(\d+(?:\.\d+)?)\s*(?:元|块)?", text):
        action = f"继续充值{match.group(1)}元"
        if action not in requested_actions:
            requested_actions.append(action)
    if any(word in text for word in ["补单", "联单", "连单", "解冻费", "认证费", "保证金", "手续费", "继续充值", "继续交钱", "继续转账"]):
        action = "继续补单/解冻/交费"
        if action not in requested_actions:
            requested_actions.append(action)
    if requested_actions:
        facts["requested_actions"] = requested_actions[:8]
    _apply_completed_actions_to_facts(analysis)


def _apply_direct_history_facts(analysis: Dict[str, Any], state: Dict[str, Any], *, include_history: bool = True) -> None:
    if include_history:
        for item in _history_for_prompt(state, limit=16):
            if item.get("role") == "user":
                _apply_direct_user_facts(analysis, item.get("text", ""))
    _apply_direct_user_facts(analysis, str(state.get("original_query") or ""))


def _education_context_from_state(state: Dict[str, Any]) -> Dict[str, Any]:
    route_decision = state.get("route_decision") if isinstance(state.get("route_decision"), dict) else {}
    context = route_decision.get("education_context") if isinstance(route_decision.get("education_context"), dict) else {}
    topic = str(context.get("topic") or "").strip()
    if topic and topic in _scam_profile_by_name():
        return context
    return {}


def _explicit_fraud_type_hits(text: str) -> List[str]:
    compact = _compact_text(text)
    if not compact:
        return []
    hits: List[str] = []
    for scam in _load_json_collection("scam_types"):
        name = str(scam.get("name") or "").strip()
        terms = [name, name.replace("诈骗", ""), *_as_list(scam.get("aliases"))]
        for term in terms:
            term_text = _compact_text(str(term or ""))
            if not term_text or term_text in GENERIC_SCAM_ALIAS_TERMS:
                continue
            if len(term_text) < 2:
                continue
            if term_text in compact and name and name not in hits:
                hits.append(name)
                break
    return hits


def _feature_names_for_fraud_type(fraud_type: str) -> List[str]:
    profile = _scam_profile_by_name().get(fraud_type) or {}
    scam_id = str(profile.get("scam_id") or "")
    names: List[str] = []
    for feature in _load_json_collection("scam_features"):
        if str(feature.get("scam_id") or "") != scam_id and str(feature.get("fraud_type") or "") != fraud_type:
            continue
        name = str(feature.get("feature_name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def _infer_feature_names_for_fraud_type(fraud_type: str, text: str) -> List[str]:
    profile = _scam_profile_by_name().get(fraud_type) or {}
    scam_id = str(profile.get("scam_id") or "")
    compact = _compact_text(text)
    inferred: List[str] = []
    if not compact:
        return inferred
    for feature in _load_json_collection("scam_features"):
        if str(feature.get("scam_id") or "") != scam_id and str(feature.get("fraud_type") or "") != fraud_type:
            continue
        keywords = _text_list(feature.get("keywords"), limit=12)
        if any(_compact_text(keyword) and _compact_text(keyword) in compact for keyword in keywords):
            name = str(feature.get("feature_name") or "").strip()
            if name and name not in inferred:
                inferred.append(name)
    return inferred


def _apply_education_context_hint(analysis: Dict[str, Any], state: Dict[str, Any]) -> None:
    context = _education_context_from_state(state)
    topic = str(context.get("topic") or "").strip()
    if not topic or not bool((analysis.get("scene") or {}).get("is_risk_scene")):
        return
    user_text = str(state.get("original_query") or "")
    explicit_hits = _explicit_fraud_type_hits(user_text)
    explicit_other = [item for item in explicit_hits if item != topic]
    if explicit_other:
        return

    fraud = analysis.setdefault("fraud", {})
    previous_type = str(fraud.get("primary_type") or "").strip()
    fraud["primary_type"] = topic
    candidates = _text_list(fraud.get("candidate_types"), limit=8)
    if topic not in candidates:
        candidates.insert(0, topic)
    fraud["candidate_types"] = candidates[:8]

    topic_feature_names = set(_feature_names_for_fraud_type(topic))
    inferred = _infer_feature_names_for_fraud_type(topic, user_text)
    current = _text_list(fraud.get("matched_feature_names"), limit=16)
    anchored_features = [item for item in inferred if item not in current]
    anchored_features.extend(item for item in current if item in topic_feature_names and item not in anchored_features)
    if anchored_features:
        fraud["matched_feature_names"] = anchored_features[:16]

    analysis["education_context"] = {
        "applied": True,
        "topic": topic,
        "previous_primary_type": previous_type,
        "reason": "用户从知识教学进入个人风险表述，且本轮没有明确切换到其他骗局类型。",
        "source": context.get("source", "knowledge_dialogue_state"),
    }


def _merge_analysis_with_memory(analysis: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    memory_context = state.get("memory_context") if isinstance(state.get("memory_context"), dict) else {}
    case_state = memory_context.get("case_state") if isinstance(memory_context.get("case_state"), dict) else {}
    if not case_state and isinstance(state.get("case_state"), dict):
        case_state = state.get("case_state") or {}
    previous_closed = _case_state_is_closed(case_state)
    previous_summary_delivered = _case_closure_summary_delivered(case_state)
    slots = case_state.get("slots") if isinstance(case_state.get("slots"), dict) else {}
    previous_analysis = case_state.get("semantic_risk_analysis") if isinstance(case_state.get("semantic_risk_analysis"), dict) else {}
    previous_progress = previous_analysis.get("action_progress") if isinstance(previous_analysis.get("action_progress"), dict) else {}
    previous_resolution = case_state.get("resolution") if isinstance(case_state.get("resolution"), dict) else {}
    if not previous_resolution and isinstance(case_state.get("resolution_memory"), dict):
        previous_resolution = case_state.get("resolution_memory") or {}

    facts = analysis.setdefault("facts", {})
    actions = facts.setdefault("user_actions", {})
    loss = facts.setdefault("loss", {})
    progress = _ensure_action_progress(analysis)
    _apply_direct_history_facts(analysis, state, include_history=not previous_closed)
    _apply_education_context_hint(analysis, state)
    if previous_summary_delivered and not _semantic_new_case_signal(analysis):
        return _reset_analysis_after_delivered_summary(analysis)
    if previous_closed:
        _apply_completed_actions_to_facts(analysis)
        return analysis

    slot_to_action = {
        "has_paid": "has_paid",
        "has_received_rebate": "has_received_small_rebate",
        "has_unrecovered_loss": "has_unrecovered_money_loss",
        "has_transferred_virtual_asset": "has_transferred_virtual_asset",
        "can_still_login_or_control_asset": "can_still_login_or_control_asset",
        "has_shared_account_password": "has_shared_account_password",
        "has_changed_password_after_exposure": "has_changed_password_after_exposure",
        "has_checked_account_bindings": "has_checked_account_bindings",
        "has_shared_code": "has_shared_code",
        "has_screen_share": "has_screen_shared_or_remote_control",
        "has_downloaded_app": "has_downloaded_app",
        "has_clicked_link": "has_clicked_link",
        "has_provided_identity_or_bank": "has_provided_identity_or_bank",
        "has_stopped_operation": "has_stopped_operation",
        "has_preserved_evidence": "has_preserved_evidence",
        "has_reported_police": "has_reported_police",
        "has_contacted_official_support": "has_contacted_official_support",
        "has_contacted_bank": "has_contacted_bank_or_payment_platform",
        "has_contacted_bank_or_payment_platform": "has_contacted_bank_or_payment_platform",
    }
    for slot_key, action_key in slot_to_action.items():
        _set_action_if_unknown(actions, action_key, slots.get(slot_key))

    _merge_completed_actions(analysis, previous_progress.get("completed_actions", []))
    _merge_completed_actions(analysis, previous_resolution.get("completed_actions", []))
    if str(progress.get("completion_scope") or "") == "all_previous_advice":
        _merge_completed_actions(analysis, _recent_assistant_advice_actions(state))
    _apply_completed_actions_to_facts(analysis)
    return analysis


def _known_fact_lines(state: Dict[str, Any], analysis: Dict[str, Any], decision: Dict[str, Any]) -> List[str]:
    facts = analysis.get("facts") or {}
    actions = facts.get("user_actions") or {}
    lines: List[str] = []
    if decision.get("fraud_type"):
        lines.append(f"疑似类型：{decision.get('fraud_type')}")
    amount = actions.get("paid_amount") or (facts.get("loss") or {}).get("amount_or_value")
    if actions.get("has_paid") == TRUE:
        lines.append(f"用户已付款/充值：{amount or '金额未明'}")
    if _text_list(facts.get("requested_actions"), limit=4):
        lines.append("对方仍在要求：" + "；".join(_text_list(facts.get("requested_actions"), limit=4)))
    if actions.get("has_transferred_virtual_asset") == FALSE:
        lines.append("游戏账号仍在用户手里")
    if actions.get("can_still_login_or_control_asset") == TRUE:
        lines.append("用户确认还能正常登录账号")
    if actions.get("can_still_login_or_control_asset") == FALSE:
        lines.append("用户确认已经无法登录账号")
    if actions.get("has_shared_account_password") == TRUE:
        lines.append("用户已把账号密码告诉对方")
    if actions.get("has_changed_password_after_exposure") == TRUE:
        lines.append("用户已修改账号密码")
    if actions.get("has_checked_account_bindings") == TRUE:
        lines.append("用户表示绑定手机仍是自己的")
    if actions.get("has_enabled_login_protection") == TRUE:
        lines.append("用户已开启登录保护或二次验证")
    if actions.get("has_preserved_evidence") == TRUE:
        lines.append("用户已保存聊天、转账或充值等证据")
    if actions.get("has_reported_police") == TRUE:
        lines.append("用户已报警或完成笔录")
    if actions.get("has_contacted_official_support") == TRUE:
        lines.append("用户已联系官方客服或平台申诉")
    if actions.get("has_contacted_bank_or_payment_platform") == TRUE:
        lines.append("用户已联系银行或支付平台")
    if actions.get("has_stopped_operation") == TRUE:
        lines.append("用户已停止继续操作或不再转账联系")
    if actions.get("has_shared_code") == FALSE:
        lines.append("用户表示目前没有收到或提供验证码")
    lifecycle = analysis.get("case_lifecycle") if isinstance(analysis.get("case_lifecycle"), dict) else {}
    if lifecycle.get("case_status"):
        lines.append(f"当前处置状态：{lifecycle.get('case_status')}")
    return lines


def _followup_targets_known(ask_goal: str, analysis: Dict[str, Any]) -> bool:
    text = str(ask_goal or "")
    actions = ((analysis.get("facts") or {}).get("user_actions") or {})
    checks = [
        (["是否还能登录", "能否登录", "还能登录", "正常登录"], "can_still_login_or_control_asset"),
        (["账号是否已给", "账号有没有给", "账号还在", "是否交付", "是否已交付"], "has_transferred_virtual_asset"),
        (["账号密码", "密码"], "has_shared_account_password"),
        (["修改密码", "改密码"], "has_changed_password_after_exposure"),
        (["验证码"], "has_shared_code"),
        (["保存证据", "聊天记录", "转账截图", "截图"], "has_preserved_evidence"),
        (["报警", "110", "派出所", "笔录"], "has_reported_police"),
        (["官方客服", "平台客服", "申诉"], "has_contacted_official_support"),
        (["登录保护", "二次验证"], "has_enabled_login_protection"),
        (["继续转", "继续充", "不再转", "停止"], "has_stopped_operation"),
    ]
    if any(any(word in text for word in words) and _tri_bool(actions.get(key)) != UNKNOWN for words, key in checks):
        return True
    return False


def _has_enough_game_stoploss_context(analysis: Dict[str, Any]) -> bool:
    fraud_type = str((analysis.get("fraud") or {}).get("primary_type") or "")
    facts = analysis.get("facts") or {}
    actions = facts.get("user_actions") or {}
    is_game = "游戏" in fraud_type or bool(actions.get("virtual_asset_type"))
    paid_or_loss = actions.get("has_paid") == TRUE or (facts.get("loss") or {}).get("loss_confirmed") == TRUE
    account_secured = (
        actions.get("can_still_login_or_control_asset") == TRUE
        and (
            actions.get("has_changed_password_after_exposure") == TRUE
            or actions.get("has_transferred_virtual_asset") == FALSE
        )
    )
    credential_known = actions.get("has_shared_account_password") in {TRUE, FALSE}
    return bool(is_game and paid_or_loss and account_secured and credential_known)


def _sanitize_followup_plan(analysis: Dict[str, Any]) -> Dict[str, Any]:
    ask_goal = str(analysis.get("ask_goal") or "")
    lifecycle = analysis.get("case_lifecycle") if isinstance(analysis.get("case_lifecycle"), dict) else {}
    if str(lifecycle.get("case_status") or "") in CLOSED_CASE_STATUSES or bool((analysis.get("resolution") or {}).get("risk_resolved")):
        analysis["ask_goal"] = ""
        analysis["missing_facts"] = []
        return analysis
    if ask_goal and (_followup_targets_known(ask_goal, analysis) or _has_enough_game_stoploss_context(analysis)):
        analysis["ask_goal"] = ""
        analysis["missing_facts"] = []
    return analysis


def _without_prompt_only_fields(item: Dict[str, Any]) -> Dict[str, Any]:
    doc = dict(item or {})
    doc.pop("regex_patterns", None)
    doc.pop("advice_template_id", None)
    doc.pop("_id", None)
    return doc


def _features_by_scam() -> Dict[str, List[Dict[str, Any]]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for item in _load_json_collection("scam_features"):
        scam_id = str(item.get("scam_id") or "")
        if not scam_id:
            continue
        grouped.setdefault(scam_id, []).append(_without_prompt_only_fields(item))
    for values in grouped.values():
        values.sort(key=lambda row: _number(row.get("risk_weight"), 0), reverse=True)
    return grouped


def _scam_profile_by_name() -> Dict[str, Dict[str, Any]]:
    profiles = {}
    features = _features_by_scam()
    for scam in _load_json_collection("scam_types"):
        item = _without_prompt_only_fields(scam)
        item["features"] = features.get(str(item.get("scam_id") or ""), [])
        profiles[str(item.get("name") or "")] = item
    return profiles


def build_scam_catalog_for_prompt(max_features_per_scam: int = 6) -> List[Dict[str, Any]]:
    """Build a compact structured catalog for LLM extraction and routing."""
    catalog: List[Dict[str, Any]] = []
    features = _features_by_scam()
    for scam in _load_json_collection("scam_types"):
        scam_id = str(scam.get("scam_id") or "")
        feature_rows = features.get(scam_id, [])[: max(1, int(max_features_per_scam or 6))]
        catalog.append(
            {
                "scam_id": scam_id,
                "name": scam.get("name", ""),
                "aliases": _text_list(scam.get("aliases"), limit=10),
                "description": scam.get("description", ""),
                "typical_stages": _text_list(scam.get("typical_stages"), limit=8),
                "critical_facts": _text_list(scam.get("critical_facts"), limit=8),
                "loss_signals": _text_list(scam.get("loss_signals"), limit=8),
                "primary_intervention_goals": _text_list(scam.get("primary_intervention_goals"), limit=6),
                "features": [
                    {
                        "feature_name": row.get("feature_name", ""),
                        "keywords": _text_list(row.get("keywords"), limit=8),
                        "stage": row.get("stage", ""),
                        "risk_weight": row.get("risk_weight", 0),
                        "explanation": row.get("explanation", ""),
                    }
                    for row in feature_rows
                ],
            }
        )
    return catalog


def build_semantic_policy_for_prompt() -> List[Dict[str, Any]]:
    return [_without_prompt_only_fields(item) for item in _load_json_collection("semantic_risk_policy")]


def _all_feature_names() -> set[str]:
    return {
        str(item.get("feature_name") or "").strip()
        for item in _load_json_collection("scam_features")
        if str(item.get("feature_name") or "").strip()
    }


def _knowledge_for_type(fraud_type: str, feature_names: List[str]) -> Dict[str, Any]:
    profiles = _scam_profile_by_name()
    profile = profiles.get(fraud_type) or {}
    risk_rules = sorted(
        [
            _without_prompt_only_fields(item)
            for item in _load_json_collection("risk_rules")
            if item.get("fraud_type") == fraud_type
        ],
        key=lambda item: _number(item.get("risk_score"), 0),
        reverse=True,
    )[:3]
    advice = [
        _without_prompt_only_fields(item)
        for item in _load_json_collection("prevention_advice")
        if item.get("fraud_type") == fraud_type
    ][:3]
    cases = [
        _without_prompt_only_fields(item)
        for item in _load_json_collection("typical_cases")
        if item.get("fraud_type") == fraud_type
    ][:2]
    laws = [
        _without_prompt_only_fields(item)
        for item in _load_json_collection("law_clauses")
        if fraud_type in _text_list(item.get("related_scam_types"), limit=20)
        or any(word in _text_list(item.get("related_behaviors"), limit=20) for word in ["报警", "止付冻结", "证据保存"])
    ][:3]
    report_guides = [
        _without_prompt_only_fields(item)
        for item in _load_json_collection("report_guides")
        if item.get("fraud_type") in {fraud_type, "通用"}
    ][:2]
    evidence_guides = [
        _without_prompt_only_fields(item)
        for item in _load_json_collection("evidence_guides")
        if item.get("fraud_type") in {fraud_type, "通用"}
    ][:2]
    feature_set = set(feature_names)
    features = [
        _without_prompt_only_fields(item)
        for item in profile.get("features") or []
        if not feature_set or item.get("feature_name") in feature_set
    ][:8]
    if not features:
        features = [_without_prompt_only_fields(item) for item in profile.get("features") or []][:6]
    return {
        "scam_profile": {key: value for key, value in profile.items() if key != "features"},
        "features": features,
        "risk_rules": risk_rules,
        "prevention_advice": advice,
        "typical_cases": cases,
        "law_guides": laws,
        "report_guides": report_guides,
        "evidence_guides": evidence_guides,
        "knowledge_grounding": {
            "structured": ["scam_profile", "features"],
            "rule_based": ["risk_rules", "matched_rules"],
            "semi_structured": ["prevention_advice", "typical_cases", "law_guides", "report_guides", "evidence_guides"],
            "usage": "用于支撑问答、语义推理、风险劝阻话术、取证报案和收尾复盘。",
        },
    }


def _history_for_prompt(state: Dict[str, Any], limit: int = 8) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    for item in state.get("history") or []:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip()
        text = str(item.get("text") or item.get("content") or "").strip()
        if role and text:
            items.append({"role": role, "text": text})
    return items[-limit:]


def _infer_advice_actions_from_text(text: str) -> List[str]:
    compact = _compact_text(text)
    actions: List[str] = []
    checks = [
        ("changed_game_password", ["修改密码", "改密码", "重置密码"]),
        ("checked_account_bindings", ["检查账号绑定", "绑定设置", "安全中心", "手机、邮箱", "手机邮箱", "密保"]),
        ("enabled_login_protection", ["登录保护", "二次验证", "双重验证", "设备锁"]),
        ("preserved_evidence", ["保存证据", "保留证据", "聊天记录", "转账截图", "充值记录", "截图"]),
        ("reported_police", ["报警", "110", "派出所", "报案", "笔录"]),
        ("contacted_bank_or_payment_platform", ["联系银行", "支付平台", "止付", "冻结", "挂失"]),
        ("contacted_game_official_support", ["游戏官方客服", "游戏平台客服", "官方客服", "账号申诉", "平台申诉"]),
        ("no_more_transfer", ["不要再转", "不要再充", "别再转", "别再充", "不再转", "不再充", "不要继续"]),
        ("stopped_contact", ["拉黑", "删除对方", "不要再和", "停止联系", "不再联系"]),
        ("stopped_operation", ["停止操作", "退出", "断开", "卸载"]),
    ]
    for action_id, words in checks:
        if any(word in compact for word in words) and action_id not in actions:
            actions.append(action_id)
    return actions


def _recent_assistant_advice_actions(state: Dict[str, Any], limit: int = 6) -> List[str]:
    actions: List[str] = []
    for item in _history_for_prompt(state, limit=limit * 2):
        if item.get("role") != "assistant":
            continue
        for action_id in _infer_advice_actions_from_text(item.get("text", "")):
            if action_id not in actions:
                actions.append(action_id)
    return actions


def _call_json_llm(system_prompt: str, human_prompt: str) -> Dict[str, Any]:
    llm = get_llm_client(json_mode=True)
    response = call_with_timeout(
        lambda: llm.invoke([SystemMessage(content=system_prompt), HumanMessage(content=human_prompt)]),
        env_timeout("ANTI_FRAUD_LLM_FACT_TIMEOUT_SECONDS", 2.0),
    )
    data = extract_json_object(get_message_content(response))
    if not data:
        raise ValueError("LLM returned empty JSON")
    return data


def _fallback_semantic_analysis(state: Dict[str, Any], reason: str = "") -> Dict[str, Any]:
    """Build a grounded risk analysis when the semantic provider is unavailable."""
    user_text = str(state.get("original_query") or "").strip()
    route_decision = state.get("route_decision") if isinstance(state.get("route_decision"), dict) else {}
    prefill = (route_decision.get("routing_decision") or {}).get("prefill_slots") or {}
    candidates = [
        item
        for item in (
            route_decision.get("fraud_type_candidates")
            or route_decision.get("risk_prefill", {}).get("fraud_candidates", [])
            or prefill.get("fraud_candidates", [])
            or ([prefill.get("fraud_type_hint")] if prefill.get("fraud_type_hint") else [])
        )
        if item
    ]
    try:
        from app.query_process.services.scam_rule_engine import evaluate_rule_text

        rule_result = evaluate_rule_text(
            user_text,
            context={
                "slots": {},
                "possible_fraud_types": candidates,
                "route_decision": route_decision,
            },
            route_decision=route_decision,
        )
    except Exception as exc:  # pragma: no cover - last-resort protection
        rule_result = {
            "fraud_type": candidates[0] if candidates else "未知",
            "possible_fraud_types": candidates or ["未知"],
            "risk_features": [],
            "risk_score": 0,
            "matched_rules": [],
            "evidence": [],
            "risk_stage": "未知",
        }
        reason = f"规则兜底失败：{exc}；{reason}".strip("；")

    text = re.sub(r"\s+", "", user_text)
    features = _text_list(rule_result.get("risk_features"), limit=16)
    has_paid = TRUE if re.search(r"(已经|已|刚刚|刚才).{0,12}(转账|转钱|付款|支付|充值|打款|汇款|交钱|垫付)|(?:转账了|付款了|充值了|垫付了)", text) else UNKNOWN
    if re.search(r"(还没|没有|没|未).{0,10}(转账|转钱|付款|充值|垫付|交钱)", text):
        has_paid = FALSE
    has_code = TRUE if re.search(r"(已经|已|刚刚|刚才).{0,12}(验证码|动态码|短信码)|(?:给了|发了|填了).{0,8}(验证码|动态码|短信码)", text) else UNKNOWN
    has_screen = TRUE if re.search(r"(正在|已经|已|刚刚).{0,10}(屏幕共享|共享屏幕|远程控制|远程协助)", text) else UNKNOWN
    has_download = TRUE if re.search(r"(已经|已|刚刚|下载了|安装了).{0,10}(App|APP|app|软件)", text) else UNKNOWN
    has_link = TRUE if re.search(r"(点了|点击了|打开了|进入了).{0,10}(链接|网址|二维码)", text) else UNKNOWN
    has_identity = TRUE if re.search(r"(已经|已|刚刚|给了|提供了|填了|上传了).{0,12}(银行卡|卡号|身份证|身份信息|人脸)", text) else UNKNOWN
    exposure = any(
        value == TRUE
        for value in [has_paid, has_code, has_screen, has_download, has_link, has_identity]
    )
    current_actions = []
    if any(item in features for item in ["要求垫付资金", "要求继续补单", "贷款前收费", "要求缴纳解冻费"]):
        current_actions.append("继续转账、充值或垫付")
    if "屏幕共享" in features or "远程控制" in features:
        current_actions.append("屏幕共享或远程控制")
    if "索要验证码" in features:
        current_actions.append("提供验证码或动态码")
    if "诱导下载陌生APP" in features:
        current_actions.append("下载陌生 App")
    requested_actions = _text_list(current_actions, limit=8)
    primary_type = str(rule_result.get("fraud_type") or "").strip()
    if not primary_type and candidates:
        primary_type = str(candidates[0]).strip()
    primary_type = primary_type or "未知"
    if primary_type == "未知" and candidates:
        primary_type = str(candidates[0])
    score = int(rule_result.get("risk_score", 0) or 0)
    is_risk_scene = bool(
        route_decision.get("workflow_mode") == "risk_case_flow"
        or route_decision.get("safety_override")
        or route_decision.get("primary_intent") in {"risk_help", "emergency_help", "risk_fact_clarification"}
        or exposure
        or requested_actions
    )
    scene_type = "post_loss_help" if exposure and has_paid == TRUE else "personal_risk_scene" if is_risk_scene else "knowledge_consultation"
    action_progress = {
        "turn_act": "risk_report" if is_risk_scene else "knowledge_question",
        "semantic_rewrite": "规则兜底提取用户当前风险事实",
        "completion_scope": "none",
        "completed_actions": [],
        "new_risk_signal": bool(is_risk_scene),
        "confidence": 0.8,
        "reason": reason or "LLM 事实研判超时，使用本地规则和用户原话兜底。",
    }
    actions = {
        "has_paid": has_paid,
        "paid_amount": "",
        "has_received_small_rebate": UNKNOWN,
        "has_unrecovered_money_loss": TRUE if has_paid == TRUE else UNKNOWN,
        "has_transferred_virtual_asset": UNKNOWN,
        "virtual_asset_type": "",
        "can_still_login_or_control_asset": UNKNOWN,
        "has_shared_account_password": UNKNOWN,
        "has_changed_password_after_exposure": UNKNOWN,
        "has_checked_account_bindings": UNKNOWN,
        "has_unknown_binding_or_device": UNKNOWN,
        "has_shared_code": has_code,
        "has_screen_shared_or_remote_control": has_screen,
        "has_downloaded_app": has_download,
        "has_clicked_link": has_link,
        "has_provided_identity_or_bank": has_identity,
        "has_stopped_operation": UNKNOWN,
        "has_preserved_evidence": UNKNOWN,
        "has_reported_police": UNKNOWN,
        "has_contacted_official_support": UNKNOWN,
        "has_contacted_bank_or_payment_platform": UNKNOWN,
        "has_enabled_login_protection": UNKNOWN,
        "user_no_longer_believes_scammer": UNKNOWN,
    }
    raw = {
        "scene": {
            "scene_type": scene_type,
            "is_risk_scene": is_risk_scene,
            "user_intent": "realtime_dissuasion" if is_risk_scene else "knowledge",
            "reason": "确定性风险规则识别到当前行为组合。" if is_risk_scene else "未识别到个人正在操作的风险行为。",
            "confidence": 0.8,
        },
        "facts": {
            "case_summary": user_text[:160],
            "counterparty_identity": "",
            "contact_channel": "",
            "platform_or_app": "",
            "requested_actions": requested_actions,
            "current_dangerous_actions": requested_actions,
            "user_actions": actions,
            "loss": {
                "loss_confirmed": TRUE if has_paid == TRUE else UNKNOWN,
                "loss_type": "money" if has_paid == TRUE else "none",
                "amount_or_value": "",
                "evidence": "",
            },
            "counterparty_behavior": features,
            "evidence": [item.get("source_text") or item.get("name") for item in rule_result.get("evidence", []) if item.get("source_text") or item.get("name")][:8],
        },
        "fraud": {
            "primary_type": primary_type,
            "candidate_types": rule_result.get("possible_fraud_types") or candidates or [primary_type],
            "stage": rule_result.get("risk_stage", ""),
            "matched_feature_names": features,
            "feature_evidence": [
                {"feature": item, "evidence": item, "confidence": 0.85} for item in features[:8]
            ],
        },
        "action_progress": action_progress,
        "missing_facts": [],
        "ask_goal": "你现在是否已经转账、提供验证码或开启屏幕共享？" if is_risk_scene and not exposure else "",
        "urgency": "urgent" if score >= 80 or exposure else "normal" if is_risk_scene else "none",
    }
    analysis = _normalize_analysis(raw)
    _apply_direct_user_facts(analysis, user_text)
    analysis["fallback_reason"] = reason or "semantic_provider_unavailable"
    return analysis


def extract_semantic_risk_facts(state: Dict[str, Any]) -> Dict[str, Any]:
    """Ask the LLM to classify the scene and extract risk facts."""
    user_text = str(state.get("original_query") or "").strip()
    route_decision = state.get("route_decision") or {}
    if route_decision.get("deterministic_risk_route"):
        return _fallback_semantic_analysis(state, "高置信风险路由优先返回确定性安全卡片")
    memory_context = state.get("memory_context") or {}
    catalog = build_scam_catalog_for_prompt(max_features_per_scam=8)
    policy = build_semantic_policy_for_prompt()
    system_prompt = """
你是反诈智能体的语义事实研判器，只输出 JSON，不直接回答用户。

任务：
1. 判断用户是否处在个人风险场景。只咨询诈骗类型、案例、防范方法时，is_risk_scene 必须为 false。
2. 如果是风险场景，结合上下文抽取风险事实、用户动作、对方动作、损失/暴露、当前是否正在危险操作。
3. 结合知识库目录匹配骗局类型、风险特征和阶段。不要使用模板问句，不要为了凑槽而臆造事实。
4. “卖账号钱没收到”“账号被骗走”“号给了钱没到”等应理解为游戏账号/虚拟资产疑似已交付或控制权受损。
5. 明确区分：对方要求用户做某事，不等于用户已经做了。
6. 输出的 matched_feature_names 必须优先使用目录中的 feature_name。
7. 会话记忆和最近对话里已经确认过的事实，不要再列入 missing_facts，也不要把 ask_goal 设为重复追问。
8. 如果用户说“我已经做完了”“都按你说的做了”“已经处理好了”等泛化表达，必须结合最近对话判断是否承接上一轮处置建议；只有能确认承接安全处置动作时，action_progress.turn_act 才能设为 completion_confirmation。
9. 不要仅凭“好了/完成/知道了”就臆造完成动作；完成动作必须来自用户明说、上一轮助手建议被用户整体确认，或会话记忆中已有事实。
10. 如果 route_decision.education_context 显示用户刚在学习某类骗局，本轮又出现“我已经转账/不能提现/对方让我交费”等个人风险信号，可把该教学主题作为 fraud.primary_type 的上下文锚点；但如果用户本轮明确说了另一个骗局类型或事实冲突，必须以用户本轮事实为准。
11. 用户如果只是表达理解、收到、知道、明白、感谢，不等于已经执行处置动作；这类情况 action_progress.turn_act 应为 followup_answer，completion_scope 为 none，completed_actions 必须为空。
12. 如果会话记忆 case_memory.previous_case_is_closed 为 true，上一风险场景只作为历史背景；除非用户本轮语义明确追问上一案或确认上一案处置结果，否则不要把上一案的诈骗类型、风险特征、槽位或完成动作当成本轮事实。用户本轮出现新的对象、平台、金额、行为、损失或暴露时，必须按新场景独立研判。
13. 如果会话记忆 case_memory.case_followup_disabled 为 true，说明上一案已经生成收尾总结，旧案彻底结束；用户后续的普通确认、理解、感谢或“已处理”不再触发旧案续接，也不再生成总结。只有用户本轮明确描述新的风险事实时，才开启新的风险场景。
14. action_progress.completed_actions 只记录用户本轮明确声称已经完成的处置动作，不能因为助手上一轮建议过、或会话记忆里曾有处置事实，就自动放入 completed_actions。
"""
    human_prompt = f"""
【用户本轮输入】
{user_text}

【最近对话】
{json.dumps(_history_for_prompt(state), ensure_ascii=False)}

【最近助手建议动作候选】
{json.dumps([{"action_id": item, "label": ACTION_LABELS.get(item, item)} for item in _recent_assistant_advice_actions(state)], ensure_ascii=False)}

【会话记忆】
{json.dumps({
    "memory_summary": memory_context.get("memory_summary", ""),
    "pending_question": memory_context.get("pending_question", {}),
    "route_context": memory_context.get("route_context", {}),
    "route_decision": route_decision,
    "education_context": route_decision.get("education_context", {}),
    "case_memory": _compact_case_memory_for_prompt(memory_context),
}, ensure_ascii=False)}

【结构化反诈知识目录】
{json.dumps(catalog, ensure_ascii=False)}

【语义风险策略】
{json.dumps(policy, ensure_ascii=False)}

请返回严格 JSON：
{{
  "scene": {{
    "scene_type": "knowledge_consultation|personal_risk_scene|post_loss_help|risk_followup|clarification",
    "is_risk_scene": true,
    "user_intent": "knowledge|judge_risk|realtime_dissuasion|stop_loss|followup_answer|unclear",
    "reason": "依据用户原话说明",
    "confidence": 0.0
  }},
  "facts": {{
    "case_summary": "一句话概括用户处境",
    "counterparty_identity": "",
    "contact_channel": "",
    "platform_or_app": "",
    "requested_actions": [],
    "current_dangerous_actions": [],
    "user_actions": {{
      "has_paid": "true|false|unknown|likely_true|likely_false",
      "paid_amount": "",
      "has_received_small_rebate": "true|false|unknown",
      "has_unrecovered_money_loss": "true|false|unknown",
      "has_transferred_virtual_asset": "true|false|unknown|likely_true|likely_false",
      "virtual_asset_type": "",
      "can_still_login_or_control_asset": "true|false|unknown",
      "has_shared_account_password": "true|false|unknown",
      "has_changed_password_after_exposure": "true|false|unknown",
      "has_checked_account_bindings": "true|false|unknown",
      "has_unknown_binding_or_device": "true|false|unknown",
      "has_shared_code": "true|false|unknown",
      "has_screen_shared_or_remote_control": "true|false|unknown",
      "has_downloaded_app": "true|false|unknown",
      "has_clicked_link": "true|false|unknown",
      "has_provided_identity_or_bank": "true|false|unknown",
      "has_stopped_operation": "true|false|unknown",
      "has_preserved_evidence": "true|false|unknown",
      "has_reported_police": "true|false|unknown",
      "has_contacted_official_support": "true|false|unknown",
      "has_contacted_bank_or_payment_platform": "true|false|unknown",
      "has_enabled_login_protection": "true|false|unknown",
      "user_no_longer_believes_scammer": "true|false|unknown"
    }},
    "loss": {{
      "loss_confirmed": "true|false|unknown",
      "loss_type": "none|money|virtual_asset|account_control|identity_or_bank_info|device_or_remote|privacy|unknown",
      "amount_or_value": "",
      "evidence": ""
    }},
    "counterparty_behavior": [],
    "evidence": []
  }},
  "fraud": {{
    "primary_type": "知识目录中的诈骗类型名，未知则空",
    "candidate_types": [],
    "stage": "",
    "matched_feature_names": [],
    "feature_evidence": [{{"feature": "", "evidence": "", "confidence": 0.0}}]
  }},
  "action_progress": {{
    "turn_act": "risk_report|followup_answer|completion_confirmation|new_risk_signal|knowledge_question|smalltalk|unclear",
    "semantic_rewrite": "把用户本轮话语改写为明确语义，例如：用户表示已完成上一轮全部处置建议",
    "completion_scope": "none|explicit_actions|all_previous_advice|partial_previous_advice",
    "completed_actions": ["stopped_operation|no_more_transfer|stopped_contact|changed_game_password|checked_account_bindings|enabled_login_protection|preserved_evidence|reported_police|contacted_game_official_support|contacted_bank_or_payment_platform"],
    "new_risk_signal": false,
    "confidence": 0.0,
    "reason": "为什么这样理解用户本轮动作"
  }},
  "missing_facts": [{{"field": "", "why": "", "priority": 1}}],
  "ask_goal": "如果需要追问，用一句话描述追问目标；不需要则空",
  "urgency": "none|normal|urgent|critical"
}}
"""
    try:
        data = _call_json_llm(system_prompt.strip(), human_prompt.strip())
        return _normalize_analysis(data)
    except Exception as exc:
        logger.warning("语义事实研判超时或失败，使用确定性风险分析：%s", exc)
        return _fallback_semantic_analysis(state, str(exc))


def _normalize_analysis(data: Dict[str, Any]) -> Dict[str, Any]:
    scene = data.get("scene") if isinstance(data.get("scene"), dict) else {}
    facts = data.get("facts") if isinstance(data.get("facts"), dict) else {}
    user_actions = facts.get("user_actions") if isinstance(facts.get("user_actions"), dict) else {}
    loss = facts.get("loss") if isinstance(facts.get("loss"), dict) else {}
    fraud = data.get("fraud") if isinstance(data.get("fraud"), dict) else {}
    progress = data.get("action_progress") if isinstance(data.get("action_progress"), dict) else {}

    known_features = _all_feature_names()
    matched_features: List[str] = []
    for item in _text_list(fraud.get("matched_feature_names"), limit=16):
        if item in known_features and item not in matched_features:
            matched_features.append(item)
    for item in _text_list(fraud.get("matched_feature_names"), limit=16):
        if item not in matched_features:
            matched_features.append(item)

    primary_type = str(fraud.get("primary_type") or "").strip()
    profiles = _scam_profile_by_name()
    if primary_type not in profiles and primary_type:
        primary_type = next((name for name in profiles if primary_type in name or name in primary_type), primary_type)

    normalized = {
        "scene": {
            "scene_type": str(scene.get("scene_type") or "clarification"),
            "is_risk_scene": bool(scene.get("is_risk_scene", False)),
            "user_intent": str(scene.get("user_intent") or ""),
            "reason": str(scene.get("reason") or ""),
            "confidence": scene.get("confidence", 0),
        },
        "facts": {
            **facts,
            "user_actions": {
                **user_actions,
                "has_paid": _tri_bool(user_actions.get("has_paid")),
                "has_received_small_rebate": _tri_bool(user_actions.get("has_received_small_rebate")),
                "has_unrecovered_money_loss": _tri_bool(user_actions.get("has_unrecovered_money_loss")),
                "has_transferred_virtual_asset": _tri_bool(user_actions.get("has_transferred_virtual_asset")),
                "can_still_login_or_control_asset": _tri_bool(user_actions.get("can_still_login_or_control_asset")),
                "has_shared_account_password": _tri_bool(user_actions.get("has_shared_account_password")),
                "has_changed_password_after_exposure": _tri_bool(user_actions.get("has_changed_password_after_exposure")),
                "has_checked_account_bindings": _tri_bool(user_actions.get("has_checked_account_bindings")),
                "has_unknown_binding_or_device": _tri_bool(user_actions.get("has_unknown_binding_or_device")),
                "has_shared_code": _tri_bool(user_actions.get("has_shared_code")),
                "has_screen_shared_or_remote_control": _tri_bool(user_actions.get("has_screen_shared_or_remote_control")),
                "has_downloaded_app": _tri_bool(user_actions.get("has_downloaded_app")),
                "has_clicked_link": _tri_bool(user_actions.get("has_clicked_link")),
                "has_provided_identity_or_bank": _tri_bool(user_actions.get("has_provided_identity_or_bank")),
                "has_stopped_operation": _tri_bool(user_actions.get("has_stopped_operation")),
                "has_preserved_evidence": _tri_bool(user_actions.get("has_preserved_evidence")),
                "has_reported_police": _tri_bool(user_actions.get("has_reported_police")),
                "has_contacted_official_support": _tri_bool(user_actions.get("has_contacted_official_support")),
                "has_contacted_bank_or_payment_platform": _tri_bool(user_actions.get("has_contacted_bank_or_payment_platform")),
                "has_enabled_login_protection": _tri_bool(user_actions.get("has_enabled_login_protection")),
                "user_no_longer_believes_scammer": _tri_bool(user_actions.get("user_no_longer_believes_scammer")),
            },
            "loss": {
                **loss,
                "loss_confirmed": _tri_bool(loss.get("loss_confirmed")),
                "loss_type": str(loss.get("loss_type") or "unknown"),
            },
        },
        "fraud": {
            **fraud,
            "primary_type": primary_type,
            "candidate_types": _text_list(fraud.get("candidate_types"), limit=8),
            "stage": str(fraud.get("stage") or ""),
            "matched_feature_names": matched_features,
        },
        "action_progress": {
            "turn_act": str(progress.get("turn_act") or ""),
            "semantic_rewrite": str(progress.get("semantic_rewrite") or progress.get("rewritten_text") or ""),
            "completion_scope": str(progress.get("completion_scope") or "none"),
            "completed_actions": _action_ids(progress.get("completed_actions"), limit=16),
            "new_risk_signal": bool(progress.get("new_risk_signal", False)),
            "confidence": progress.get("confidence", 0),
            "reason": str(progress.get("reason") or ""),
        },
        "missing_facts": data.get("missing_facts") if isinstance(data.get("missing_facts"), list) else [],
        "ask_goal": str(data.get("ask_goal") or ""),
        "urgency": str(data.get("urgency") or "normal"),
    }
    _apply_completed_actions_to_facts(normalized)
    return normalized


def _feature_names_by_id() -> Dict[str, str]:
    return {
        str(item.get("feature_id") or ""): str(item.get("feature_name") or "")
        for item in _load_json_collection("scam_features")
        if item.get("feature_id") and item.get("feature_name")
    }


def _analysis_condition_text(analysis: Dict[str, Any] | None) -> str:
    if not isinstance(analysis, dict):
        return ""
    facts = analysis.get("facts") if isinstance(analysis.get("facts"), dict) else {}
    fraud = analysis.get("fraud") if isinstance(analysis.get("fraud"), dict) else {}
    scene = analysis.get("scene") if isinstance(analysis.get("scene"), dict) else {}
    progress = analysis.get("action_progress") if isinstance(analysis.get("action_progress"), dict) else {}
    loss = facts.get("loss") if isinstance(facts.get("loss"), dict) else {}
    actions = facts.get("user_actions") if isinstance(facts.get("user_actions"), dict) else {}
    values: List[Any] = [
        scene.get("reason"),
        fraud.get("stage"),
        progress.get("semantic_rewrite"),
        progress.get("reason"),
        facts.get("contact_channel"),
        facts.get("counterparty_identity"),
        facts.get("platform_or_app"),
        loss.get("loss_type"),
        loss.get("amount_or_value"),
        facts.get("requested_actions"),
        facts.get("current_dangerous_actions"),
        facts.get("evidence"),
    ]
    for key, value in actions.items():
        if _tri_bool(value) == TRUE:
            values.append(key)
    return _compact_text(json.dumps(values, ensure_ascii=False))


def _fact_or_action_condition_matches(term: str, analysis: Dict[str, Any] | None) -> bool:
    if not isinstance(analysis, dict):
        return False
    facts = analysis.get("facts") if isinstance(analysis.get("facts"), dict) else {}
    actions = facts.get("user_actions") if isinstance(facts.get("user_actions"), dict) else {}
    loss = facts.get("loss") if isinstance(facts.get("loss"), dict) else {}
    requested_text = _analysis_condition_text(analysis)
    compact_term = _compact_text(term)
    if compact_term and compact_term in requested_text:
        return True
    checks = {
        "已发生转账": actions.get("has_paid") == TRUE or loss.get("loss_confirmed") == TRUE,
        "已泄露验证码": actions.get("has_shared_code") == TRUE,
        "索要验证码": actions.get("has_shared_code") == TRUE or "验证码" in requested_text,
        "屏幕共享": actions.get("has_screen_shared_or_remote_control") == TRUE or "屏幕共享" in requested_text,
        "远程控制": actions.get("has_screen_shared_or_remote_control") == TRUE or "远程控制" in requested_text,
        "诱导下载陌生APP": actions.get("has_downloaded_app") == TRUE or "下载" in requested_text,
        "点击陌生链接": actions.get("has_clicked_link") == TRUE or "链接" in requested_text,
        "索要银行卡或身份信息": actions.get("has_provided_identity_or_bank") == TRUE or "银行卡" in requested_text or "身份证" in requested_text,
        "账号密码索取": actions.get("has_shared_account_password") == TRUE or "账号密码" in requested_text,
        "游戏账号密码索取": actions.get("has_shared_account_password") == TRUE or "账号密码" in requested_text,
        "虚拟资产已交付": actions.get("has_transferred_virtual_asset") == TRUE,
        "无法提现": "无法提现" in requested_text or "提现不了" in requested_text or "不能提现" in requested_text,
        "提现失败继续入金": "提现" in requested_text and any(word in requested_text for word in ["继续", "入金", "充值", "保证金"]),
        "要求继续补单": "补单" in requested_text,
        "要求缴纳解冻费": "解冻费" in requested_text or "解冻" in requested_text,
        "要求垫付资金": any(word in requested_text for word in ["垫付", "充值", "保证金", "转账", "先交"]),
        "保本高收益承诺": any(word in requested_text for word in ["保本", "稳赚", "高收益"]),
        "保本稳赚承诺": any(word in requested_text for word in ["保本", "稳赚", "高收益"]),
        "交易对象失联": any(word in requested_text for word in ["失联", "拉黑", "不回"]),
        "非本人账户收款": any(word in requested_text for word in ["第三方账户", "非本人", "朋友账户"]),
        "拒绝二次核验": any(word in requested_text for word in ["不方便", "不能电话", "不能视频", "别核实", "不要问"]),
        "要求保密催促": any(word in requested_text for word in ["保密", "不要告诉", "限时", "马上"]),
        "要求删除证据": any(word in requested_text for word in ["删除", "删掉", "保密"]),
    }
    return bool(checks.get(term, False))


def _condition_satisfied(term: str, feature_set: set[str], analysis: Dict[str, Any] | None) -> bool:
    if not term:
        return False
    if term in feature_set:
        return True
    feature_names_by_id = _feature_names_by_id()
    for rule in _load_json_collection("risk_rules"):
        for group in _as_list(rule.get("semantic_condition_groups")):
            for item in _as_list((group or {}).get("terms")):
                if not isinstance(item, dict) or item.get("term") != term:
                    continue
                for feature_id in _as_list(item.get("matched_feature_ids")):
                    if feature_names_by_id.get(str(feature_id)) in feature_set:
                        return True
    return _fact_or_action_condition_matches(term, analysis)


def _rule_matches(rule: Dict[str, Any], features: Iterable[str], fraud_type: str, analysis: Dict[str, Any] | None = None) -> bool:
    if not rule.get("enabled", True):
        return False
    rule_type = str(rule.get("fraud_type") or "")
    if rule_type and fraud_type and rule_type != fraud_type:
        return False
    feature_set = set(str(item) for item in features)
    conditions = rule.get("conditions") if isinstance(rule.get("conditions"), dict) else {}
    all_items = [str(item) for item in _as_list(conditions.get("all")) if str(item)]
    any_items = [str(item) for item in _as_list(conditions.get("any")) if str(item)]
    min_any = _number(conditions.get("min_any"), 0)
    if any(not _condition_satisfied(item, feature_set, analysis) for item in all_items):
        return False
    if min_any and sum(1 for item in any_items if _condition_satisfied(item, feature_set, analysis)) < min_any:
        return False
    return True


def _match_structured_rules(fraud_type: str, features: List[str], analysis: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for rule in _load_json_collection("risk_rules"):
        if _rule_matches(rule, features, fraud_type, analysis):
            matches.append(_without_prompt_only_fields(rule))
    matches.sort(key=lambda item: _number(item.get("risk_score"), 0), reverse=True)
    return matches


def _feature_weight_sum(feature_names: List[str]) -> int:
    weights = {
        str(item.get("feature_name") or ""): _number(item.get("risk_weight"), 0)
        for item in _load_json_collection("scam_features")
    }
    return min(100, sum(weights.get(name, 0) for name in feature_names))


def decide_risk_from_analysis(analysis: Dict[str, Any]) -> Dict[str, Any]:
    scene = analysis.get("scene") or {}
    facts = analysis.get("facts") or {}
    actions = facts.get("user_actions") or {}
    loss = facts.get("loss") or {}
    fraud = analysis.get("fraud") or {}
    features = _text_list(fraud.get("matched_feature_names"), limit=16)
    fraud_type = str(fraud.get("primary_type") or "").strip() or "未知"
    raw_candidate_types = [fraud_type, *_text_list(fraud.get("candidate_types"), limit=8)]
    type_candidates = canonicalize_fraud_types(raw_candidate_types, limit=8)
    primary_metadata = fraud_type_metadata(fraud_type)
    rule_fraud_type = standard_name_for(fraud_type) if primary_metadata.get("known") else fraud_type
    matched_rules = _match_structured_rules(rule_fraud_type, features, analysis)

    risk_scene = bool(scene.get("is_risk_scene"))
    active_danger = bool(_text_list(facts.get("current_dangerous_actions"), limit=8))
    exposure = any(
        actions.get(key) == TRUE
        for key in [
            "has_shared_code",
            "has_screen_shared_or_remote_control",
            "has_downloaded_app",
            "has_clicked_link",
            "has_provided_identity_or_bank",
            "has_transferred_virtual_asset",
        ]
    )
    money_loss = actions.get("has_paid") == TRUE and actions.get("has_unrecovered_money_loss") != FALSE
    asset_loss = (
        actions.get("has_transferred_virtual_asset") == TRUE
        or loss.get("loss_type") in {"virtual_asset", "account_control"}
        or loss.get("loss_confirmed") == TRUE
    )
    has_loss_or_exposure = bool(money_loss or asset_loss or exposure)
    requested_actions = bool(_text_list(facts.get("requested_actions"), limit=8))

    top_rule_score = _number((matched_rules[0] if matched_rules else {}).get("risk_score"), 0)
    score = max(top_rule_score, _feature_weight_sum(features))
    if not risk_scene:
        risk_level = "none"
        risk_class = "non_risk"
        score = 0
    elif active_danger or analysis.get("urgency") == "critical":
        risk_level = "critical"
        risk_class = "active_critical"
        score = max(score, 95)
    elif has_loss_or_exposure:
        risk_level = "high"
        risk_class = "loss_or_exposure"
        score = max(score, 90)
    elif requested_actions or score >= 85 or analysis.get("urgency") == "urgent":
        risk_level = "high"
        risk_class = "pre_loss_high"
        score = max(score, 80)
    elif features:
        risk_level = "medium"
        risk_class = "pre_loss_suspicious"
        score = max(score, 45)
    else:
        risk_level = "medium_low"
        risk_class = "uncertain_personal_risk"
        score = max(score, 20) if risk_scene else 0

    display_level = {
        "none": "不进入风险场景",
        "medium_low": "中低风险",
        "medium": "中风险",
        "high": "高风险",
        "critical": "紧急风险",
    }.get(risk_level, risk_level)
    stage = str(fraud.get("stage") or (matched_rules[0].get("stages", [""])[0] if matched_rules else "") or "")
    reported_confidence = analysis.get("type_confidence")
    try:
        type_confidence = float(reported_confidence)
    except (TypeError, ValueError):
        type_confidence = 0.96 if matched_rules and primary_metadata.get("known") else 0.84 if primary_metadata.get("known") else 0.0
    type_confidence = max(0.0, min(1.0, type_confidence))
    primary_type = primary_metadata.get("primary_type") or fraud_type
    candidate_types = [item.get("primary_type", "") for item in type_candidates if item.get("primary_type")]
    candidate_type_ids = [item.get("fraud_type_id", "") for item in type_candidates if item.get("fraud_type_id")]

    return {
        "is_risk_scene": risk_scene,
        "risk_level": risk_level,
        "display_risk_level": display_level,
        "risk_class": risk_class,
        "risk_score": min(100, score),
        "fraud_type": fraud_type,
        "fraud_type_id": primary_metadata.get("fraud_type_id", ""),
        "primary_type": primary_type,
        "candidate_types": candidate_types,
        "candidate_type_ids": candidate_type_ids,
        "type_candidates": type_candidates,
        "type_confidence": type_confidence,
        "confidence": type_confidence,
        "fraud_stage": stage,
        "risk_features": features,
        "matched_rules": matched_rules[:5],
        "has_loss_or_exposure": has_loss_or_exposure,
        "active_danger": active_danger,
        "requested_actions": _text_list(facts.get("requested_actions"), limit=8),
        "current_dangerous_actions": _text_list(facts.get("current_dangerous_actions"), limit=8),
        "reason": scene.get("reason") or "LLM 语义事实结合结构化规则裁决",
        "case_context_type": 3 if not risk_scene else 2 if has_loss_or_exposure else 1,
        "case_context_label": "反诈学习" if not risk_scene else "被骗求助" if has_loss_or_exposure else "劝阻咨询",
    }


def _progress_confidence(progress: Dict[str, Any]) -> float:
    try:
        return float(progress.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def _completion_signal(analysis: Dict[str, Any]) -> bool:
    progress = _ensure_action_progress(analysis)
    turn_act = str(progress.get("turn_act") or "")
    scope = str(progress.get("completion_scope") or "none")
    completed = _action_ids(progress.get("completed_actions"), limit=24)
    confidence = _progress_confidence(progress)
    return bool(
        (turn_act == "completion_confirmation" and confidence >= 0.55)
        or (scope in {"all_previous_advice", "explicit_actions", "partial_previous_advice"} and completed)
        or len(completed) >= 2
    )


def _no_engagement_resolution_signal(state: Dict[str, Any], analysis: Dict[str, Any], decision: Dict[str, Any]) -> bool:
    facts = analysis.get("facts") or {}
    actions = facts.get("user_actions") or {}
    text = _compact_text(str(state.get("original_query") or ""))
    if not text or not bool((analysis.get("scene") or {}).get("is_risk_scene")):
        return False
    if decision.get("has_loss_or_exposure") or decision.get("active_danger"):
        return False
    if _text_list(facts.get("requested_actions"), limit=4) or _text_list(facts.get("current_dangerous_actions"), limit=4):
        return False
    exposed_keys = [
        "has_paid",
        "has_shared_code",
        "has_screen_shared_or_remote_control",
        "has_downloaded_app",
        "has_clicked_link",
        "has_provided_identity_or_bank",
        "has_transferred_virtual_asset",
        "has_shared_account_password",
    ]
    if any(actions.get(key) == TRUE for key in exposed_keys):
        return False
    no_contact = any(
        word in text
        for word in [
            "没有联系",
            "没联系",
            "未联系",
            "没有打电话",
            "没打电话",
            "没有加微信",
            "没加微信",
            "没有加qq",
            "没加qq",
            "没有扫码",
            "没扫码",
        ]
    )
    passive_lookup = any(word in text for word in ["就看看", "只是看看", "只看看", "想知道", "了解一下"])
    no_exposure = any(
        word in text
        for word in [
            "没有交钱",
            "没交钱",
            "没有转账",
            "没转账",
            "没有给信息",
            "没给信息",
            "没有提供",
            "没提供",
            "没有填写",
            "没填写",
            "没有下载",
            "没下载",
        ]
    )
    return bool(no_contact or (passive_lookup and no_exposure))


def _action_completed(analysis: Dict[str, Any], *action_ids: str) -> bool:
    progress = _ensure_action_progress(analysis)
    completed = set(_action_ids(progress.get("completed_actions"), limit=24))
    return any(action_id in completed for action_id in action_ids)


def _has_substantive_current_risk_facts(analysis: Dict[str, Any], decision: Dict[str, Any]) -> bool:
    facts = analysis.get("facts") if isinstance(analysis.get("facts"), dict) else {}
    actions = facts.get("user_actions") if isinstance(facts.get("user_actions"), dict) else {}
    loss = facts.get("loss") if isinstance(facts.get("loss"), dict) else {}
    progress = _ensure_action_progress(analysis)
    if bool(progress.get("new_risk_signal")) or str(progress.get("turn_act") or "") in {"risk_report", "new_risk_signal"}:
        return True
    if decision.get("active_danger") or decision.get("has_loss_or_exposure"):
        return True
    if _text_list(facts.get("requested_actions"), limit=8) or _text_list(facts.get("current_dangerous_actions"), limit=8):
        return True
    if _text_list(facts.get("evidence"), limit=8) or _text_list(facts.get("counterparty_behavior"), limit=8):
        return True
    if any(str(facts.get(key) or "").strip() for key in ["counterparty_identity", "contact_channel", "platform_or_app", "payment_channel", "withdrawal_status"]):
        return True
    loss_type = str(loss.get("loss_type") or "").strip()
    if loss.get("loss_confirmed") == TRUE or str(loss.get("amount_or_value") or "").strip():
        return True
    if loss_type and loss_type not in {"none", UNKNOWN}:
        return True
    exposure_keys = [
        "has_paid",
        "has_received_small_rebate",
        "has_unrecovered_money_loss",
        "has_transferred_virtual_asset",
        "can_still_login_or_control_asset",
        "has_shared_account_password",
        "has_unknown_binding_or_device",
        "has_shared_code",
        "has_screen_shared_or_remote_control",
        "has_downloaded_app",
        "has_clicked_link",
        "has_provided_identity_or_bank",
    ]
    return any(_tri_bool(actions.get(key)) != UNKNOWN for key in exposure_keys)


def _should_carry_previous_closed_case(
    analysis: Dict[str, Any],
    decision: Dict[str, Any],
    previous_case: Dict[str, Any],
) -> bool:
    if not _case_state_is_closed(previous_case):
        return False
    if _case_closure_summary_delivered(previous_case):
        return False
    if _has_substantive_current_risk_facts(analysis, decision):
        return False
    progress = _ensure_action_progress(analysis)
    scene = analysis.get("scene") if isinstance(analysis.get("scene"), dict) else {}
    turn_act = str(progress.get("turn_act") or "")
    scene_type = str(scene.get("scene_type") or "")
    return bool(
        turn_act in {"followup_answer", "completion_confirmation", "smalltalk", "unclear"}
        or scene_type in {"risk_followup", "clarification", "smalltalk"}
        or not bool(scene.get("is_risk_scene"))
    )


def apply_case_lifecycle(
    state: Dict[str, Any],
    analysis: Dict[str, Any],
    decision: Dict[str, Any],
) -> Dict[str, Any]:
    """Add resolution/case lifecycle facts without reintroducing the old template workflow."""
    _apply_completed_actions_to_facts(analysis)
    scene = analysis.get("scene") or {}
    facts = analysis.get("facts") or {}
    actions = facts.get("user_actions") or {}
    loss = facts.get("loss") or {}
    progress = _ensure_action_progress(analysis)
    completed = _action_ids(progress.get("completed_actions"), limit=24)
    memory_context = state.get("memory_context") if isinstance(state.get("memory_context"), dict) else {}
    previous_case = memory_context.get("case_state") if isinstance(memory_context.get("case_state"), dict) else {}
    if not previous_case and isinstance(state.get("case_state"), dict):
        previous_case = state.get("case_state") or {}
    previous_resolution = previous_case.get("resolution") if isinstance(previous_case.get("resolution"), dict) else {}
    if not previous_resolution and isinstance(previous_case.get("resolution_memory"), dict):
        previous_resolution = previous_case.get("resolution_memory") or {}
    previous_closed = _case_state_is_closed(previous_case)
    previous_education_delivered = bool(
        previous_case.get("post_resolution_education_delivered")
        or previous_resolution.get("post_resolution_education_delivered")
    )
    education_already_delivered = previous_education_delivered
    brief_ack = _is_brief_ack_text(str(state.get("original_query") or ""))

    if not bool(scene.get("is_risk_scene")):
        lifecycle = {
            "case_status": "non_risk_task",
            "active_workflow": "idle",
            "post_resolution_answer_mode": "normal",
            "post_resolution_education_delivered": education_already_delivered,
            "reason": "本轮不是个人风险处境。",
        }
        resolution = {
            "risk_resolved": False,
            "resolution_level": "none",
            "completed_actions": completed,
            "missing_resolution_actions": [],
            "missing_action_ids": [],
            "ready_for_education": False,
            "post_resolution_education_delivered": education_already_delivered,
            "judge_source": "semantic_lifecycle",
            "reason": lifecycle["reason"],
            "closure_standard": {"can_close": False},
        }
        analysis["case_lifecycle"] = lifecycle
        analysis["resolution"] = resolution
        return analysis

    fraud_type = str((analysis.get("fraud") or {}).get("primary_type") or decision.get("fraud_type") or "")
    is_game = "游戏" in fraud_type or bool(actions.get("virtual_asset_type"))
    has_money_loss = actions.get("has_paid") == TRUE and actions.get("has_unrecovered_money_loss") != FALSE
    has_loss_or_exposure = bool(decision.get("has_loss_or_exposure") or has_money_loss or loss.get("loss_confirmed") == TRUE)
    password_exposed = actions.get("has_shared_account_password") == TRUE
    requested_actions = _text_list(facts.get("requested_actions"), limit=8)
    active_danger = bool(decision.get("active_danger") or progress.get("new_risk_signal"))
    carry_previous_closed = bool(
        previous_closed
        and not active_danger
        and _should_carry_previous_closed_case(analysis, decision, previous_case)
    )
    if previous_closed and not carry_previous_closed:
        education_already_delivered = False
    no_engagement_resolved = _no_engagement_resolution_signal(state, analysis, decision)
    if no_engagement_resolved:
        _add_completed_action(analysis, "stopped_operation")
        _apply_completed_actions_to_facts(analysis)
        facts = analysis.get("facts") or {}
        actions = facts.get("user_actions") or {}
        progress = _ensure_action_progress(analysis)
        completed = _action_ids(progress.get("completed_actions"), limit=24)
        progress["turn_act"] = "completion_confirmation"
        progress["completion_scope"] = "all_previous_advice"
        progress["confidence"] = max(_progress_confidence(progress), 0.9)
        progress["reason"] = "用户明确未联系对方或只是查看，没有资金、验证码、屏幕共享、陌生App或个人信息暴露，风险场景可收尾。"
        analysis["ask_goal"] = ""
        analysis["missing_facts"] = []
    completion_signal = _completion_signal(analysis) or no_engagement_resolved

    danger_stopped = (
        actions.get("has_stopped_operation") == TRUE
        or _action_completed(analysis, "stopped_operation", "no_more_transfer", "stopped_contact")
        or (completion_signal and not active_danger)
    )
    evidence_done = actions.get("has_preserved_evidence") == TRUE or _action_completed(analysis, "preserved_evidence")
    police_done = actions.get("has_reported_police") == TRUE or _action_completed(analysis, "reported_police")
    official_done = (
        actions.get("has_contacted_official_support") == TRUE
        or _action_completed(analysis, "contacted_game_official_support")
    )
    bank_or_payment_done = (
        actions.get("has_contacted_bank_or_payment_platform") == TRUE
        or _action_completed(analysis, "contacted_bank_or_payment_platform")
    )
    bindings_done = actions.get("has_checked_account_bindings") == TRUE or _action_completed(analysis, "checked_account_bindings")
    login_protection_done = actions.get("has_enabled_login_protection") == TRUE or _action_completed(analysis, "enabled_login_protection")
    password_changed = actions.get("has_changed_password_after_exposure") == TRUE or _action_completed(analysis, "changed_game_password")
    can_control_account = actions.get("can_still_login_or_control_asset") == TRUE
    account_stable = True
    if is_game:
        if password_exposed:
            account_stable = bool(password_changed and can_control_account and (bindings_done or official_done or login_protection_done))
        else:
            account_stable = actions.get("can_still_login_or_control_asset") != FALSE

    money_resolution_done = True
    if has_money_loss:
        money_resolution_done = bool(evidence_done and (police_done or bank_or_payment_done))

    missing: List[Dict[str, str]] = []
    if requested_actions and not danger_stopped:
        missing.append({"id": "stopped_operation", "label": ACTION_LABELS["no_more_transfer"]})
    if is_game and password_exposed and not password_changed:
        missing.append({"id": "changed_game_password", "label": ACTION_LABELS["changed_game_password"]})
    if is_game and password_exposed and password_changed and not (bindings_done or official_done or login_protection_done):
        missing.append({"id": "checked_account_bindings", "label": ACTION_LABELS["checked_account_bindings"]})
    if has_money_loss and not evidence_done:
        missing.append({"id": "preserved_evidence", "label": ACTION_LABELS["preserved_evidence"]})
    if has_money_loss and not (police_done or bank_or_payment_done):
        missing.append({"id": "reported_police", "label": ACTION_LABELS["reported_police"]})

    close_ready = bool(completion_signal and danger_stopped and account_stable and money_resolution_done)
    if active_danger and not completion_signal:
        case_status = "active"
        resolution_level = "active"
        resolved = False
        reason = "本轮出现新的危险动作或风险信号，风险事件保持活跃。"
    elif close_ready:
        case_status = "stop_loss_done" if has_loss_or_exposure else "prevented"
        resolution_level = "closed_after_loss" if has_loss_or_exposure else "prevented_before_loss"
        resolved = True
        reason = "用户语义确认已完成上一轮处置建议，且关键止损动作已经满足。"
    elif danger_stopped or completed:
        case_status = "mitigated"
        resolution_level = "partial"
        resolved = False
        reason = "用户已经完成部分止损动作，但还未满足当前场景全部收尾条件。"
    else:
        case_status = "active"
        resolution_level = "active"
        resolved = False
        reason = "当前风险仍需继续处置或确认。"

    if carry_previous_closed:
        previous_status = str(previous_case.get("case_status") or "")
        case_status = previous_status if previous_status in CLOSED_CASE_STATUSES else case_status
        resolved = True
        if brief_ack:
            reason = "风险事件此前已完成处置，本轮只是用户简短确认。"

    if case_status in CLOSED_CASE_STATUSES or resolved:
        if not education_already_delivered:
            post_resolution_answer_mode = "closure_with_education"
            post_resolution_education_delivered = True
        elif brief_ack:
            post_resolution_answer_mode = "brief_ack_after_education"
            post_resolution_education_delivered = True
        else:
            post_resolution_answer_mode = "closed_followup"
            post_resolution_education_delivered = True
    elif case_status == "mitigated":
        post_resolution_answer_mode = "partial_resolution"
        post_resolution_education_delivered = education_already_delivered
    else:
        post_resolution_answer_mode = "active_risk"
        post_resolution_education_delivered = education_already_delivered

    lifecycle = {
        "case_status": case_status,
        "active_workflow": "idle" if case_status in CLOSED_CASE_STATUSES else "risk_case_flow",
        "post_resolution_answer_mode": post_resolution_answer_mode,
        "post_resolution_education_delivered": post_resolution_education_delivered,
        "completion_signal": completion_signal,
        "danger_stopped": danger_stopped,
        "account_stable": account_stable,
        "money_resolution_done": money_resolution_done,
        "missing_action_ids": [item["id"] for item in missing],
        "reason": reason,
    }
    resolution = {
        "risk_resolved": resolved,
        "resolution_level": resolution_level,
        "completed_actions": completed,
        "missing_resolution_actions": [item["label"] for item in missing],
        "missing_action_ids": [item["id"] for item in missing],
        "unsafe_signals": _text_list(facts.get("current_dangerous_actions"), limit=8),
        "ready_for_education": resolved,
        "post_resolution_education_delivered": post_resolution_education_delivered,
        "post_resolution_answer_mode": post_resolution_answer_mode,
        "judge_source": "semantic_lifecycle",
        "reason": reason,
        "closure_standard": {
            "can_close": resolved,
            "requires_no_more_transfer": bool(requested_actions),
            "requires_account_secured": bool(is_game and password_exposed),
            "requires_evidence_or_report": bool(has_money_loss),
        },
    }
    analysis["case_lifecycle"] = lifecycle
    analysis["resolution"] = resolution
    if resolved:
        analysis["ask_goal"] = ""
        analysis["missing_facts"] = []
    return analysis


def _decision_with_lifecycle(decision: Dict[str, Any], analysis: Dict[str, Any]) -> Dict[str, Any]:
    lifecycle = analysis.get("case_lifecycle") if isinstance(analysis.get("case_lifecycle"), dict) else {}
    resolution = analysis.get("resolution") if isinstance(analysis.get("resolution"), dict) else {}
    if not lifecycle:
        return decision
    updated = dict(decision)
    updated["case_status"] = lifecycle.get("case_status", "active")
    updated["risk_resolved"] = bool(resolution.get("risk_resolved", False))
    updated["ready_for_education"] = bool(resolution.get("ready_for_education", False))
    updated["resolution_level"] = resolution.get("resolution_level", "")
    updated["post_resolution_answer_mode"] = lifecycle.get("post_resolution_answer_mode", "")
    updated["post_resolution_education_delivered"] = bool(lifecycle.get("post_resolution_education_delivered", False))
    return updated


def _slots_from_analysis(analysis: Dict[str, Any]) -> Dict[str, Any]:
    facts = analysis.get("facts") or {}
    actions = facts.get("user_actions") or {}
    loss = facts.get("loss") or {}
    return {
        "has_paid": actions.get("has_paid", UNKNOWN),
        "has_received_rebate": actions.get("has_received_small_rebate", UNKNOWN),
        "has_unrecovered_loss": actions.get("has_unrecovered_money_loss", UNKNOWN),
        "loss_amount": actions.get("paid_amount") or loss.get("amount_or_value") or "",
        "has_transferred_virtual_asset": actions.get("has_transferred_virtual_asset", UNKNOWN),
        "virtual_asset_type": actions.get("virtual_asset_type") or "",
        "can_still_login_or_control_asset": actions.get("can_still_login_or_control_asset", UNKNOWN),
        "has_shared_account_password": actions.get("has_shared_account_password", UNKNOWN),
        "has_changed_password_after_exposure": actions.get("has_changed_password_after_exposure", UNKNOWN),
        "has_checked_account_bindings": actions.get("has_checked_account_bindings", UNKNOWN),
        "has_unknown_binding_or_device": actions.get("has_unknown_binding_or_device", UNKNOWN),
        "has_shared_code": actions.get("has_shared_code", UNKNOWN),
        "has_screen_share": actions.get("has_screen_shared_or_remote_control", UNKNOWN),
        "has_downloaded_app": actions.get("has_downloaded_app", UNKNOWN),
        "has_clicked_link": actions.get("has_clicked_link", UNKNOWN),
        "has_provided_identity_or_bank": actions.get("has_provided_identity_or_bank", UNKNOWN),
        "has_stopped_operation": actions.get("has_stopped_operation", UNKNOWN),
        "has_preserved_evidence": actions.get("has_preserved_evidence", UNKNOWN),
        "has_reported_police": actions.get("has_reported_police", UNKNOWN),
        "has_contacted_official_support": actions.get("has_contacted_official_support", UNKNOWN),
        "has_contacted_bank_or_payment_platform": actions.get("has_contacted_bank_or_payment_platform", UNKNOWN),
        "has_enabled_login_protection": actions.get("has_enabled_login_protection", UNKNOWN),
        "user_no_longer_believes_scammer": actions.get("user_no_longer_believes_scammer", UNKNOWN),
        "completed_actions": _action_ids((analysis.get("action_progress") or {}).get("completed_actions"), limit=24),
        "current_requested_action": "；".join(_text_list(facts.get("requested_actions"), limit=6)),
        "contact_channel": str(facts.get("contact_channel") or ""),
        "opponent_identity": str(facts.get("counterparty_identity") or ""),
        "platform_or_app": str(facts.get("platform_or_app") or ""),
    }


def _retrieved_docs(knowledge: Dict[str, Any]) -> List[Dict[str, Any]]:
    docs: List[Dict[str, Any]] = []
    for key in [
        "features",
        "risk_rules",
        "prevention_advice",
        "typical_cases",
        "law_guides",
        "report_guides",
        "evidence_guides",
    ]:
        for item in _as_list(knowledge.get(key)):
            if not isinstance(item, dict):
                continue
            docs.append(
                {
                    "id": (
                        item.get("feature_id")
                        or item.get("rule_id")
                        or item.get("advice_id")
                        or item.get("case_id")
                        or item.get("law_id")
                        or item.get("guide_id")
                        or item.get("scam_id")
                        or ""
                    ),
                    "knowledge_type": key,
                    "fraud_type": item.get("fraud_type") or (knowledge.get("scam_profile") or {}).get("name", ""),
                    "title": (
                        item.get("feature_name")
                        or item.get("title")
                        or item.get("topic")
                        or item.get("advice")
                        or item.get("scenario")
                        or item.get("rule_id")
                        or ""
                    ),
                    "summary": (
                        item.get("explanation")
                        or item.get("summary")
                        or item.get("plain_summary")
                        or item.get("advice")
                        or item.get("suggested_summary_template")
                        or item.get("warning")
                        or ""
                    ),
                    "risk_level": item.get("risk_level", ""),
                    "retrieval_source": "structured_semantic_knowledge",
                }
            )
    return docs[:10]


def _should_emit_closure_summary(analysis: Dict[str, Any]) -> bool:
    """Use the semantic action analysis, not text matching, to decide summary timing."""
    progress = _ensure_action_progress(analysis)
    turn_act = str(progress.get("turn_act") or "")
    scope = str(progress.get("completion_scope") or "none")
    completed = _action_ids(progress.get("completed_actions"), limit=24)
    confidence = _progress_confidence(progress)
    return bool(
        turn_act == "completion_confirmation"
        and scope in {"all_previous_advice", "explicit_actions"}
        and completed
        and confidence >= 0.65
    )


def build_structured_safety_card(
    analysis: Dict[str, Any],
    decision: Dict[str, Any],
) -> Dict[str, Any]:
    """Return executable outbound safety actions for a risk response."""
    facts = analysis.get("facts") if isinstance(analysis.get("facts"), dict) else {}
    actions = facts.get("user_actions") if isinstance(facts.get("user_actions"), dict) else {}
    requested = _text_list(facts.get("requested_actions"), limit=8)
    features = set(_text_list(decision.get("risk_features"), limit=20))
    has_exposure = bool(decision.get("has_loss_or_exposure"))
    has_payment = actions.get("has_paid") == TRUE or "已发生转账" in features
    stop_actions: List[str] = []
    if requested or features:
        stop_actions.append("立即停止当前转账、充值、补单、交费或交付账号/银行卡的动作")
    if "屏幕共享" in features or "远程控制" in features or actions.get("has_screen_shared_or_remote_control") == TRUE:
        stop_actions.append("立刻关闭屏幕共享/远程控制并退出对方要求打开的 App")
    if "索要验证码" in features or "账号密码索取" in features or actions.get("has_shared_code") == TRUE:
        stop_actions.append("不要提供验证码、密码、银行卡或身份证信息")
    verify_actions = ["通过官方 App、官网客服电话或线下机构独立核验，不使用对方提供的联系方式"]
    evidence_actions = ["保存聊天记录、来电号码、链接、账号、收款码和转账凭证"]
    loss_actions: List[str] = []
    if has_payment or has_exposure:
        loss_actions.append("如已付款或泄露信息，立即联系银行/支付平台申请止付、冻结或改密，并拨打 110/96110")
    if not stop_actions:
        stop_actions.append("在身份和交易未独立核验前，先暂停任何付款和信息提交")
    return {
        "version": "safety-card-v1",
        "status": "active" if decision.get("is_risk_scene") else "not_applicable",
        "risk_stage": decision.get("fraud_stage", ""),
        "fraud_type_id": decision.get("fraud_type_id", ""),
        "stop_current_action": stop_actions,
        "official_verification": verify_actions,
        "preserve_evidence": evidence_actions,
        "post_loss_response": loss_actions,
        "required_categories": [
            "stop_current_action",
            "official_verification",
            "preserve_evidence",
            *(["post_loss_response"] if loss_actions else []),
        ],
    }


def _deterministic_realtime_answer(
    state: Dict[str, Any],
    analysis: Dict[str, Any],
    decision: Dict[str, Any],
) -> str:
    """Produce a useful first response without depending on an LLM."""
    fraud_type = str(decision.get("fraud_type") or "未知风险").strip() or "未知风险"
    features = _text_list(decision.get("risk_features"), limit=3)
    evidence = _text_list((analysis.get("facts") or {}).get("evidence"), limit=3)
    evidence = evidence or features or ["对方正在要求你绕开官方流程并执行高风险操作"]
    card = build_structured_safety_card(analysis, decision)
    lines = [f"判断为：{fraud_type}。先不要继续按对方要求操作。"]
    lines.append("我这样判断，主要是因为：")
    lines.extend(f"{index}. {item}" for index, item in enumerate(evidence[:3], start=1))
    lines.append("现在先做：")
    action_lines = list(card["stop_current_action"]) + list(card["official_verification"]) + list(card["preserve_evidence"])
    action_lines.extend(card["post_loss_response"])
    lines.extend(f"{index}. {item}" for index, item in enumerate(action_lines, start=1))
    ask_goal = str(analysis.get("ask_goal") or "").strip()
    if ask_goal:
        lines.append(f"\n下一步请确认：{ask_goal}")
    return "\n".join(lines)


def _answer_satisfies_safety_gate(answer: str, decision: Dict[str, Any], card: Dict[str, Any]) -> bool:
    text = _compact_text(answer)
    if not text or not decision.get("is_risk_scene"):
        return bool(text)
    type_name = str(decision.get("fraud_type") or "").strip()
    has_type = not type_name or type_name in answer or standard_name_for(type_name) in answer
    stop = any(token in text for token in ("不要", "停止", "暂停", "别再", "关闭共享", "退出"))
    verify = any(token in text for token in ("官方", "核实", "核验", "回拨"))
    evidence = any(token in text for token in ("保存", "保留", "截图", "证据"))
    loss_required = bool(card.get("post_loss_response"))
    loss_ok = not loss_required or any(token in text for token in ("止付", "冻结", "报警", "96110", "110"))
    return bool(has_type and stop and verify and evidence and loss_ok)


def generate_realtime_answer(
    state: Dict[str, Any],
    analysis: Dict[str, Any],
    decision: Dict[str, Any],
    knowledge: Dict[str, Any],
) -> str:
    """Generate the final answer with a bounded LLM call and a safety gate."""
    known_facts = _known_fact_lines(state, analysis, decision)
    lifecycle = analysis.get("case_lifecycle") if isinstance(analysis.get("case_lifecycle"), dict) else {}
    resolution = analysis.get("resolution") if isinstance(analysis.get("resolution"), dict) else {}
    is_closed = str(lifecycle.get("case_status") or "") in CLOSED_CASE_STATUSES or bool(resolution.get("risk_resolved"))
    post_mode = str(lifecycle.get("post_resolution_answer_mode") or resolution.get("post_resolution_answer_mode") or "")
    closure_summary_needed = bool(is_closed and post_mode == "closure_with_education" and _should_emit_closure_summary(analysis))
    closure_answer_mode = (
        "expert_closure_summary"
        if closure_summary_needed
        else "closed_followup_without_summary"
        if is_closed
        else "normal_risk_or_knowledge_answer"
    )
    action_progress = analysis.get("action_progress") if isinstance(analysis.get("action_progress"), dict) else {}
    if (
        is_closed
        and not closure_summary_needed
        and _is_brief_ack_text(str(state.get("original_query") or ""))
        and not action_progress
    ):
        return ASSISTANT_CLOSED_SCENE_TEXT
    followup_goal = analysis.get("ask_goal") or (
        "无；语义分析确认用户本轮是在承接上一轮处置建议并已完成关键动作。本轮请以反诈专家口吻做自然收尾复盘，既复盘本案，也给同类防范建议。"
        if closure_summary_needed
        else "无；语义分析没有确认用户本轮完成新的处置动作。本轮不要输出收尾复盘或总结，只根据用户本轮语义自然回应。"
        if is_closed
        else "无；本轮不要追问，用行动建议收口。"
    )
    prompt = f"""
你是一个自然、克制、实时的反诈智能体。请直接回答用户，中文输出。

表达要求：
1. 不要机械输出“风险等级、风险分、当前阶段、依据：...”这类表单字段。
2. 不要要求用户回复固定词，不要说“只需回答是或否”“回复已保留”。
3. 如果是风险场景，先回应用户本轮问题，再明确阻止最危险动作，再结合用户原话解释风险；只有【本轮追问目标】不是“无”时，最后才问 1 个最关键问题。
4. 如果只是知识咨询，不进入风险场景，不追问用户有没有转账，正常科普。
5. 追问必须贴合场景。例如游戏交易要问账号是否已给对方、是否还能登录、是否走官方担保；刷单返利要问是否需要垫付/充值/补单。
6. 不编造事实，不索要验证码、身份证号、银行卡号等敏感明文。
7. 不要重复追问【已确认事实】里已经有答案的问题；如果用户问“怎么追回/怎么办/判断一下”，优先给结论和下一步行动，不要把已回答事实再问一遍。
8. 如果【本轮追问目标】为“无”，不要以疑问句结尾，改用简短行动清单、明确判断或自然收口。
9. 必须服从【收尾回答模式】：
   - expert_closure_summary：语义分析已经确认用户本轮完成了关键处置动作。请像一位有经验的反诈民警/反诈老师一样自然收尾，口吻亲切、稳重、有人味。内容包含两层：先用用户听得懂的话复盘“这次为什么危险、骗子抓住了哪些点、用户哪些处置做对了”；再给同类骗局防范建议。不要写“本次诈骗总结”“个性化总结”“相关防范建议”这类栏目标题，不要说“这次先稳住了”，不要把字段逐条拼接成报告。
   - closed_followup_without_summary：案件状态可能已经关闭，但语义分析没有确认用户本轮完成新的处置动作。不要输出收尾复盘，不要总结旧案，只对用户本轮话作自然回应。
   - normal_risk_or_knowledge_answer：按正常风险劝阻或知识问答回答。
10. 收尾复盘可以用自然过渡，例如“那我帮你把这件事简单复盘一下”“这次真正危险的地方有两个”“以后碰到类似情况，先看这几个信号”。但不要固定套模板。
11. 如果用户只是表达理解、收到、知道、明白、感谢，而语义分析没有把本轮判为 completion_confirmation，不要输出诈骗总结。
12. 生成风险判断和劝阻话术时，必须结合【命中的知识库材料】中的结构化诈骗画像/特征、规则化风险条件、半结构化案例/防范建议/报案指南/证据指南/法律处置常识。不要只泛泛说“这是诈骗”，要说明命中了哪些关键手法或损失信号。
13. 用户问追回、报案、证据、止付时，优先使用 report_guides、evidence_guides、law_guides；用户问为什么危险时，优先使用 risk_rules、features、critical_facts、loss_signals。
14. 【本轮追问目标】必须严格服从；不要自行追加第二个问题。
15. 如果【用户本轮输入】或历史里包含【内部情绪提示】，该段不是用户事实，只用于调整表达方式；不要在回答中提到“语音识别”“情绪识别”或提示内容。
16. 回答要更像真实反诈助手在陪用户处理事：焦虑/惊慌时先稳住，愤怒时先承接再给证据和举报路径，困惑时先讲清判断依据。

【用户本轮输入】
{state.get("original_query", "")}

【最近对话】
{json.dumps(_history_for_prompt(state), ensure_ascii=False)}

【已确认事实】
{chr(10).join(known_facts) if known_facts else "无"}

【本轮动作语义】
{json.dumps(analysis.get("action_progress", {}), ensure_ascii=False)}

【风险收尾状态】
{json.dumps({"case_lifecycle": lifecycle, "resolution": resolution}, ensure_ascii=False)}

【收尾回答模式】
{json.dumps({"mode": closure_answer_mode, "closure_summary_needed": closure_summary_needed}, ensure_ascii=False)}

【本轮追问目标】
{followup_goal}

【语义事实】
{json.dumps(analysis, ensure_ascii=False)}

【规则裁决】
{json.dumps(decision, ensure_ascii=False)}

【命中的知识库材料】
{json.dumps(knowledge, ensure_ascii=False)}

【语义风险策略】
{json.dumps(build_semantic_policy_for_prompt(), ensure_ascii=False)}

请生成最终回答。
"""
    card = build_structured_safety_card(analysis, decision)
    # Fast-path only active risk turns. Closed cases still need the normal
    # generation path so closure/review semantics and their tests are kept.
    if (
        (state.get("route_decision") or {}).get("deterministic_risk_route")
        and decision.get("is_risk_scene")
        and not is_closed
    ):
        answer = _deterministic_realtime_answer(state, analysis, decision)
        if state.get("is_stream") and state.get("session_id"):
            push_to_session(state["session_id"], SSEEvent.DELTA, {"delta": answer})
        return answer
    try:
        llm = get_llm_client(json_mode=False)
        response = call_with_timeout(
            lambda: llm.invoke([HumanMessage(content=prompt.strip())]),
            env_timeout("ANTI_FRAUD_LLM_GENERATION_TIMEOUT_SECONDS", 2.5),
        )
        answer = get_message_content(response)
        if not _answer_satisfies_safety_gate(answer, decision, card):
            logger.warning("LLM 风险回答未通过类型化安全门，改用确定性安全卡片")
            answer = _deterministic_realtime_answer(state, analysis, decision)
        if state.get("is_stream") and state.get("session_id"):
            push_to_session(state["session_id"], SSEEvent.DELTA, {"delta": answer})
        return answer
    except Exception as exc:
        logger.warning("风险回答生成超时或失败，使用确定性安全卡片：%s", exc)
        return _deterministic_realtime_answer(state, analysis, decision)


def build_result_summary(
    state: Dict[str, Any],
    analysis: Dict[str, Any],
    decision: Dict[str, Any],
    knowledge: Dict[str, Any],
    answer: str,
) -> Dict[str, Any]:
    slots = _slots_from_analysis(analysis)
    docs = _retrieved_docs(knowledge)
    scene = analysis.get("scene") or {}
    lifecycle = analysis.get("case_lifecycle") if isinstance(analysis.get("case_lifecycle"), dict) else {}
    resolution = analysis.get("resolution") if isinstance(analysis.get("resolution"), dict) else {}
    case_status = str(
        decision.get("case_status")
        or lifecycle.get("case_status")
        or ("active" if decision.get("is_risk_scene") else "non_risk_task")
    )
    post_resolution_reset = case_status in CLOSED_CASE_STATUSES and bool(resolution.get("post_resolution_education_delivered"))
    closure_summary_delivered = bool(post_resolution_reset and _should_emit_closure_summary(analysis))
    assistant_mode = "knowledge_education" if post_resolution_reset else "risk_dissuasion" if decision.get("is_risk_scene") else "knowledge_education"
    workflow_mode = "knowledge_answer" if post_resolution_reset else "risk_case_flow" if decision.get("is_risk_scene") else "knowledge_answer"
    route_name = "post_resolution_education" if post_resolution_reset else "semantic_realtime_dissuasion" if decision.get("is_risk_scene") else "knowledge_answer"
    safety_card = build_structured_safety_card(analysis, decision)
    candidate_types = decision.get("candidate_types") or (analysis.get("fraud") or {}).get("candidate_types", [])
    summary = {
        "basic_input": {
            "session_id": state.get("session_id", ""),
            "original_query": state.get("original_query", ""),
            "is_stream": bool(state.get("is_stream", False)),
        },
        "scene_understanding": {
            "scene": scene,
            "case_context_type": decision.get("case_context_type", 3),
            "case_context_label": decision.get("case_context_label", ""),
            "case_state": state.get("case_state", {}),
        },
        "semantic_risk_analysis": analysis,
        "risk_decision": decision,
        "case_lifecycle": lifecycle,
        "resolution": resolution,
        "knowledge_used": knowledge,
        "slots": slots,
        "scam_understanding": {
            "primary_scam_type": decision.get("fraud_type", "未知"),
            "fraud_type_id": decision.get("fraud_type_id", ""),
            "primary_type": decision.get("primary_type", decision.get("fraud_type", "未知")),
            "candidate_types": candidate_types,
            "candidate_type_ids": decision.get("candidate_type_ids", []),
            "type_candidates": decision.get("type_candidates", []),
            "type_confidence": decision.get("type_confidence", 0.0),
            "possible_scam_types": candidate_types,
            "fraud_stage": decision.get("fraud_stage", ""),
            "matched_features": decision.get("risk_features", []),
            "evidence_points": (analysis.get("facts") or {}).get("evidence", []),
        },
        "risk": {
            "risk_class": decision.get("risk_class", ""),
            "reason": decision.get("reason", ""),
            "matched_rules": decision.get("matched_rules", []),
            "case_status": case_status,
            "risk_resolved": bool(decision.get("risk_resolved", False)),
            "user_exposure": {
                "has_loss_or_exposure": decision.get("has_loss_or_exposure", False),
                "active_danger": decision.get("active_danger", False),
            },
        },
        "intervention": {
            "route": "semantic_realtime_dissuasion" if decision.get("is_risk_scene") else "knowledge_answer",
            "next_question": analysis.get("ask_goal", ""),
            "message_plan": "LLM 实时生成，规则和知识库只作为约束",
            "actions": decision.get("current_dangerous_actions") or decision.get("requested_actions") or [],
            "safety_card": safety_card,
        },
        "safety_card": safety_card,
        "retrieved_docs": docs,
        "matched_rules": decision.get("matched_rules", []),
        "missing_info": analysis.get("missing_facts", []),
        "answer": answer,
        "assistant_mode": assistant_mode,
        "module": "unified_anti_fraud_assistant",
        "route_decision": state.get("route_decision", {}),
        "turn_rewrite": (state.get("route_decision") or {}).get("turn_rewrite", {}),
        "pending_answer_decision": (state.get("route_decision") or {}).get("pending_answer_decision", {}),
        "workflow_action": "semantic_risk_agent",
        "workflow_mode": workflow_mode,
        "warnings": state.get("warnings", []),
    }
    summary.update(
        {
            "case_context_type": decision.get("case_context_type", 3),
            "case_context_label": decision.get("case_context_label", ""),
            "case_status": case_status,
            "risk_resolved": bool(decision.get("risk_resolved", False)),
            "ready_for_education": bool(decision.get("ready_for_education", False)),
            "post_resolution_answer_mode": decision.get("post_resolution_answer_mode", ""),
            "post_resolution_education_delivered": bool(decision.get("post_resolution_education_delivered", False)),
            "closure_summary_delivered": closure_summary_delivered,
            "closure_summary_type": "personalized_scam_summary" if closure_summary_delivered else "",
            "route_name": route_name,
            "fraud_type": decision.get("fraud_type", "未知"),
            "fraud_type_id": decision.get("fraud_type_id", ""),
            "primary_type": decision.get("primary_type", decision.get("fraud_type", "未知")),
            "candidate_types": candidate_types,
            "candidate_type_ids": decision.get("candidate_type_ids", []),
            "type_candidates": decision.get("type_candidates", []),
            "type_confidence": decision.get("type_confidence", 0.0),
            "fraud_stage": decision.get("fraud_stage", ""),
            "payment_status": "paid" if slots.get("has_paid") == TRUE else "not_paid" if slots.get("has_paid") == FALSE else UNKNOWN,
            "loss_status": "loss_confirmed" if decision.get("has_loss_or_exposure") else "no_confirmed_loss" if decision.get("is_risk_scene") else "none",
            "intervention_goal": analysis.get("ask_goal", ""),
            "answer_strategy": "semantic_llm_realtime",
            "next_question": analysis.get("ask_goal", ""),
            "risk_score": decision.get("risk_score", 0),
            "risk_level": decision.get("display_risk_level", ""),
            "possible_fraud_types": candidate_types,
            "possible_fraud_stages": [decision.get("fraud_stage", "")] if decision.get("fraud_stage") else [],
            "risk_features": decision.get("risk_features", []),
            "normalized_risk_features": decision.get("risk_features", []),
            "rule_engine": {
                "engine_version": "semantic-rule-constraint-v2",
                "risk_level": decision.get("display_risk_level", ""),
                "risk_score": decision.get("risk_score", 0),
                "matched_rules": decision.get("matched_rules", []),
                "risk_features": decision.get("risk_features", []),
                "fraud_type_id": decision.get("fraud_type_id", ""),
                "primary_type": decision.get("primary_type", decision.get("fraud_type", "未知")),
                "candidate_types": candidate_types,
                "candidate_type_ids": decision.get("candidate_type_ids", []),
                "type_confidence": decision.get("type_confidence", 0.0),
                "case_status": case_status,
                "risk_resolved": bool(decision.get("risk_resolved", False)),
            },
            "semantic_agent": {
                "analysis": analysis,
                "decision": decision,
            },
        }
    )
    anti_fraud_engine = build_anti_fraud_engine_result(
        input_text=str((summary.get("basic_input") or {}).get("original_query") or ""),
        route_decision=state.get("route_decision", {}),
        risk_result=summary,
        memory_context=state.get("memory_context", {}),
    )
    summary["anti_fraud_engine"] = anti_fraud_engine
    summary["risk_judgement_card"] = anti_fraud_engine.get("risk_judgement_card", {})
    return summary


def persist_semantic_turn(
    state: Dict[str, Any],
    analysis: Dict[str, Any],
    decision: Dict[str, Any],
    knowledge: Dict[str, Any],
    answer: str,
    summary: Dict[str, Any],
) -> None:
    session_id = state.get("session_id", "")
    case_state = dict(state.get("case_state") or {})
    slots = summary.get("slots", {})
    lifecycle = analysis.get("case_lifecycle") if isinstance(analysis.get("case_lifecycle"), dict) else {}
    resolution = analysis.get("resolution") if isinstance(analysis.get("resolution"), dict) else {}
    case_status = str(
        decision.get("case_status")
        or lifecycle.get("case_status")
        or ("active" if decision.get("is_risk_scene") else "non_risk_task")
    )
    case_is_closed = case_status in CLOSED_CASE_STATUSES or bool(resolution.get("risk_resolved"))
    closure_summary_delivered = bool(summary.get("closure_summary_delivered", False))
    route_context = dict(case_state.get("route_context") or state.get("route_context") or {})
    route_context["active_workflow"] = "idle" if case_is_closed else "risk_case_flow" if decision.get("is_risk_scene") else "idle"
    route_context["workflow_status"] = case_status
    route_context["last_route_decision"] = state.get("route_decision", {})
    pending_question = {}
    if decision.get("is_risk_scene") and not case_is_closed and analysis.get("ask_goal"):
        pending_question = {
            "type": "semantic_followup",
            "allow_free_text": True,
            "ask_goal": analysis.get("ask_goal", ""),
            "missing_facts": analysis.get("missing_facts", []),
            "source": "semantic_risk_agent",
        }
    route_context["pending_question"] = pending_question
    case_state.update(
        {
            "case_id": state.get("case_id", case_state.get("case_id", "")),
            "session_id": session_id,
            "case_status": case_status,
            "case_context_type": decision.get("case_context_type", 3),
            "case_context_label": decision.get("case_context_label", ""),
            "fraud_type": decision.get("fraud_type", "未知"),
            "fraud_type_id": decision.get("fraud_type_id", ""),
            "primary_type": decision.get("primary_type", decision.get("fraud_type", "未知")),
            "candidate_types": decision.get("candidate_types", []),
            "candidate_type_ids": decision.get("candidate_type_ids", []),
            "type_confidence": decision.get("type_confidence", 0.0),
            "fraud_stage": decision.get("fraud_stage", ""),
            "risk_features": decision.get("risk_features", []),
            "risk_score": decision.get("risk_score", 0),
            "risk_level": decision.get("display_risk_level", ""),
            "slots": slots,
            "scam_understanding": summary.get("scam_understanding", {}),
            "risk": summary.get("risk", {}),
            "intervention": summary.get("intervention", {}),
            "resolution": resolution,
            "resolution_memory": {
                "risk_resolved": bool(resolution.get("risk_resolved", False)),
                "resolution_level": resolution.get("resolution_level", ""),
                "completed_actions": resolution.get("completed_actions", []),
                "missing_actions": resolution.get("missing_resolution_actions", []),
                "missing_action_ids": resolution.get("missing_action_ids", []),
                "unsafe_signals": resolution.get("unsafe_signals", []),
                "ready_for_education": bool(resolution.get("ready_for_education", False)),
                "post_resolution_education_delivered": bool(resolution.get("post_resolution_education_delivered", False)),
                "post_resolution_answer_mode": resolution.get("post_resolution_answer_mode", ""),
                "closure_summary_delivered": closure_summary_delivered,
                "judge_source": resolution.get("judge_source", ""),
                "reason": resolution.get("reason", ""),
                "closure_standard": resolution.get("closure_standard", {}),
                "last_resolution_check_at": datetime.now().isoformat(timespec="seconds"),
            },
            "risk_resolved": bool(resolution.get("risk_resolved", False)),
            "ready_for_education": bool(resolution.get("ready_for_education", False)),
            "post_resolution_education_delivered": bool(resolution.get("post_resolution_education_delivered", False)),
            "post_resolution_answer_mode": resolution.get("post_resolution_answer_mode", ""),
            "closure_summary_delivered": closure_summary_delivered,
            "closure_summary_type": "personalized_scam_summary" if closure_summary_delivered else "",
            "semantic_risk_analysis": analysis,
            "semantic_risk_decision": decision,
            "retrieved_docs": summary.get("retrieved_docs", []),
            "pending_question": pending_question,
            "route_context": route_context,
            "last_answer": answer,
            "last_updated_at": datetime.now().isoformat(timespec="seconds"),
        }
    )
    if closure_summary_delivered:
        case_state = _cleared_case_state_after_closure_summary(
            existing_case=case_state,
            session_id=session_id,
            case_id=state.get("case_id", case_state.get("case_id", "")),
            route_context=route_context,
        )
        pending_question = {}
        route_context = case_state.get("route_context", {})
    summary["case_state"] = case_state
    summary["memory_context"] = {
        **(state.get("memory_context") or {}),
        "case_state": case_state,
        "pending_question": pending_question,
        "route_context": route_context,
        "memory_summary": case_state.get("memory_summary", ""),
        "post_closure_memory_reset": bool(case_state.get("case_memory_cleared_after_closure")),
    }
    state.update(
        {
            "case_state": case_state,
            "slots": {} if closure_summary_delivered else slots,
            "scam_understanding": {} if closure_summary_delivered else summary.get("scam_understanding", {}),
            "risk": {} if closure_summary_delivered else summary.get("risk", {}),
            "intervention": {} if closure_summary_delivered else summary.get("intervention", {}),
            "semantic_scene": {} if closure_summary_delivered else analysis.get("scene", {}),
            "semantic_risk_analysis": {} if closure_summary_delivered else analysis,
            "semantic_risk_decision": {} if closure_summary_delivered else decision,
            "retrieved_docs": [] if closure_summary_delivered else summary.get("retrieved_docs", []),
            "matched_rules": [] if closure_summary_delivered else decision.get("matched_rules", []),
            "risk_score": 0 if closure_summary_delivered else decision.get("risk_score", 0),
            "risk_level": "" if closure_summary_delivered else decision.get("display_risk_level", ""),
            "fraud_type": "" if closure_summary_delivered else decision.get("fraud_type", "未知"),
            "fraud_stage": "" if closure_summary_delivered else decision.get("fraud_stage", ""),
            "risk_features": [] if closure_summary_delivered else decision.get("risk_features", []),
            "case_context_type": 3 if closure_summary_delivered else decision.get("case_context_type", 3),
            "case_context_label": "" if closure_summary_delivered else decision.get("case_context_label", ""),
            "case_status": case_state["case_status"],
            "risk_resolved": bool(case_state.get("risk_resolved", False)),
            "ready_for_education": bool(case_state.get("ready_for_education", False)),
            "next_question": "" if closure_summary_delivered else analysis.get("ask_goal", ""),
            "answer": answer,
            "workflow_action": "semantic_risk_agent",
            "route_name": summary.get("route_name") or ("semantic_realtime_dissuasion" if decision.get("is_risk_scene") else "knowledge_answer"),
            "workflow_mode": summary.get("workflow_mode", ""),
            "assistant_mode": summary.get("assistant_mode", ""),
            "result_summary": summary,
            "preserve_pending_question": bool(pending_question),
        }
    )
    decorated = attach_video_cards(
        {
            "session_id": session_id,
            "answer": answer,
            "summary": summary,
            "assistant_mode": summary.get("assistant_mode", ""),
            "workflow_mode": summary.get("workflow_mode", ""),
            "fraud_type": summary.get("fraud_type", ""),
            "risk_judgement_card": summary.get("risk_judgement_card", {}),
        },
        session_id,
    )
    video_cards = decorated.get("video_cards", [])
    if video_cards:
        summary["video_cards"] = video_cards
    if session_id:
        save_case_state(session_id, case_state)
        save_risk_chat_message(
            session_id=session_id,
            role="user",
            text=state.get("original_query", ""),
            fraud_types=[decision.get("fraud_type", "")] if decision.get("fraud_type") else [],
            risk_summary=summary,
        )
        save_risk_chat_message(
            session_id=session_id,
            role="assistant",
            text=answer,
            fraud_types=[decision.get("fraud_type", "")] if decision.get("fraud_type") else [],
            risk_summary=summary,
            video_cards=video_cards,
        )
        set_task_result(session_id, "answer", answer)
        set_task_result(session_id, "risk_score", str(decision.get("risk_score", "")))
        set_task_result(session_id, "risk_level", str(decision.get("display_risk_level", "")))
        set_task_result(session_id, "result_summary", json.dumps(summary, ensure_ascii=False))
        set_task_result(session_id, "matched_rules", json.dumps(decision.get("matched_rules", []), ensure_ascii=False))
        set_task_result(session_id, "retrieved_docs", json.dumps(summary.get("retrieved_docs", []), ensure_ascii=False))
        if state.get("is_stream"):
            push_to_session(
                session_id,
                SSEEvent.FINAL,
                {"answer": answer, "summary": summary, "video_cards": video_cards},
            )


def run_semantic_risk_agent(state: Dict[str, Any]) -> Dict[str, Any]:
    analysis = extract_semantic_risk_facts(state)
    analysis = _sanitize_followup_plan(_merge_analysis_with_memory(analysis, state))
    decision = decide_risk_from_analysis(analysis)
    analysis = apply_case_lifecycle(state, analysis, decision)
    analysis = _sanitize_followup_plan(analysis)
    decision = _decision_with_lifecycle(decision, analysis)
    knowledge = _knowledge_for_type(decision.get("fraud_type", ""), decision.get("risk_features", []))
    answer = generate_realtime_answer(state, analysis, decision, knowledge)
    summary = build_result_summary(state, analysis, decision, knowledge, answer)
    persist_semantic_turn(state, analysis, decision, knowledge, answer, summary)
    return state


__all__ = [
    "SEMANTIC_POLICY_COLLECTION",
    "build_scam_catalog_for_prompt",
    "build_semantic_policy_for_prompt",
    "decide_risk_from_analysis",
    "extract_semantic_risk_facts",
    "run_semantic_risk_agent",
]
