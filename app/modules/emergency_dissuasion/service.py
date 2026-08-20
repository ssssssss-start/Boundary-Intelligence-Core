import json
import uuid
from typing import Any, Dict, List

from fastapi import BackgroundTasks

from app.clients.mongo_history_utils import get_recent_messages
from app.modules.emergency_dissuasion.graph import emergency_dissuasion_app
from app.modules.knowledge_assistant.emotion import with_emotion_context
from app.query_process.agent.memory import get_memory_manager
from app.query_process.agent.nodes.common import build_history_text
from app.query_process.services.risk_video_card_service import attach_video_cards
from app.utils.sse_utils import SSEEvent, create_sse_queue, push_to_session
from app.utils.task_utils import (
    TASK_STATUS_COMPLETED,
    TASK_STATUS_FAILED,
    TASK_STATUS_PROCESSING,
    get_done_task_list,
    get_task_result,
    update_task_status,
)


def _get_json_task_result(session_id: str, key: str, default):
    raw = get_task_result(session_id, key, "")
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def _empty_pending_answer_decision() -> Dict[str, Any]:
    return {
        "is_pending_answer": False,
        "slot_updates": {},
        "completed_actions": [],
        "denied_actions": [],
        "confidence": 0.0,
        "reason": "",
    }


def _normalize_history_for_graph(history: List[Dict[str, Any]] | None) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    for item in history or []:
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip()
        if role == "bot":
            role = "assistant"
        text = str(item.get("text") or item.get("content") or "").strip()
        if not role or not text:
            continue
        normalized.append({**item, "role": role, "text": text, "content": text})
    return normalized


def _case_memory_cleared_after_closure(memory_context: Dict[str, Any]) -> bool:
    case_state = memory_context.get("case_state") if isinstance(memory_context.get("case_state"), dict) else {}
    resolution = case_state.get("resolution") if isinstance(case_state.get("resolution"), dict) else {}
    if not resolution and isinstance(case_state.get("resolution_memory"), dict):
        resolution = case_state.get("resolution_memory") or {}
    return bool(
        case_state.get("case_memory_cleared_after_closure")
        or case_state.get("closure_summary_delivered")
        or resolution.get("closure_summary_delivered")
    )


def build_emergency_route_decision(
    user_query: str,
    memory_context: Dict[str, Any],
    intent_hint: str = "emergency_help",
) -> Dict[str, Any]:
    """Build a minimal emergency route envelope.

    The semantic risk agent performs LLM scene/fact extraction inside the graph.
    This envelope only ensures the request reaches that graph without invoking
    the old regex-heavy safety router.
    """
    return {
        "primary_intent": "emergency_help",
        "secondary_intents": [],
        "workflow_mode": "risk_case_flow",
        "confidence": 1.0,
        "urgency": "normal",
        "safety_override": False,
        "continue_current_workflow": True,
        "reason": "紧急风险劝阻模块固定进入语义风险研判链路",
        "need_clarification": False,
        "clarification_question": "",
        "clarification_options": [],
        "entities": {},
        "risk_signals": {},
        "scores": {},
        "knowledge_matches": [],
        "routing_decision": {
            "target": "risk_case_flow",
            "force_high_risk": False,
            "prefill_slots": {},
        },
        "turn_rewrite": {
            "judge_source": "semantic_emergency_route",
            "original_text": user_query,
            "rewritten_text": user_query,
            "confidence": 1.0,
            "reason": "应急模块直接交给语义风险代理研判",
        },
        "pending_answer_decision": _empty_pending_answer_decision(),
        "semantic_scene": {},
        "next_action": {},
        "risk_prefill": {
            "fraud_candidates": [],
            "confirmed_exposure": [],
            "risky_requested_actions": [],
            "slot_updates": {},
        },
    }


def run_emergency_graph(
    session_id: str,
    user_query: str,
    is_stream: bool = True,
    intent_hint: str = "emergency_help",
    route_decision_override: Dict[str, Any] | None = None,
    history_override: List[Dict[str, Any]] | None = None,
):
    memory_context = get_memory_manager().load_context(session_id, user_query, intent_hint=intent_hint or "")
    route_decision = route_decision_override or build_emergency_route_decision(
        user_query,
        memory_context,
        intent_hint=intent_hint or "",
    )
    turn_rewrite = route_decision.get("turn_rewrite") or {}
    history = _normalize_history_for_graph(
        history_override if history_override is not None else get_recent_messages(session_id, limit=10)
    )
    if _case_memory_cleared_after_closure(memory_context):
        history = []
    history_text = build_history_text(history)
    default_state = {
        "original_query": user_query,
        "rewritten_query": turn_rewrite.get("rewritten_text", ""),
        "session_id": session_id,
        "case_id": memory_context.get("case_id", ""),
        "intent_hint": intent_hint or "",
        "memory_context": memory_context,
        "route_context": memory_context.get("route_context", {}),
        "pending_question": memory_context.get("pending_question", {}),
        "turn_memory": memory_context.get("turn_memory", {}),
        "memory_summary": memory_context.get("memory_summary", ""),
        "route_decision": route_decision,
        "history": history,
        "history_text": history_text,
        "is_stream": is_stream,
        "emergency_mode": True,
    }
    try:
        emergency_dissuasion_app.invoke(default_state)
        update_task_status(session_id, TASK_STATUS_COMPLETED, is_stream)
    except Exception as e:
        update_task_status(session_id, TASK_STATUS_FAILED, is_stream)
        if is_stream:
            push_to_session(session_id, SSEEvent.ERROR, {"error": str(e)})


def _fallback_emergency_answer(user_query: str, summary: Dict[str, Any]) -> str:
    safety_card = summary.get("safety_card") if isinstance(summary.get("safety_card"), dict) else {}
    if safety_card and safety_card.get("required_categories"):
        card_lines = []
        for category in ("stop_current_action", "official_verification", "preserve_evidence", "post_loss_response"):
            for item in safety_card.get(category) or []:
                if item and item not in card_lines:
                    card_lines.append(str(item))
        if card_lines:
            next_question = summary.get("next_question") or "你现在是否已经转账、提供验证码，或者还在屏幕共享/远程控制中？"
            return "\n".join(
                [
                    f"判断为：{summary.get('primary_type') or summary.get('fraud_type') or '疑似诈骗'}。先不要继续按对方要求操作。",
                    *[f"{index}. {item}" for index, item in enumerate(card_lines, start=1)],
                    f"\n下一步请确认：{next_question}",
                ]
            )
    text = " ".join(
        [
            user_query,
            str(summary.get("user_situation") or ""),
            str(summary.get("fraud_stage") or ""),
            " ".join(str(item) for item in summary.get("risk_features") or []),
        ]
    )
    steps = ["先立刻停止和对方继续操作，保留聊天记录、转账记录、链接、账号、电话等证据。"]
    if any(keyword in text for keyword in ("屏幕共享", "共享屏幕", "远程", "控制")):
        steps.append("马上关闭屏幕共享或远程控制，退出对方要求打开的 App 或会议，不要再按对方指令点击。")
    if any(keyword in text for keyword in ("验证码", "动态码", "密码", "银行卡", "身份证")):
        steps.append("不要再提供验证码、密码、银行卡、身份证等信息；如果已经提供，立即联系银行冻结或修改相关账户密码。")
    if any(keyword in text for keyword in ("转账", "付款", "汇款", "垫付", "保证金", "解冻费", "手续费")):
        steps.append("如果已经付款或正在付款，马上停止转账，联系银行或支付平台申请止付，并拨打 110 或 96110 求助。")
    if any(keyword in text for keyword in ("下载", "安装", "App", "APP", "链接", "网址", "二维码")):
        steps.append("不要打开陌生链接、不要下载对方发来的 App；如果已经安装，先断开网络并尽快卸载、查杀和修改重要账户密码。")
    if len(steps) == 1:
        steps.append("不要转账、不要发验证码、不要点陌生链接、不要下载陌生 App，先通过官方渠道独立核实。")
    next_question = summary.get("next_question") or "你现在是否已经转账、提供验证码，或者还在屏幕共享/远程控制中？"
    return "\n".join(f"{index + 1}. {step}" for index, step in enumerate(steps)) + f"\n\n下一步请确认：{next_question}"


def build_emergency_sync_result(session_id: str, user_query: str = "") -> Dict[str, Any]:
    answer = get_task_result(session_id, "answer", "")
    summary = _get_json_task_result(session_id, "result_summary", {})
    if not str(answer or "").strip():
        answer = _fallback_emergency_answer(user_query, summary)
    response = {
        "message": "处理完成！",
        "session_id": session_id,
        "answer": answer,
        "case_status": summary.get("case_status", ""),
        "fraud_type": summary.get("fraud_type", ""),
        "fraud_type_id": summary.get("fraud_type_id", ""),
        "primary_type": summary.get("primary_type", summary.get("fraud_type", "")),
        "candidate_types": summary.get("candidate_types", summary.get("possible_fraud_types", [])),
        "candidate_type_ids": summary.get("candidate_type_ids", []),
        "type_candidates": summary.get("type_candidates", []),
        "type_confidence": summary.get("type_confidence", 0.0),
        "fraud_stage": summary.get("fraud_stage", ""),
        "user_situation": summary.get("user_situation", ""),
        "payment_status": summary.get("payment_status", "unknown"),
        "loss_status": summary.get("loss_status", "unknown"),
        "intervention_goal": summary.get("intervention_goal", ""),
        "answer_strategy": summary.get("answer_strategy", ""),
        "next_question": summary.get("next_question", ""),
        "post_resolution_answer_mode": summary.get("post_resolution_answer_mode", ""),
        "post_resolution_education_delivered": bool(summary.get("post_resolution_education_delivered", False)),
        "case_state": summary.get("case_state", {}),
        "risk_score": summary.get("risk_score", 0),
        "risk_level": summary.get("risk_level", ""),
        "possible_fraud_types": summary.get("possible_fraud_types", []),
        "possible_fraud_stages": summary.get("possible_fraud_stages", []),
        "risk_features": summary.get("risk_features", []),
        "matched_rules": summary.get("matched_rules", []),
        "risk_judgement_card": summary.get("risk_judgement_card", (summary.get("anti_fraud_engine", {}) or {}).get("risk_judgement_card", {})),
        "safety_card": summary.get("safety_card", {}),
        "video_cards": summary.get("video_cards", []),
        "retrieved_docs": summary.get("retrieved_docs", []),
        "missing_info": summary.get("missing_info", []),
        "warnings": summary.get("warnings", []),
        "done_list": get_done_task_list(session_id),
        "module": "emergency_dissuasion",
        "assistant_mode": "risk_dissuasion",
    }
    response.update(
        {
            "summary": summary,
            "slots": summary.get("slots", summary.get("case_state", {}).get("slots", {})),
            "scam_understanding": summary.get("scam_understanding", {}),
            "risk": summary.get("risk", {}),
            "risk_class": summary.get("risk_class", summary.get("risk", {}).get("risk_class", "")),
            "intervention": summary.get("intervention", {}),
            "resolution": summary.get("resolution", {}),
            "workflow_action": summary.get("workflow_action", ""),
            "slot_gate": summary.get("slot_gate", {}),
            "ready_for_education": summary.get("ready_for_education", False),
            "pending_resolution_actions": summary.get("pending_resolution_actions", []),
            "route_decision": summary.get("route_decision", summary.get("intent_recognition", {})),
            "turn_rewrite": summary.get("turn_rewrite", (summary.get("route_decision", {}) or {}).get("turn_rewrite", {})),
            "pending_answer_decision": summary.get(
                "pending_answer_decision",
                (summary.get("route_decision", {}) or {}).get("pending_answer_decision", {}),
            ),
            "workflow_mode": summary.get("workflow_mode", summary.get("route_name", "")),
            "memory_context": summary.get("memory_context", {}),
            "route_memory": summary.get("route_memory", {}),
            "slot_memory": summary.get("slot_memory", {}),
            "exposure_memory": summary.get("exposure_memory", {}),
            "current_unsafe_memory": summary.get("current_unsafe_memory", {}),
            "case_event_hint": summary.get("case_event_hint", {}),
        }
    )
    return attach_video_cards(response, session_id)


async def handle_emergency_chat(background_tasks: BackgroundTasks, request) -> Dict[str, Any]:
    provided_emotion = request.emotion if isinstance(request.emotion, dict) else request.voice_emotion
    user_query, emotion = with_emotion_context(request.query, request.input_mode, provided_emotion)
    session_id = request.session_id if request.session_id else str(uuid.uuid4())
    is_stream = request.is_stream
    intent_hint = request.intent_hint or "emergency_help"
    if is_stream:
        create_sse_queue(session_id)
    update_task_status(session_id, TASK_STATUS_PROCESSING, is_stream)

    if is_stream:
        background_tasks.add_task(run_emergency_graph, session_id, user_query, is_stream, intent_hint)
        return {"message": "结果正在处理中...", "session_id": session_id, "emotion": emotion}

    run_emergency_graph(session_id, user_query, is_stream, intent_hint)
    result = build_emergency_sync_result(session_id, user_query)
    result["emotion"] = emotion
    return result
