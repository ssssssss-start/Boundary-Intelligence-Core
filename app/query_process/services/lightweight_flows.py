"""Lightweight non-risk workflows behind RouteDecision.

These service flows are reserved for specialty tasks such as URL checks and
report drafts. Risk conversations are handled by the semantic risk graph.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from app.clients.mongo_business_utils import get_business_mongo_tool
from app.clients.mongo_history_utils import save_risk_chat_message
from app.game_process.services.game_service import DEFAULT_USER_ID, get_next_level
from app.query_process.agent.memory import get_memory_manager
from app.query_process.services.knowledge_service import search_knowledge
from app.query_process.services.anti_fraud_engine import build_anti_fraud_engine_result
from app.query_process.services.risk_video_card_service import attach_video_cards
from app.query_process.services.scam_rule_engine import infer_fraud_types
from app.utils.sse_utils import SSEEvent, push_to_session
from app.utils.task_utils import add_done_task, add_running_task, set_task_result


INTENT_ANTI_FRAUD_QA = "anti_fraud_qa"
INTENT_EDUCATION_GAME = "education_game"
INTENT_RISK_FACT_CLARIFICATION = "risk_fact_clarification"
INTENT_SMALLTALK = "smalltalk"

DISABLED_CHAT_TOOL_INTENTS = {"url_check", "report_submit"}
DISABLED_CHAT_TOOL_WORKFLOWS = {"url_check", "report_flow"}


def _doc_summaries(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "id": item.get("knowledge_id", item.get("id", "")),
            "knowledge_type": item.get("knowledge_type", ""),
            "fraud_type": item.get("fraud_type", ""),
            "title": item.get("title", ""),
            "risk_level": item.get("risk_level", ""),
            "score": item.get("score", 0),
            "retrieval_source": item.get("source", ""),
            "embedding_backend": "",
            "summary": item.get("summary", ""),
        }
        for item in items
    ]


def _scam_type_intro(user_query: str) -> str:
    for fraud_type in infer_fraud_types(user_query):
        if not fraud_type or fraud_type == "未知":
            continue
        try:
            tool = get_business_mongo_tool()
            doc = tool.db["scam_types"].find_one(
                {
                    "$or": [
                        {"operational_fraud_type": fraud_type},
                        {"name": fraud_type},
                        {"aliases": fraud_type},
                    ]
                },
                {"_id": 0},
            )
        except Exception:
            doc = None
        if doc:
            aliases = "、".join(doc.get("aliases") or [])
            desc = doc.get("description") or doc.get("definition") or ""
            target = "、".join(doc.get("target_users") or [])
            channel = "、".join(doc.get("common_channels") or [])
            parts = [f"{fraud_type}通常是骗子利用任务、返利、身份冒充或平台流程制造信任，再诱导用户转账、泄露信息或下载陌生工具的诈骗。"]
            if desc:
                parts[0] = desc
            if aliases:
                parts.append(f"常见说法包括：{aliases}。")
            if target:
                parts.append(f"常见受影响人群：{target}。")
            if channel:
                parts.append(f"常见接触渠道：{channel}。")
            return "\n".join(parts)
        return f"{fraud_type}是常见电信网络诈骗类型，核心风险是骗子通过话术和流程诱导用户转账、泄露账号验证码或继续投入资金。"
    return ""


def _knowledge_answer(user_query: str) -> tuple[str, Dict[str, Any]]:
    result = {"source": "none", "items": []}
    items: List[Dict[str, Any]] = []
    try:
        result = search_knowledge(user_query, limit=5)
        items = result.get("items") or []
    except Exception:
        items = []

    if not items:
        for fraud_type in infer_fraud_types(user_query):
            if fraud_type and fraud_type != "未知":
                try:
                    result = search_knowledge(fraud_type, limit=5)
                    items = result.get("items") or []
                except Exception:
                    items = []
                if items:
                    break

    if items:
        lines = ["这是反诈知识问答，不是实时风险处置。根据知识库，可以这样理解："]
        intro = _scam_type_intro(user_query)
        if intro:
            lines.append(intro)
        for idx, item in enumerate(items[:3], start=1):
            title = item.get("title") or item.get("fraud_type") or f"知识点{idx}"
            summary = item.get("summary") or "暂无摘要"
            lines.append(f"{idx}. {title}：{summary}")
        lines.append("如果这是你正在经历的情况，请直接描述对方让你做什么、是否已经转账或给过验证码，我会切换到风险研判。")
    else:
        lines = [
            "这是反诈知识问答。当前没有检索到足够匹配的知识条目。",
            "你可以换一种说法，例如“什么是刷单返利诈骗”“冒充公检法怎么识别”“校园贷有哪些套路”。",
            "如果你正在被对方诱导操作，请直接说对方让你做什么，我会进入风险研判。",
        ]
    answer = "\n".join(lines)
    return answer, {
        "retrieved_docs": _doc_summaries(items),
        "knowledge_source": result.get("source", "none"),
    }


def _game_answer(session_id: str) -> tuple[str, Dict[str, Any]]:
    try:
        result = get_next_level(user_id=session_id or DEFAULT_USER_ID)
        level = result.get("level") or {}
    except Exception:
        result = {"source": "none", "level": {}}
        level = {}
    if not level:
        return "暂时没有可用的反诈测试题。你可以先问我某类诈骗的识别方法。", result
    options = level.get("options") or []
    option_text = "\n".join(f"{idx + 1}. {item}" for idx, item in enumerate(options))
    answer = (
        f"反诈测试题：{level.get('title', '情景判断')}\n"
        f"{level.get('scenario', level.get('question', '请判断这个场景是否有风险。'))}\n"
        f"{option_text}\n"
        "请直接回复选项编号或选项内容。"
    )
    return answer, result


def _fallback_answer() -> tuple[str, Dict[str, Any]]:
    answer = (
        "您好呀！我是您的反诈骗小卫士，专门帮您识破各种骗局。\n"
        "陌生链接别乱点，可疑电话多核实，转账汇款先问我！\n"
        "有可疑的事情，尽管发给我，我帮您把把关，一秒识破它！"
    )
    return answer, {}


def _risk_fact_clarification_answer(route_decision: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    route_question = ((route_decision.get("next_action") or {}).get("question") or "").strip()
    semantic_frame = route_decision.get("semantic_frame") or {}
    pending_decision = route_decision.get("pending_answer_decision") or {}
    slot_updates = pending_decision.get("slot_updates") or {}
    if pending_decision.get("is_pending_answer") and slot_updates and not any(slot_updates.values()):
        answer = (
            "好的，目前没有确认已经转账、泄露验证码、共享屏幕或填写敏感信息，暂时不需要直接进入紧急止损。\n\n"
            "接下来我需要判断这件事本身是否可疑。请用一句话告诉我：对方是谁，具体让你做什么？"
            "例如：客服让我下载会议软件、对方让我交保证金才能提现、有人让我点链接填写信息。"
        )
        return answer, {
            "risk_score": 0,
            "risk_level": "未确认损失，等待风险场景描述",
            "clarification_target": "requested_action_or_scam_context",
            "pending_answer_decision": pending_decision,
        }

    answer = route_question or (
        "我先按正在遭遇诈骗处理。请补充两点：1. 对方是谁、具体让你做什么；"
        "2. 你是否已经转账、交付游戏装备/账号、给验证码、共享屏幕、下载App、点链接填信息，金额大概是多少。"
        "如果正在转账、共享屏幕或发送验证码，请先立刻停止。"
    )
    return answer, {
        "risk_score": 0,
        "risk_level": "事实待确认",
        "clarification_target": "exposure_or_current_unsafe_action",
        "turn_rewrite": route_decision.get("turn_rewrite", {}),
        "semantic_frame": semantic_frame,
    }


def _answered_no_exposure(route_decision: Dict[str, Any]) -> bool:
    pending_decision = route_decision.get("pending_answer_decision") or {}
    slot_updates = pending_decision.get("slot_updates") or {}
    core_exposure_slots = {
        "has_paid",
        "has_shared_code",
        "has_screen_share",
        "has_downloaded_app",
        "has_provided_identity_or_bank",
    }
    compact_text = "".join(str((route_decision.get("turn_rewrite") or {}).get("original_text") or "").split())
    global_denial = compact_text in {"都没有", "全都没有", "全部没有", "没有", "什么都没有", "啥都没有", "一个都没有"}
    return bool(
        pending_decision.get("is_pending_answer")
        and slot_updates
        and (core_exposure_slots.issubset(set(slot_updates)) or global_denial)
        and all(value is False for value in slot_updates.values())
    )


def _slots_from_pending_decision(route_decision: Dict[str, Any], evidence_text: str) -> tuple[Dict[str, str], Dict[str, str]]:
    pending_decision = route_decision.get("pending_answer_decision") or {}
    slots: Dict[str, str] = {}
    evidence: Dict[str, str] = {}
    for slot, value in (pending_decision.get("slot_updates") or {}).items():
        if isinstance(value, bool):
            slots[slot] = "true" if value else "false"
            evidence[slot] = evidence_text
    return slots, evidence


def _clarification_answer(route_decision: Dict[str, Any]) -> tuple[str, Dict[str, Any]]:
    question = route_decision.get("clarification_question") or "你是想了解反诈知识，还是需要我帮你判断当前风险？"
    options = route_decision.get("clarification_options") or []
    option_text = "\n".join(f"- {item.get('label', '')}" for item in options if item.get("label"))
    answer = question if not option_text else f"{question}\n{option_text}"
    return answer, {"clarification_options": options}


def run_lightweight_flow(
    session_id: str,
    user_query: str,
    memory_context: Dict[str, Any],
    route_decision: Dict[str, Any],
    is_stream: bool = False,
) -> Dict[str, Any]:
    intent = route_decision.get("primary_intent", INTENT_SMALLTALK)
    workflow = route_decision.get("workflow_mode", "fallback")
    if intent in DISABLED_CHAT_TOOL_INTENTS or workflow in DISABLED_CHAT_TOOL_WORKFLOWS:
        intent = INTENT_ANTI_FRAUD_QA
        workflow = "knowledge_answer"
        route_decision = {
            **route_decision,
            "primary_intent": INTENT_ANTI_FRAUD_QA,
            "workflow_mode": workflow,
            "reason": "可疑链接 / 内容一键举报已从普通聊天专项流程移除，普通聊天按反诈咨询处理。",
            "routing_decision": {
                **(route_decision.get("routing_decision") or {}),
                "target": workflow,
            },
        }
    add_running_task(session_id, "route_decision", is_stream)
    add_done_task(session_id, "route_decision", is_stream)
    add_running_task(session_id, workflow, is_stream)

    if intent == INTENT_ANTI_FRAUD_QA:
        answer, payload = _knowledge_answer(user_query)
    elif intent == INTENT_EDUCATION_GAME:
        answer, payload = _game_answer(session_id)
    elif intent == INTENT_RISK_FACT_CLARIFICATION:
        answer, payload = _risk_fact_clarification_answer(route_decision)
    elif intent == "clarify":
        answer, payload = _clarification_answer(route_decision)
    else:
        answer, payload = _fallback_answer()

    anti_fraud_engine = build_anti_fraud_engine_result(
        input_text=user_query,
        route_decision=route_decision,
        memory_context=memory_context,
    )
    payload.setdefault("anti_fraud_engine", anti_fraud_engine)
    payload.setdefault("risk_judgement_card", anti_fraud_engine.get("risk_judgement_card", {}))
    route_decision["anti_fraud_engine"] = anti_fraud_engine

    add_done_task(session_id, workflow, is_stream)
    existing_route_context = memory_context.get("route_context") or {}
    preserve_pending_question = (
        intent in {INTENT_SMALLTALK, "clarify"}
        and bool(memory_context.get("pending_question"))
        and existing_route_context.get("active_workflow") == "risk_case_flow"
    )
    answered_no_exposure = intent == INTENT_RISK_FACT_CLARIFICATION and _answered_no_exposure(route_decision)
    pending_slots, pending_slot_evidence = _slots_from_pending_decision(route_decision, user_query)
    memory_case_state = memory_context.get("case_state") or {}
    memory_case_status = memory_case_state.get("case_status", "active")

    summary = {
        "basic_input": {
            "session_id": session_id,
            "original_query": user_query,
            "rewritten_query": (route_decision.get("turn_rewrite") or {}).get("rewritten_text", ""),
            "is_stream": bool(is_stream),
        },
        "intent_recognition": route_decision,
        "route_decision": route_decision,
        "turn_rewrite": route_decision.get("turn_rewrite", {}),
        "pending_answer_decision": route_decision.get("pending_answer_decision", {}),
        "workflow_mode": workflow,
        "case_context_type": 3,
        "case_context_label": "智能客服任务",
        "case_status": "non_risk_task",
        "route_name": workflow,
        "answer_strategy": "RouteDecision 入口路由后的轻量专项流",
        "retrieved_docs": payload.get("retrieved_docs", []),
        "matched_rules": [],
        "risk_score": payload.get("risk_score", 0),
        "risk_level": payload.get("risk_level", ""),
        "warnings": [],
        "lightweight_payload": payload,
        "anti_fraud_engine": anti_fraud_engine,
        "risk_judgement_card": anti_fraud_engine.get("risk_judgement_card", {}),
        "memory_context": {
            "case_id": memory_context.get("case_id", ""),
            "memory_summary": memory_context.get("memory_summary", ""),
            "pending_question": memory_context.get("pending_question", {}),
            "route_context": memory_context.get("route_context", {}),
        },
    }

    state = {
        "session_id": session_id,
        "case_id": memory_context.get("case_id", ""),
        "original_query": user_query,
        "rewritten_query": (route_decision.get("turn_rewrite") or {}).get("rewritten_text", ""),
        "intent": intent,
        "intent_confidence": route_decision.get("confidence", 0),
        "route_decision": route_decision,
        "route_name": workflow,
        "case_status": memory_case_status if preserve_pending_question else "non_risk_task",
        "workflow_action": "ask_slots" if intent == INTENT_RISK_FACT_CLARIFICATION and not answered_no_exposure else "",
        "missing_info": ["has_paid", "has_shared_code", "has_screen_share", "has_downloaded_app", "has_clicked_link", "has_provided_identity_or_bank"] if intent == INTENT_RISK_FACT_CLARIFICATION and not answered_no_exposure else [],
        "next_question": "你是否已经转账、给验证码、共享屏幕、下载对方App、点链接填信息，或正在被催继续操作？" if intent == INTENT_RISK_FACT_CLARIFICATION and not answered_no_exposure else "",
        "case_context_type": 3,
        "case_context_label": "智能客服任务",
        "slots": pending_slots,
        "slot_evidence": pending_slot_evidence,
        "memory_context": memory_context,
        "preserve_pending_question": preserve_pending_question,
        "route_context": {
            "active_workflow": workflow,
            "workflow_status": "non_risk_task",
            "last_route_decision": route_decision,
            "pending_question": {},
        },
        "answer": answer,
        "result_summary": summary,
    }
    get_memory_manager().commit_turn(state)
    case_state = state.get("case_state", {})
    summary["case_state"] = case_state
    summary["memory_context"] = {
        "case_id": state.get("case_id", ""),
        "memory_summary": case_state.get("memory_summary", ""),
        "pending_question": (state.get("memory_context") or {}).get("pending_question", {}),
        "route_context": case_state.get("route_context", {}),
    }
    summary["route_memory"] = case_state.get("route_memory", {})

    decorated = attach_video_cards(
        {
            "session_id": session_id,
            "answer": answer,
            "summary": summary,
            "assistant_mode": summary.get("assistant_mode", ""),
            "workflow_mode": summary.get("workflow_mode", workflow),
            "fraud_type": summary.get("fraud_type", ""),
            "risk_judgement_card": summary.get("risk_judgement_card", {}),
        },
        session_id,
    )
    video_cards = decorated.get("video_cards", [])
    if video_cards:
        summary["video_cards"] = video_cards

    try:
        save_risk_chat_message(
            session_id=session_id,
            role="user",
            text=user_query,
            rewritten_query=(route_decision.get("turn_rewrite") or {}).get("rewritten_text", ""),
            risk_summary=summary,
        )
        save_risk_chat_message(
            session_id=session_id,
            role="assistant",
            text=answer,
            risk_summary=summary,
            video_cards=video_cards,
        )
    except Exception:
        summary.setdefault("warnings", []).append("保存轻量流程历史消息失败")

    set_task_result(session_id, "answer", answer)
    set_task_result(session_id, "risk_score", str(summary.get("risk_score", "")))
    set_task_result(session_id, "risk_level", str(summary.get("risk_level", "")))
    set_task_result(session_id, "result_summary", json.dumps(summary, ensure_ascii=False))
    set_task_result(session_id, "matched_rules", json.dumps(summary.get("matched_rules", []), ensure_ascii=False))
    set_task_result(session_id, "retrieved_docs", json.dumps(summary.get("retrieved_docs", []), ensure_ascii=False))

    if is_stream:
        push_to_session(
            session_id,
            SSEEvent.FINAL,
            {"answer": answer, "summary": summary, "video_cards": video_cards},
        )
    return {"answer": answer, "summary": summary}
