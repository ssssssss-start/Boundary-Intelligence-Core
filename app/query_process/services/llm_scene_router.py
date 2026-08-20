"""LLM-first scene routing for the unified anti-fraud assistant.

This replaces the old keyword-heavy intent router for the user-facing chat
entry.  The router only decides which workflow should handle the turn; it does
not generate visible user text.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from langchain_core.messages import HumanMessage, SystemMessage

from app.lm.lm_utils import get_llm_client
from app.anti_fraud.taxonomy import fraud_type_registry
from app.query_process.agent.nodes.common import extract_json_object, get_message_content
from app.query_process.services.semantic_risk_agent import build_scam_catalog_for_prompt, build_semantic_policy_for_prompt
from app.utils.timeout_utils import call_with_timeout, env_timeout


VALID_WORKFLOWS = {"risk_case_flow", "knowledge_answer", "fallback", "clarification"}
DISABLED_CHAT_TOOL_WORKFLOWS = {"url_check", "report_flow"}
DISABLED_CHAT_TOOL_INTENTS = {"url_check", "report_submit"}
DISABLED_CHAT_TOOL_SCENES = {"report_or_evidence_help", "url_or_content_check"}


def _history_for_prompt(memory_context: Dict[str, Any]) -> List[Dict[str, Any]]:
    values: List[Dict[str, Any]] = []
    for item in memory_context.get("recent_user_messages") or []:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text_redacted") or item.get("text") or "").strip()
        if text:
            values.append({"role": "user", "text": text})
    return values[-6:]


def _normalize_route(raw: Dict[str, Any], user_text: str) -> Dict[str, Any]:
    scene = raw.get("scene") if isinstance(raw.get("scene"), dict) else {}
    scene_type = str(scene.get("scene_type") or raw.get("scene_type") or "clarification").strip()
    workflow = str(raw.get("workflow_mode") or "").strip()
    disabled_chat_tool_route = workflow in DISABLED_CHAT_TOOL_WORKFLOWS or scene_type in DISABLED_CHAT_TOOL_SCENES
    if disabled_chat_tool_route:
        scene_type = "knowledge_consultation"
    if disabled_chat_tool_route:
        workflow = "knowledge_answer"
    if workflow not in VALID_WORKFLOWS:
        if scene_type in {"personal_risk_scene", "post_loss_help", "risk_followup", "realtime_dissuasion"}:
            workflow = "risk_case_flow"
        elif scene_type in {"knowledge_consultation", "case_learning", "law_consult"}:
            workflow = "knowledge_answer"
        elif scene_type == "smalltalk":
            workflow = "fallback"
        else:
            workflow = "clarification"

    is_risk = workflow == "risk_case_flow"
    primary_intent = str(raw.get("primary_intent") or "").strip()
    if not primary_intent:
        primary_intent = {
            "risk_case_flow": "risk_help",
            "knowledge_answer": "anti_fraud_qa",
            "fallback": "smalltalk",
            "clarification": "clarify",
        }.get(workflow, "clarify")
    elif primary_intent in DISABLED_CHAT_TOOL_INTENTS:
        primary_intent = "anti_fraud_qa"

    confidence = raw.get("confidence", scene.get("confidence", 0.0))
    try:
        confidence_value = max(0.0, min(float(confidence), 1.0))
    except (TypeError, ValueError):
        confidence_value = 0.0

    reason = str(raw.get("reason") or scene.get("reason") or "").strip()
    normalized_topic = str(raw.get("normalized_topic") or raw.get("topic") or "").strip()
    fraud_type_id = str(raw.get("fraud_type_id") or "").strip()
    query_rewrite = str(raw.get("query_rewrite") or raw.get("rewritten_text") or user_text).strip()
    is_personal_risk_scene = bool(raw.get("is_personal_risk_scene", is_risk))
    needs_clarification = bool(raw.get("needs_clarification", workflow == "clarification"))
    prefill_slots = raw.get("prefill_slots") if isinstance(raw.get("prefill_slots"), dict) else {}
    prefill_slots = {
        **prefill_slots,
        "normalized_topic": normalized_topic,
        "fraud_type_id": fraud_type_id,
        "query_rewrite": query_rewrite,
    }
    return {
        "primary_intent": primary_intent,
        "secondary_intents": raw.get("secondary_intents") if isinstance(raw.get("secondary_intents"), list) else [],
        "workflow_mode": workflow,
        "confidence": confidence_value,
        "urgency": str(raw.get("urgency") or ("normal" if is_risk else "none")),
        "safety_override": bool(raw.get("safety_override", False)),
        "continue_current_workflow": bool(raw.get("continue_current_workflow", False)),
        "reason": reason or "LLM scene router decision",
        "need_clarification": needs_clarification,
        "clarification_question": str(raw.get("clarification_question") or ""),
        "clarification_options": raw.get("clarification_options") if isinstance(raw.get("clarification_options"), list) else [],
        "is_personal_risk_scene": is_personal_risk_scene,
        "normalized_topic": normalized_topic,
        "fraud_type_id": fraud_type_id,
        "query_rewrite": query_rewrite,
        "risk_signals": raw.get("risk_signals") if isinstance(raw.get("risk_signals"), dict) else {},
        "routing_decision": {
            "target": workflow,
            "force_high_risk": bool(raw.get("force_high_risk", False)),
            "prefill_slots": prefill_slots,
        },
        "semantic_scene": {
            **scene,
            "scene_type": scene_type,
            "is_risk_scene": is_risk,
            "user_text": user_text,
        },
        "turn_rewrite": {
            "judge_source": "llm_scene_router",
            "original_text": user_text,
            "rewritten_text": query_rewrite,
            "confidence": confidence_value,
            "reason": reason,
        },
        "pending_answer_decision": {
            "is_pending_answer": bool(raw.get("is_pending_answer", False)),
            "slot_updates": {},
            "completed_actions": [],
            "denied_actions": [],
            "confidence": confidence_value if raw.get("is_pending_answer") else 0.0,
            "reason": reason,
        },
    }


def route_user_input_llm(user_text: str, memory_context: Dict[str, Any], intent_hint: str = "") -> Dict[str, Any]:
    """Return a workflow route using the LLM.

    If the LLM is unavailable or returns invalid JSON, the exception is allowed
    to propagate.  The product decision is: no model, no synthetic fallback
    answer.
    """
    user_text = str(user_text or "").strip()
    memory_context = dict(memory_context or {})
    catalog = build_scam_catalog_for_prompt(max_features_per_scam=4)
    taxonomy_catalog = [
        {
            "fraud_type_id": row.get("fraud_type_id", ""),
            "standard_name": row.get("standard_name", ""),
            "aliases": row.get("aliases", [])[:10],
            "parent_category": row.get("parent_category", ""),
        }
        for row in fraud_type_registry()
    ]
    policy = build_semantic_policy_for_prompt()
    system_prompt = """
你是反诈智能体的入口场景路由器，只输出 JSON，不回答用户。

核心原则：
1. 先区分“知识咨询”和“用户自己的风险处境”。咨询某类诈骗是什么，本身不是风险场景，走 knowledge_answer。
2. 用户描述自己、家人、朋友正在接触对方、已经被骗、钱没收到、账号给了、还能不能继续、对方还在催，这些走 risk_case_flow。
3. 用户在回答上一轮风险追问，即使只说“没有”“有”“还没”“已经给了”，如果会话里有 active risk workflow，也走 risk_case_flow。
4. “可疑链接 / 内容一键举报”已经从普通聊天意图中移除，只能通过页面左下角 + 菜单的独立小窗触发；普通聊天不要输出 report_flow、url_check 或 report_submit。
5. 用户只粘贴链接、短信或说“我要举报/检测链接”，但没有描述自己正在受骗、已操作或被催促操作时，按反诈知识咨询处理，走 knowledge_answer。
6. 用户描述自己、家人、朋友正在被要求点击链接、转账、填验证码/银行卡/身份证、下载 App、屏幕共享，走 risk_case_flow。
7. 不要因为出现诈骗类型名称就判为风险场景，必须看是否有个人处境或正在发生的行为。
8. 如果用户只是问“租房诈骗/银行转账骗局/某行业骗局怎么防”这类知识问题，要归入 knowledge_answer，并给出标准主题或通用主题。
9. normalized_topic 必须是 taxonomy 中的 standard_name；如果不是单一诈骗类型，使用通用主题名，例如“通用转账安全/资金风险科普”。
10. query_rewrite 要把用户口语改写成更适合本地 RAG 或可信 Web 检索的查询。
"""
    human_prompt = f"""
【用户本轮输入】
{user_text}

【intent_hint】
{intent_hint or ""}

【会话记忆】
{json.dumps({
    "pending_question": memory_context.get("pending_question", {}),
    "route_context": memory_context.get("route_context", {}),
    "memory_summary": memory_context.get("memory_summary", ""),
    "recent_user_messages": _history_for_prompt(memory_context),
}, ensure_ascii=False)}

【可用骗局类型目录】
{json.dumps(catalog, ensure_ascii=False)}

【统一诈骗类型 taxonomy】
{json.dumps(taxonomy_catalog, ensure_ascii=False)}

【语义风险策略】
{json.dumps(policy, ensure_ascii=False)}

请返回严格 JSON：
{{
  "scene": {{
    "scene_type": "knowledge_consultation|personal_risk_scene|post_loss_help|risk_followup|smalltalk|clarification",
    "is_risk_scene": true,
    "reason": "为什么这样路由",
    "confidence": 0.0
  }},
  "primary_intent": "anti_fraud_qa|risk_help|emergency_help|risk_fact_clarification|smalltalk|clarify",
  "workflow_mode": "risk_case_flow|knowledge_answer|fallback|clarification",
  "secondary_intents": [],
  "urgency": "none|normal|urgent|critical",
  "continue_current_workflow": false,
  "is_pending_answer": false,
  "is_personal_risk_scene": false,
  "normalized_topic": "标准诈骗类型名；或通用主题；不明确则空字符串",
  "fraud_type_id": "taxonomy 中的 fraud_type_id；通用主题可用 general_anti_fraud；不明确则空字符串",
  "query_rewrite": "适合本地知识库和可信 Web 检索的简短改写",
  "needs_clarification": false,
  "reason": "一句话路由依据",
  "rewritten_text": "保留用户事实的简短改写",
  "confidence": 0.0
}}
"""
    llm = get_llm_client(json_mode=True)
    timeout_seconds = env_timeout("ANTI_FRAUD_LLM_ROUTE_TIMEOUT_SECONDS", 1.5)
    response = call_with_timeout(
        lambda: llm.invoke([SystemMessage(content=system_prompt.strip()), HumanMessage(content=human_prompt.strip())]),
        timeout_seconds,
    )
    data = extract_json_object(get_message_content(response))
    if not data:
        raise ValueError("LLM scene router returned empty JSON")
    return _normalize_route(data, user_text)


__all__ = ["route_user_input_llm"]
