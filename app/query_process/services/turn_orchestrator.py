"""Policy layer that turns safety and semantic frames into route decisions.

This module keeps route priority explicit:
emergency stop-loss > preventive risk case > risk fact collection > knowledge >
true smalltalk fallback.  It does not replace the rule engine; it only decides
which workflow should receive the turn.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


INTENT_ANTI_FRAUD_QA = "anti_fraud_qa"
INTENT_RISK_HELP = "risk_help"
INTENT_EMERGENCY_HELP = "emergency_help"
INTENT_RISK_FACT_CLARIFICATION = "risk_fact_clarification"
INTENT_EDUCATION_GAME = "education_game"
INTENT_SMALLTALK = "smalltalk"
INTENT_CLARIFY = "clarify"

WORKFLOW_BY_INTENT = {
    INTENT_ANTI_FRAUD_QA: "knowledge_answer",
    INTENT_RISK_HELP: "risk_case_flow",
    INTENT_EMERGENCY_HELP: "risk_case_flow",
    INTENT_RISK_FACT_CLARIFICATION: "risk_case_flow",
    INTENT_SMALLTALK: "fallback",
    INTENT_CLARIFY: "clarification",
}


def _base_policy(
    intent: str,
    confidence: float,
    reason: str,
    force_high_risk: bool = False,
    secondary_intents: Optional[List[str]] = None,
    prefill_slots: Optional[Dict[str, Any]] = None,
    urgency: str = "normal",
) -> Dict[str, Any]:
    workflow = WORKFLOW_BY_INTENT.get(intent, "fallback")
    return {
        "primary_intent": intent,
        "workflow_mode": workflow,
        "confidence": confidence,
        "urgency": urgency,
        "reason": reason,
        "secondary_intents": secondary_intents or [],
        "routing_decision": {
            "target": workflow,
            "force_high_risk": force_high_risk,
            "prefill_slots": prefill_slots or {},
        },
    }


def hard_safety_policy(
    safety_signals: Dict[str, Any],
    semantic_frame: Dict[str, Any],
    entities: Dict[str, Any] | None = None,
) -> Optional[Dict[str, Any]]:
    """Return a non-negotiable route when safety facts are clear."""
    entities = entities or {}
    prefill_slots = dict(safety_signals.get("slots") or {})
    prefill_slots.update(semantic_frame.get("slot_updates") or {})

    if safety_signals.get("confirmed_exposure_signal"):
        return _base_policy(
            INTENT_EMERGENCY_HELP,
            0.96,
            "安全硬规则：用户已出现资金、虚拟资产、验证码、屏幕共享、陌生App或敏感信息暴露",
            force_high_risk=True,
            prefill_slots=prefill_slots,
            urgency="emergency",
        )

    if safety_signals.get("requested_action_signal"):
        return _base_policy(
            INTENT_RISK_HELP,
            0.9,
            "安全硬规则：用户描述对方正在提出转账、验证码、屏幕共享、下载App或链接填信息等高危要求",
            prefill_slots=prefill_slots,
            urgency="normal",
        )
    return None


def semantic_policy(
    safety_signals: Dict[str, Any],
    semantic_frame: Dict[str, Any],
    entities: Dict[str, Any] | None = None,
) -> Optional[Dict[str, Any]]:
    """Route by semantic frame when no hard safety route already fired."""
    entities = entities or {}
    route = semantic_frame.get("recommended_route", "")
    dialogue_act = semantic_frame.get("dialogue_act", "")
    prefill_slots = dict(safety_signals.get("slots") or {})
    prefill_slots.update(semantic_frame.get("slot_updates") or {})

    if route == "risk_case_flow" or dialogue_act in {"risk_claim", "risk_help", "risk_fact_clarification", "emergency_update"}:
        if safety_signals.get("personal_risk_claim") and not safety_signals.get("confirmed_exposure_signal") and not safety_signals.get("requested_action_signal"):
            return _base_policy(
                INTENT_RISK_FACT_CLARIFICATION,
                max(float(semantic_frame.get("confidence", 0) or 0), 0.84),
                "语义回合判断：用户表达自身遭遇/疑似遭遇诈骗，但关键事实不足，进入风险链路补槽",
                prefill_slots=prefill_slots,
                urgency="normal",
            )
        return _base_policy(
            INTENT_RISK_HELP,
            max(float(semantic_frame.get("confidence", 0) or 0), 0.82),
            "语义回合判断：用户输入属于当前风险求助，交给风险工作流研判",
            prefill_slots=prefill_slots,
            urgency="normal",
        )

    if route == "knowledge_answer":
        return _base_policy(INTENT_ANTI_FRAUD_QA, max(float(semantic_frame.get("confidence", 0) or 0), 0.78), "语义回合判断：用户明确在咨询反诈知识", urgency="none")
    if route == "fallback" and safety_signals.get("is_smalltalk"):
        return _base_policy(INTENT_SMALLTALK, 0.82, "语义回合判断：明确闲聊/身份询问", urgency="none")
    return None


def fallback_guard_policy(
    safety_signals: Dict[str, Any],
    semantic_frame: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Prevent any risk-like text from reaching the smalltalk fallback."""
    if safety_signals.get("risk_vocabulary_guard") or semantic_frame.get("dialogue_act") in {"risk_claim", "risk_fact_clarification"}:
        prefill_slots = dict(safety_signals.get("slots") or {})
        prefill_slots.update(semantic_frame.get("slot_updates") or {})
        return _base_policy(
            INTENT_RISK_FACT_CLARIFICATION,
            0.78,
            "fallback 安全闸门：输入含风险语义，禁止进入自我介绍兜底，转入风险补槽",
            prefill_slots=prefill_slots,
            urgency="normal",
        )
    return None
