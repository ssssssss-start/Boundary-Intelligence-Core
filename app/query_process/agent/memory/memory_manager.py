"""Central memory manager for the anti-fraud interaction agent.

P0 scope:
- session memory: current case, active workflow, pending question
- case memory: slots, scam/risk/intervention/resolution snapshots
- case events: append-only audit timeline
- turn memory: redacted current turn facts

The legacy six-node graph still owns reasoning. This manager owns context
loading and state persistence so new memory features do not scatter MongoDB
writes across every node.
"""

from __future__ import annotations

import uuid
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from app.clients.mongo_history_utils import get_case_state, get_history_mongo_tool, get_recent_messages, save_case_state
from app.core.logger import logger
from app.query_process.agent.memory.memory_redactor import build_turn_memory, redact_sensitive_text
from app.query_process.services.risk_decay_manager import (
    apply_decay_to_case_snapshot,
    build_risk_decay_update,
)


TRUE = "true"
FALSE = "false"
UNKNOWN = "unknown"
MEMORY_VERSION = 1

EXPOSURE_SLOT_KEYS = {
    "has_paid": "has_ever_paid",
    "has_shared_code": "has_ever_shared_code",
    "has_screen_share": "has_ever_screen_shared",
    "has_downloaded_app": "has_ever_downloaded_app",
    "has_provided_identity_or_bank": "has_ever_provided_identity_or_bank",
}

RESOLUTION_SLOT_KEYS = {
    "has_stopped_operation",
    "has_contacted_bank",
    "has_reported_police",
    "has_preserved_evidence",
    "user_no_longer_believes_scammer",
    "funds_recovered",
    "has_official_channel_verification_guided",
    "has_report_decision_made",
}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _bool_from_slot(value: Any) -> Optional[bool]:
    if value is True or value == TRUE:
        return True
    if value is False or value == FALSE:
        return False
    return None


def _slot_status(slot: str, value: Any) -> str:
    bool_value = _bool_from_slot(value)
    if bool_value is False:
        return "denied_by_user"
    if slot in RESOLUTION_SLOT_KEYS and bool_value is True:
        return "completed_by_user"
    if slot in EXPOSURE_SLOT_KEYS and bool_value is True:
        return "completed_by_user"
    if slot == "current_requested_action" and value:
        return "requested_by_scammer"
    if slot in {"promised_benefit", "threat_or_pressure"} and value:
        return "requested_by_scammer"
    if value not in (None, "", [], {}, UNKNOWN):
        return "known"
    return "unknown"


class MemoryManager:
    """Read and write layered memory for one conversation turn."""

    def load_context(self, session_id: str, user_text: str, intent_hint: str = "") -> Dict[str, Any]:
        case_state = self._load_case_state(session_id)
        case_state = apply_decay_to_case_snapshot(case_state, user_text)
        case_id = case_state.get("case_id") or f"case_{uuid.uuid4().hex[:12]}"
        case_state["case_id"] = case_id
        case_state["session_id"] = session_id

        session_state = self._load_or_create_session_state(session_id, case_id)
        pending_question = session_state.get("pending_question") or case_state.get("route_context", {}).get("pending_question") or {}
        recent_user_messages = [
            {
                "role": item.get("role", ""),
                "text_redacted": redact_sensitive_text(str(item.get("text") or "")),
                "ts": item.get("ts"),
            }
            for item in get_recent_messages(session_id, limit=10)
            if item.get("role") == "user"
        ]
        turn_id = f"turn_{uuid.uuid4().hex[:12]}"
        created_at = _now()
        turn_memory = build_turn_memory(session_id, case_id, user_text, turn_id, created_at)
        route_context = case_state.get("route_context") or {
            "active_workflow": session_state.get("active_workflow", ""),
            "workflow_status": session_state.get("workflow_status", ""),
            "pending_question": pending_question,
            "last_route_decision": session_state.get("last_route_decision", {}),
        }

        return {
            "session_id": session_id,
            "case_id": case_id,
            "intent_hint": intent_hint or "",
            "session_state": session_state,
            "case_state": case_state,
            "pending_question": pending_question,
            "recent_user_messages": recent_user_messages,
            "memory_summary": case_state.get("memory_summary", ""),
            "route_context": route_context,
            "turn_memory": turn_memory,
        }

    def commit_turn(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Persist session, case, and audit memory after the graph finishes."""
        session_id = state.get("session_id", "")
        if not session_id:
            return state

        memory_context = state.get("memory_context") or {}
        case_id = state.get("case_id") or memory_context.get("case_id") or f"case_{uuid.uuid4().hex[:12]}"
        existing_case = deepcopy(state.get("case_state") or memory_context.get("case_state") or {})
        existing_case["case_id"] = case_id
        existing_case["session_id"] = session_id

        case_state = self.build_case_memory(state, existing_case)
        session_state = self.build_session_memory(state, case_state)

        try:
            save_case_state(session_id, case_state)
            self._save_session_state(session_state)
            for event_type, payload in self._events_for_turn(state, case_state):
                self.append_event(session_id, case_id, event_type, payload)
        except Exception as exc:
            logger.warning(f"commit anti-fraud memory failed: {exc}")

        state["case_id"] = case_id
        state["case_state"] = case_state
        state["memory_context"] = {
            **memory_context,
            "case_id": case_id,
            "case_state": case_state,
            "session_state": session_state,
            "pending_question": session_state.get("pending_question", {}),
            "route_context": case_state.get("route_context", {}),
            "memory_summary": case_state.get("memory_summary", ""),
        }
        return state

    def build_case_memory(self, state: Dict[str, Any], existing_case: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        existing = deepcopy(existing_case or {})
        slots = deepcopy(state.get("slots") or existing.get("slots") or {})
        slot_evidence = state.get("slot_evidence") or {}
        now = _now()

        case_state = deepcopy(existing)
        case_state.update({
            "case_id": state.get("case_id") or existing.get("case_id") or f"case_{uuid.uuid4().hex[:12]}",
            "session_id": state.get("session_id", existing.get("session_id", "")),
            "case_status": state.get("case_status", existing.get("case_status", "active")),
            "case_context_type": state.get("case_context_type", existing.get("case_context_type", 3)),
            "case_context_label": state.get("case_context_label", existing.get("case_context_label", "")),
            "updated_at": now,
            "version": MEMORY_VERSION,
            "slots": slots,
        })
        risk_decay = deepcopy(state.get("risk_decay") or {})
        if not risk_decay and (
            state.get("risk")
            or state.get("risk_score")
            or existing.get("risk_memory")
            or existing.get("risk_decay")
            or existing.get("risk_score")
        ):
            current_case_for_decay = {
                **case_state,
                "resolution": state.get("resolution") or existing.get("resolution_memory") or existing.get("resolution") or {},
                "risk_score": state.get("risk_score", existing.get("risk_score", 0)),
                "risk_level": state.get("risk_level", existing.get("risk_level", "")),
            }
            risk_decay = build_risk_decay_update(
                previous_case=existing,
                current_case=current_case_for_decay,
                current_text=str(state.get("original_query") or ""),
                slots=slots,
                risk_score=state.get("risk_score", existing.get("risk_score", 0)),
                risk_level=str(state.get("risk_level") or existing.get("risk_level") or ""),
                risk_class=str((state.get("risk") or {}).get("risk_class") or existing.get("risk_class") or ""),
                resolution=state.get("resolution") or existing.get("resolution_memory") or existing.get("resolution") or {},
            )
        if risk_decay:
            case_state["risk_decay"] = risk_decay
            case_state["risk_score"] = risk_decay.get("current_risk_score", state.get("risk_score", existing.get("risk_score", 0)))
            case_state["risk_level"] = risk_decay.get("risk_level", state.get("risk_level", existing.get("risk_level", "")))
            if risk_decay.get("case_status"):
                case_state["case_status"] = risk_decay.get("case_status")
            if risk_decay.get("risk_resolved"):
                case_state["risk_resolved"] = True
                case_state["ready_for_education"] = bool(risk_decay.get("ready_for_education", True))
            state["risk_decay"] = risk_decay
            state["risk_score"] = case_state["risk_score"]
            state["risk_level"] = case_state["risk_level"]
            state["case_status"] = case_state["case_status"]
            state["risk_resolved"] = bool(case_state.get("risk_resolved", False))
            state["ready_for_education"] = bool(case_state.get("ready_for_education", False))
        case_state["route_memory"] = self._build_route_memory(state, existing)
        case_state["route_context"] = self._build_route_context(state, existing)
        case_state["slot_memory"] = self._build_slot_memory(slots, slot_evidence, existing.get("slot_memory") or {}, state)
        case_state["exposure_memory"] = self._build_exposure_memory(slots, existing.get("exposure_memory") or {})
        case_state["current_unsafe_memory"] = self._build_current_unsafe_memory(slots, state)
        case_state["scam_memory"] = deepcopy(state.get("scam_understanding") or existing.get("scam_memory") or {})
        case_state["risk_memory"] = self._build_risk_memory(state)
        case_state["intervention_memory"] = self._build_intervention_memory(state)
        case_state["resolution_memory"] = self._build_resolution_memory(state)
        case_state["education_memory"] = self._build_education_memory(state)
        case_state["memory_summary"] = self.summarize_case(case_state)
        return case_state

    def build_session_memory(self, state: Dict[str, Any], case_state: Dict[str, Any]) -> Dict[str, Any]:
        memory_context = state.get("memory_context") or {}
        old_session = deepcopy(memory_context.get("session_state") or {})
        session_id = state.get("session_id", "")
        case_id = case_state.get("case_id", "")
        active_case_ids = _ensure_list(old_session.get("active_case_ids"))
        if case_id and case_id not in active_case_ids:
            active_case_ids.append(case_id)
        route_context = case_state.get("route_context") or {}
        pending_question = route_context.get("pending_question")
        if pending_question is None:
            pending_question = self._pending_question_from_state(state)
        return {
            **old_session,
            "session_id": session_id,
            "current_case_id": case_id,
            "active_case_ids": active_case_ids,
            "active_workflow": route_context.get("active_workflow", ""),
            "workflow_status": case_state.get("case_status", ""),
            "pending_question": pending_question,
            "last_route_decision": route_context.get("last_route_decision", {}),
            "last_user_turn_id": (memory_context.get("turn_memory") or {}).get("turn_id", ""),
            "updated_at": _now(),
        }

    def append_event(self, session_id: str, case_id: str, event_type: str, payload: Dict[str, Any]) -> None:
        try:
            tool = get_history_mongo_tool()
            tool.case_event.insert_one({
                "event_id": f"evt_{uuid.uuid4().hex[:12]}",
                "session_id": session_id,
                "case_id": case_id,
                "event_type": event_type,
                "event_payload": payload,
                "created_at": _now(),
            })
        except Exception as exc:
            logger.warning(f"append anti-fraud case event failed: {exc}")

    def summarize_case(self, case_state: Dict[str, Any]) -> str:
        scam = case_state.get("scam_memory") or {}
        risk = case_state.get("risk_memory") or {}
        exposure = case_state.get("exposure_memory") or {}
        resolution = case_state.get("resolution_memory") or {}
        parts = []
        scam_type = scam.get("primary_scam_type") or case_state.get("fraud_type") or "未知骗局"
        parts.append(f"疑似{scam_type}")
        if scam.get("fraud_stage"):
            parts.append(f"阶段：{scam.get('fraud_stage')}")
        if risk.get("display_risk_label"):
            parts.append(str(risk.get("display_risk_label")))
        if risk.get("risk_decay_status"):
            parts.append(f"状态：{risk.get('risk_decay_status')}")
        if exposure.get("has_ever_paid"):
            amount = exposure.get("loss_amount") or "未知金额"
            parts.append(f"历史上已发生资金损失：{amount}")
        if resolution.get("risk_resolved"):
            parts.append("当前风险解除核验已通过")
        elif resolution.get("missing_actions"):
            parts.append("仍需确认：" + "、".join(map(str, resolution.get("missing_actions")[:3])))
        return "；".join(parts)

    def _load_case_state(self, session_id: str) -> Dict[str, Any]:
        try:
            return get_case_state(session_id) or {}
        except Exception as exc:
            logger.warning(f"load case memory failed: {exc}")
            return {}

    def _load_or_create_session_state(self, session_id: str, case_id: str) -> Dict[str, Any]:
        if not session_id:
            return {}
        try:
            tool = get_history_mongo_tool()
            doc = tool.session_state.find_one({"session_id": session_id}) or {}
            if doc.get("_id") is not None:
                doc["_id"] = str(doc["_id"])
            if doc:
                return doc
            doc = {
                "session_id": session_id,
                "current_case_id": case_id,
                "active_case_ids": [case_id],
                "active_workflow": "",
                "workflow_status": "created",
                "pending_question": {},
                "last_route_decision": {},
                "created_at": _now(),
                "updated_at": _now(),
            }
            self._save_session_state(doc)
            return doc
        except Exception as exc:
            logger.warning(f"load session memory failed: {exc}")
            return {
                "session_id": session_id,
                "current_case_id": case_id,
                "active_case_ids": [case_id],
                "pending_question": {},
            }

    def _save_session_state(self, session_state: Dict[str, Any]) -> None:
        session_id = session_state.get("session_id", "")
        if not session_id:
            return
        document = deepcopy(session_state)
        document.pop("_id", None)
        tool = get_history_mongo_tool()
        tool.session_state.update_one({"session_id": session_id}, {"$set": document}, upsert=True)

    def _build_route_memory(self, state: Dict[str, Any], existing: Dict[str, Any]) -> Dict[str, Any]:
        memory_context = state.get("memory_context") or {}
        route_decision = state.get("route_decision") or {}
        primary_intent = route_decision.get("primary_intent") or state.get("intent", "")
        return {
            **(existing.get("route_memory") or {}),
            "primary_intent": primary_intent,
            "secondary_intents": route_decision.get("secondary_intents", []),
            "workflow_mode": route_decision.get("workflow_mode") or self._workflow_mode_from_state(state),
            "intent_confidence": route_decision.get("confidence", state.get("intent_confidence", 0)),
            "intent_hint": state.get("intent_hint") or memory_context.get("intent_hint", ""),
            "intent_reason": route_decision.get("reason", state.get("intent_reason", "")),
            "route_decision": route_decision,
            "updated_at": _now(),
        }

    def _build_route_context(self, state: Dict[str, Any], existing: Dict[str, Any]) -> Dict[str, Any]:
        memory_context = state.get("memory_context") or {}
        old = deepcopy(existing.get("route_context") or {})
        pending_question = self._pending_question_from_state(state)
        preserve_pending = bool(state.get("preserve_pending_question"))
        if preserve_pending and not pending_question:
            pending_question = old.get("pending_question") or memory_context.get("pending_question") or {}
        route_decision = state.get("route_decision") or {}
        mode = route_decision.get("workflow_mode") or self._workflow_mode_from_state(state)
        active_workflow = mode
        workflow_status = state.get("case_status", "")
        risk_resolved = bool((state.get("resolution") or {}).get("risk_resolved"))
        risk_decay = state.get("risk_decay") or {}
        decay_status = str(risk_decay.get("status") or "")
        case_status = str(state.get("case_status") or "")
        case_is_closed = risk_resolved or case_status in {"prevented", "stop_loss_done", "education_ready", "closed", "observation"}
        if decay_status in {"resolved", "observation"}:
            case_is_closed = True
        if case_is_closed:
            pending_question = {}
            active_workflow = "idle"
        last_route_decision = {
            **route_decision,
            "primary_intent": route_decision.get("primary_intent", state.get("intent", "")),
            "workflow_mode": mode,
            "workflow_action": state.get("workflow_action", ""),
            "risk_class": (state.get("risk") or {}).get("risk_class", ""),
            "confidence": route_decision.get("confidence", state.get("intent_confidence", 0)),
        }
        if preserve_pending:
            active_workflow = old.get("active_workflow") or "risk_case_flow"
            workflow_status = old.get("workflow_status") or workflow_status
            last_route_decision = old.get("last_route_decision") or last_route_decision
        if case_is_closed:
            preserve_pending = False
            active_workflow = "idle"
        locked = active_workflow == "risk_case_flow" and not risk_resolved and case_status not in {"prevented", "stop_loss_done", "mitigated", "observation"}
        return {
            **old,
            "active_workflow": active_workflow,
            "workflow_status": workflow_status,
            "intent_lock": {
                "locked": locked,
                "mode": active_workflow if locked else "",
                "priority": 90 if locked else 0,
                "until": "risk_resolved" if locked else "",
                "reason": "risk case is not resolved" if locked else "",
            },
            "pending_question": pending_question,
            "last_route_decision": last_route_decision,
            "updated_at": _now(),
        }

    def _workflow_mode_from_state(self, state: Dict[str, Any]) -> str:
        intent = state.get("intent", "")
        if state.get("route_name") in {"loss_response", "prevention_consult", "slot_collection"}:
            return "risk_case_flow"
        if intent == "knowledge_consult":
            return "knowledge_answer"
        return "risk_case_flow" if state.get("risk") or state.get("slots") else "fallback"

    def _pending_question_from_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        if (state.get("resolution") or {}).get("risk_resolved") or state.get("case_status") in {"prevented", "stop_loss_done", "education_ready", "closed", "observation"}:
            return {}
        existing_pending = (state.get("case_state") or {}).get("pending_question") or state.get("pending_question") or {}
        if existing_pending.get("type") in {"risk_followup", "semantic_followup"} and existing_pending.get("allow_free_text"):
            return existing_pending
        semantic_question = str(state.get("next_question") or "").strip()
        semantic_analysis = state.get("semantic_risk_analysis") or {}
        if state.get("workflow_action") == "semantic_risk_agent" and semantic_question:
            return {
                "question_id": f"pq_{uuid.uuid4().hex[:8]}",
                "type": "semantic_followup",
                "allow_free_text": True,
                "ask_goal": semantic_question,
                "missing_facts": _ensure_list(semantic_analysis.get("missing_facts")),
                "question_text": semantic_question,
                "source": "semantic_risk_agent",
                "asked_at": _now(),
            }
        intervention_dialogue = state.get("intervention_dialogue") or {}
        intervention_question = str(intervention_dialogue.get("confirmation_question") or "").strip()
        intervention_slot = str(intervention_dialogue.get("next_required_slot") or "").strip()
        slot_aliases = {
            "has_transfer": ["has_paid"],
            "has_given_code": ["has_shared_code"],
            "has_given_bank_info": ["has_provided_identity_or_bank"],
            "has_screen_sharing": ["has_screen_share"],
            "has_downloaded_app": ["has_downloaded_app"],
            "has_clicked_url": ["has_clicked_link"],
            "evidence_saved": ["has_preserved_evidence"],
            "has_stopped_operation": ["has_stopped_operation"],
            "has_advance_payment_request": ["has_advance_payment_request"],
            "has_continue_payment_request": ["has_continue_payment_request"],
            "report_needed": ["has_report_decision_made"],
        }
        if intervention_question and intervention_slot in slot_aliases:
            return {
                "question_id": f"pq_{uuid.uuid4().hex[:8]}",
                "type": "slot_check",
                "target_slots": slot_aliases[intervention_slot],
                "question_text": intervention_question,
                "asked_at": _now(),
            }
        if state.get("workflow_action") == "ask_slots":
            return {
                "question_id": f"pq_{uuid.uuid4().hex[:8]}",
                "type": "slot_check",
                "target_slots": _ensure_list(state.get("missing_info")),
                "question_text": state.get("next_question", ""),
                "asked_at": _now(),
            }
        dynamic_question = ((state.get("dialogue_policy") or {}).get("one_key_question") or "").strip()
        if dynamic_question:
            target_slots = []
            if any(word in dynamic_question for word in ["转账", "付款", "充值", "垫付", "补单", "交钱", "交费", "缴费", "金额"]):
                target_slots.append("has_paid")
            if "验证码" in dynamic_question:
                target_slots.append("has_shared_code")
            if "屏幕" in dynamic_question or "远程" in dynamic_question:
                target_slots.append("has_screen_share")
            if "下载" in dynamic_question or "安装" in dynamic_question or "App" in dynamic_question or "软件" in dynamic_question:
                target_slots.append("has_downloaded_app")
            if "链接" in dynamic_question or "扫码" in dynamic_question:
                target_slots.append("has_clicked_link")
            if any(word in dynamic_question for word in ["密码", "银行卡", "身份证", "身份信息", "人脸", "敏感信息"]):
                target_slots.append("has_provided_identity_or_bank")
            if target_slots:
                return {
                    "question_id": f"pq_{uuid.uuid4().hex[:8]}",
                    "type": "slot_check",
                    "target_slots": list(dict.fromkeys(target_slots)),
                    "question_text": dynamic_question,
                    "asked_at": _now(),
                }
        pending_actions = _ensure_list(state.get("pending_resolution_actions"))
        if pending_actions:
            return {
                "question_id": f"pq_{uuid.uuid4().hex[:8]}",
                "type": "resolution_check",
                "target_slots": pending_actions,
                "question_text": state.get("next_question", ""),
                "asked_at": _now(),
            }
        return {}

    def _build_slot_memory(
        self,
        slots: Dict[str, Any],
        evidence: Dict[str, str],
        old_memory: Dict[str, Any],
        state: Dict[str, Any],
    ) -> Dict[str, Any]:
        turn_id = ((state.get("memory_context") or {}).get("turn_memory") or {}).get("turn_id", "")
        updated = deepcopy(old_memory or {})
        now = _now()
        for slot, value in slots.items():
            if value in (None, "", [], {}, UNKNOWN) and slot in updated:
                continue
            if value in (None, "", [], {}, UNKNOWN):
                updated.setdefault(slot, {
                    "value": None,
                    "status": "unknown",
                    "confidence": 0.0,
                    "source": "unknown",
                })
                continue
            old = updated.get(slot, {})
            updated[slot] = {
                **old,
                "value": _bool_from_slot(value) if _bool_from_slot(value) is not None else value,
                "status": _slot_status(slot, value),
                "confidence": 0.92 if evidence.get(slot) else old.get("confidence", 0.65),
                "source": "user" if evidence.get(slot) else old.get("source", "system"),
                "source_turn_id": turn_id or old.get("source_turn_id", ""),
                "evidence_text": redact_sensitive_text(evidence.get(slot) or old.get("evidence_text", "")),
                "updated_at": now,
            }
        return updated

    def _build_exposure_memory(self, slots: Dict[str, Any], old: Dict[str, Any]) -> Dict[str, Any]:
        exposure = deepcopy(old or {})
        for slot, memory_key in EXPOSURE_SLOT_KEYS.items():
            current = _bool_from_slot(slots.get(slot))
            if current is True:
                exposure[memory_key] = True
            elif memory_key not in exposure:
                exposure[memory_key] = False if current is False else None
        if slots.get("loss_amount"):
            exposure["loss_amount"] = slots.get("loss_amount")
        elif "loss_amount" not in exposure:
            exposure["loss_amount"] = ""
        return exposure

    def _build_current_unsafe_memory(self, slots: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
        text = str(state.get("original_query") or "")
        stopped = slots.get("has_stopped_operation") == TRUE
        return {
            "is_currently_transferring": False if stopped else any(word in text for word in ["正在转", "继续转", "马上转", "准备转"]),
            "is_currently_screen_sharing": False if stopped else any(word in text for word in ["还在共享", "正在共享", "继续共享", "还在远程", "正在远程"]),
            "is_currently_following_scammer": False if stopped else any(word in text for word in ["还在按", "继续按", "准备按"]),
            "is_currently_in_call_with_scammer": False if stopped else any(word in text for word in ["还在通话", "正在通话", "还没挂"]),
            "updated_at": _now(),
        }

    def _build_risk_memory(self, state: Dict[str, Any]) -> Dict[str, Any]:
        risk = state.get("risk") or {}
        risk_class = risk.get("risk_class", "")
        risk_decay = deepcopy(state.get("risk_decay") or {})
        score = risk_decay.get("current_risk_score", state.get("risk_score", 0)) if risk_decay else state.get("risk_score", 0)
        label = risk_decay.get("risk_level", state.get("risk_level", "")) if risk_decay else state.get("risk_level", "")
        return {
            "internal_risk_class": risk_class,
            "danger_level": "critical" if risk_class == "high_loss" else "high" if state.get("risk_features") else "low",
            "exposure_state": "loss_or_exposed" if risk_class == "high_loss" else "no_loss_yet",
            "intervention_mode": "stop_loss" if risk_class == "high_loss" else "preventive_block",
            "display_risk_label": label,
            "risk_score": score,
            "risk_reason": risk.get("reason") or state.get("score_reason", ""),
            "matched_rules": state.get("matched_rules", []),
            "risk_decay_status": risk_decay.get("status", ""),
            "base_risk_score": risk_decay.get("base_risk_score", state.get("risk_score", 0)) if risk_decay else state.get("risk_score", 0),
            "risk_decay": risk_decay,
            "updated_at": _now(),
        }

    def _build_intervention_memory(self, state: Dict[str, Any]) -> Dict[str, Any]:
        intervention = deepcopy(state.get("intervention") or {})
        return {
            "last_intervention_mode": intervention.get("route", ""),
            "actions_given": intervention.get("actions", []),
            "pending_actions": state.get("pending_resolution_actions", []),
            "next_question": intervention.get("next_question") or state.get("next_question", ""),
            "last_intervention_at": _now(),
        }

    def _build_resolution_memory(self, state: Dict[str, Any]) -> Dict[str, Any]:
        resolution = deepcopy(state.get("resolution") or {})
        risk_decay = deepcopy(state.get("risk_decay") or {})
        return {
            "risk_resolved": bool(resolution.get("risk_resolved", False)),
            "resolution_level": resolution.get("resolution_level", ""),
            "completed_actions": resolution.get("completed_actions", []),
            "missing_actions": resolution.get("missing_resolution_actions", []),
            "missing_action_ids": resolution.get("missing_action_ids", []),
            "unsafe_signals": resolution.get("unsafe_signals", []),
            "ready_for_education": bool(resolution.get("ready_for_education", False)),
            "judge_source": resolution.get("judge_source", ""),
            "reason": resolution.get("reason", ""),
            "closure_standard": resolution.get("closure_standard", {}),
            "risk_decay_status": risk_decay.get("status", ""),
            "last_resolution_check_at": _now(),
        }

    def _build_education_memory(self, state: Dict[str, Any]) -> Dict[str, Any]:
        scam_type = (state.get("scam_understanding") or {}).get("primary_scam_type") or state.get("fraud_type", "")
        ready = bool(state.get("ready_for_education", False))
        return {
            "recommended_topic": scam_type,
            "quiz_offered": ready,
            "quiz_completed": False,
            "reward_score": 0,
            "ready_for_education": ready,
            "updated_at": _now(),
        }

    def _events_for_turn(self, state: Dict[str, Any], case_state: Dict[str, Any]) -> List[tuple[str, Dict[str, Any]]]:
        turn = (state.get("memory_context") or {}).get("turn_memory") or {}
        base = {
            "turn_id": turn.get("turn_id", ""),
            "user_text_redacted": turn.get("user_text_redacted", redact_sensitive_text(state.get("original_query", ""))),
        }
        events: List[tuple[str, Dict[str, Any]]] = [
            ("route_decided", {**base, "route_memory": case_state.get("route_memory", {})}),
        ]
        if state.get("slot_evidence"):
            events.append(("slot_updated", {**base, "slot_evidence": state.get("slot_evidence", {})}))
        if state.get("scam_understanding"):
            events.append(("scam_type_detected", {**base, "scam_memory": case_state.get("scam_memory", {})}))
        if state.get("risk"):
            events.append(("risk_decided", {**base, "risk_memory": case_state.get("risk_memory", {})}))
        if state.get("intervention"):
            events.append(("intervention_given", {**base, "intervention_memory": case_state.get("intervention_memory", {})}))
        if state.get("resolution"):
            events.append(("resolution_checked", {**base, "resolution_memory": case_state.get("resolution_memory", {})}))
        return events


_memory_manager: Optional[MemoryManager] = None


def get_memory_manager() -> MemoryManager:
    global _memory_manager
    if _memory_manager is None:
        _memory_manager = MemoryManager()
    return _memory_manager
