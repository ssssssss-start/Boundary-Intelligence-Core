import unittest
from datetime import datetime, timedelta

from app.query_process.agent.memory.memory_manager import MemoryManager
from app.query_process.agent.nodes.compact_workflow_core import FALSE, TRUE, node_case_context
from app.query_process.services.risk_decay_manager import apply_decay_to_case_snapshot


class MemoryLayerTest(unittest.TestCase):
    def test_pending_question_binds_short_denial_to_target_slots(self):
        state = {
            "session_id": "",
            "case_id": "case_test",
            "history": [],
            "history_text": "",
            "original_query": "没有",
            "memory_context": {
                "case_id": "case_test",
                "case_state": {},
                "pending_question": {
                    "type": "slot_check",
                    "target_slots": ["has_paid", "has_shared_code"],
                    "question_text": "你有没有已经转账或给过验证码？",
                },
            },
        }

        state = node_case_context(state)

        self.assertEqual(state["slots"]["has_paid"], FALSE)
        self.assertEqual(state["slots"]["has_shared_code"], FALSE)
        self.assertEqual(state["slot_evidence"]["has_paid"], "没有")
        self.assertEqual(state["pending_question"]["target_slots"], ["has_paid", "has_shared_code"])

    def test_slot_check_confirmation_does_not_mark_all_exposure_slots_true(self):
        state = {
            "session_id": "",
            "case_id": "case_test",
            "history": [],
            "history_text": "",
            "original_query": "确认",
            "memory_context": {
                "case_id": "case_test",
                "case_state": {},
                "pending_question": {
                    "type": "slot_check",
                    "target_slots": ["has_paid", "has_shared_code"],
                    "question_text": "你有没有已经转账或给过验证码？",
                },
            },
        }

        state = node_case_context(state)

        self.assertNotEqual(state["slots"]["has_paid"], TRUE)
        self.assertNotEqual(state["slots"]["has_shared_code"], TRUE)

    def test_single_slot_positive_answer_can_bind_to_pending_safety_slot(self):
        state = {
            "session_id": "",
            "case_id": "case_test",
            "history": [],
            "history_text": "",
            "original_query": "有",
            "memory_context": {
                "case_id": "case_test",
                "case_state": {},
                "pending_question": {
                    "type": "slot_check",
                    "target_slots": ["has_paid"],
                    "question_text": "你有没有已经转账？",
                },
            },
        }

        state = node_case_context(state)

        self.assertEqual(state["slots"]["has_paid"], TRUE)
        self.assertEqual(state["slot_evidence"]["has_paid"], "有")

    def test_resolution_pending_global_done_marks_missing_actions(self):
        state = {
            "session_id": "",
            "case_id": "case_test",
            "history": [],
            "history_text": "",
            "original_query": "我已经都完成了",
            "memory_context": {
                "case_id": "case_test",
                "case_state": {},
                "pending_question": {
                    "type": "resolution_check",
                    "target_slots": ["stopped_operation", "contacted_bank", "reported_police", "preserved_evidence"],
                    "question_text": "你是否已经停止操作、联系银行、报警并保存证据？",
                },
            },
            "route_decision": {
                "pending_answer_decision": {
                    "is_pending_answer": True,
                    "pending_type": "resolution_check",
                    "confidence": 0.88,
                    "reason": "上下文语义改写判断用户在概括确认上一轮全部止损动作",
                    "slot_updates": {},
                    "completed_actions": ["stopped_operation", "contacted_bank", "reported_police", "preserved_evidence"],
                    "denied_actions": [],
                    "judge_source": "turn_rewrite",
                }
            },
        }

        state = node_case_context(state)

        self.assertEqual(state["slots"]["has_stopped_operation"], TRUE)
        self.assertEqual(state["slots"]["has_contacted_bank"], TRUE)
        self.assertEqual(state["slots"]["has_reported_police"], TRUE)
        self.assertEqual(state["slots"]["has_preserved_evidence"], TRUE)

    def test_case_memory_separates_historical_exposure_and_current_state(self):
        manager = MemoryManager()
        state = {
            "session_id": "s_test",
            "case_id": "case_test",
            "original_query": "我已经转了3000，但现在不转了，已经停止操作。",
            "slots": {
                "has_paid": TRUE,
                "loss_amount": "3000",
                "has_stopped_operation": TRUE,
                "has_shared_code": FALSE,
                "has_screen_share": FALSE,
                "has_downloaded_app": FALSE,
                "has_provided_identity_or_bank": FALSE,
            },
            "slot_evidence": {
                "has_paid": "我已经转了3000",
                "has_stopped_operation": "现在不转了",
            },
            "risk": {"risk_class": "high_loss", "reason": "用户历史上已经发生转账。"},
            "risk_level": "高风险：已经被骗/已经暴露",
            "risk_score": 90,
            "resolution": {"risk_resolved": False, "missing_resolution_actions": ["报警", "保存证据"]},
        }

        case_state = manager.build_case_memory(state, {"case_id": "case_test", "session_id": "s_test"})

        self.assertTrue(case_state["exposure_memory"]["has_ever_paid"])
        self.assertEqual(case_state["exposure_memory"]["loss_amount"], "3000")
        self.assertFalse(case_state["current_unsafe_memory"]["is_currently_transferring"])
        self.assertEqual(case_state["slot_memory"]["has_paid"]["status"], "completed_by_user")

    def test_route_context_locks_unresolved_risk_case(self):
        manager = MemoryManager()
        state = {
            "session_id": "s_test",
            "case_id": "case_test",
            "intent": "risk_check",
            "intent_confidence": 0.8,
            "route_name": "loss_response",
            "case_status": "unresolved",
            "slots": {"has_paid": TRUE},
            "risk": {"risk_class": "high_loss"},
            "resolution": {"risk_resolved": False},
        }

        case_state = manager.build_case_memory(state, {"case_id": "case_test", "session_id": "s_test"})

        self.assertTrue(case_state["route_context"]["intent_lock"]["locked"])
        self.assertEqual(case_state["route_context"]["active_workflow"], "risk_case_flow")

    def test_neutral_lightweight_turn_preserves_risk_pending_question(self):
        manager = MemoryManager()
        pending = {
            "type": "slot_check",
            "target_slots": ["has_paid", "has_shared_code"],
            "question_text": "你有没有转账或给验证码？",
        }
        old_route_decision = {
            "primary_intent": "risk_help",
            "workflow_mode": "risk_case_flow",
        }
        existing_case = {
            "case_id": "case_test",
            "session_id": "s_test",
            "case_status": "active",
            "route_context": {
                "active_workflow": "risk_case_flow",
                "workflow_status": "active",
                "pending_question": pending,
                "last_route_decision": old_route_decision,
            },
        }
        state = {
            "session_id": "s_test",
            "case_id": "case_test",
            "intent": "smalltalk",
            "intent_confidence": 0.8,
            "route_name": "fallback",
            "case_status": "active",
            "route_decision": {
                "primary_intent": "smalltalk",
                "workflow_mode": "fallback",
            },
            "memory_context": {
                "pending_question": pending,
                "session_state": {},
            },
            "preserve_pending_question": True,
        }

        case_state = manager.build_case_memory(state, existing_case)
        session_state = manager.build_session_memory(state, case_state)

        self.assertEqual(case_state["route_context"]["pending_question"], pending)
        self.assertEqual(case_state["route_context"]["active_workflow"], "risk_case_flow")
        self.assertEqual(case_state["route_context"]["last_route_decision"], old_route_decision)
        self.assertEqual(session_state["pending_question"], pending)

    def test_resolved_case_clears_pending_and_unlocks_route_context(self):
        manager = MemoryManager()
        pending = {
            "type": "resolution_check",
            "target_slots": ["reported_police"],
            "question_text": "你报警了吗？",
        }
        existing_case = {
            "case_id": "case_test",
            "session_id": "s_test",
            "case_status": "unresolved",
            "route_context": {
                "active_workflow": "risk_case_flow",
                "pending_question": pending,
                "last_route_decision": {
                    "primary_intent": "emergency_help",
                    "workflow_mode": "risk_case_flow",
                },
            },
        }
        state = {
            "session_id": "s_test",
            "case_id": "case_test",
            "intent": "risk_help",
            "route_name": "loss_response",
            "case_status": "stop_loss_done",
            "route_decision": {
                "primary_intent": "emergency_help",
                "workflow_mode": "risk_case_flow",
            },
            "resolution": {
                "risk_resolved": True,
                "ready_for_education": True,
            },
            "pending_resolution_actions": ["reported_police"],
            "memory_context": {
                "pending_question": pending,
                "session_state": {},
            },
        }

        case_state = manager.build_case_memory(state, existing_case)
        session_state = manager.build_session_memory(state, case_state)

        self.assertEqual(case_state["route_context"]["active_workflow"], "idle")
        self.assertEqual(case_state["route_context"]["pending_question"], {})
        self.assertFalse(case_state["route_context"]["intent_lock"]["locked"])
        self.assertEqual(session_state["active_workflow"], "idle")
        self.assertEqual(session_state["pending_question"], {})

    def test_risk_decay_mitigates_when_user_confirms_no_transfer_before_closure(self):
        case_state = apply_decay_to_case_snapshot(
            {
                "case_id": "case_test",
                "session_id": "s_test",
                "case_status": "active",
                "risk_score": 85,
                "risk_level": "高风险",
                "risk_memory": {
                    "display_risk_label": "高风险",
                    "risk_score": 85,
                    "risk_class": "medium_low_pre_loss",
                },
                "route_context": {
                    "active_workflow": "risk_case_flow",
                    "pending_question": {
                        "type": "slot_check",
                        "target_slots": ["has_paid", "has_shared_code"],
                    },
                },
            },
            "我没有转账，已经拉黑对方了。",
        )

        self.assertEqual(case_state["risk_decay"]["status"], "mitigated")
        self.assertEqual(case_state["case_status"], "mitigated")
        self.assertLess(case_state["risk_score"], 85)
        self.assertFalse(case_state["risk_resolved"])

    def test_risk_decay_resolves_when_closure_standard_is_met(self):
        case_state = apply_decay_to_case_snapshot(
            {
                "case_id": "case_test",
                "session_id": "s_test",
                "case_status": "active",
                "risk_score": 85,
                "risk_level": "高风险",
                "risk_memory": {
                    "display_risk_label": "高风险",
                    "risk_score": 85,
                    "risk_class": "medium_low_pre_loss",
                },
                "resolution_memory": {
                    "closure_standard": {"can_close": True},
                },
                "route_context": {
                    "active_workflow": "risk_case_flow",
                    "pending_question": {
                        "type": "slot_check",
                        "target_slots": ["has_paid", "has_shared_code"],
                    },
                },
            },
            "我没有转账，已经拉黑对方了。",
        )

        self.assertEqual(case_state["risk_decay"]["status"], "resolved")
        self.assertEqual(case_state["case_status"], "prevented")
        self.assertLessEqual(case_state["risk_score"], 20)
        self.assertTrue(case_state["risk_resolved"])
        self.assertEqual(case_state["route_context"]["active_workflow"], "idle")
        self.assertEqual(case_state["route_context"]["pending_question"], {})

    def test_risk_decay_moves_inactive_case_to_observation_after_timeout(self):
        old_ts = (datetime.now() - timedelta(minutes=20)).isoformat(timespec="seconds")
        case_state = apply_decay_to_case_snapshot(
            {
                "case_id": "case_test",
                "session_id": "s_test",
                "case_status": "active",
                "last_updated_at": old_ts,
                "risk_score": 82,
                "risk_level": "高风险",
                "risk_memory": {
                    "display_risk_label": "高风险",
                    "risk_score": 82,
                    "risk_class": "medium_low_pre_loss",
                    "updated_at": old_ts,
                },
                "route_context": {
                    "active_workflow": "risk_case_flow",
                    "pending_question": {
                        "type": "slot_check",
                        "target_slots": ["has_paid"],
                    },
                },
            },
            "这个靠谱吗？",
        )

        self.assertEqual(case_state["risk_decay"]["status"], "observation")
        self.assertEqual(case_state["case_status"], "observation")
        self.assertLessEqual(case_state["risk_score"], 45)
        self.assertEqual(case_state["route_context"]["active_workflow"], "idle")
        self.assertEqual(case_state["route_context"]["pending_question"], {})

    def test_risk_decay_reactivates_when_new_danger_signal_appears(self):
        case_state = apply_decay_to_case_snapshot(
            {
                "case_id": "case_test",
                "session_id": "s_test",
                "case_status": "observation",
                "risk_decay": {
                    "status": "observation",
                    "current_risk_score": 35,
                    "risk_level": "中风险",
                },
                "risk_score": 35,
                "risk_level": "中风险",
                "risk_memory": {
                    "display_risk_label": "中风险",
                    "risk_score": 35,
                    "risk_class": "medium_low_pre_loss",
                },
                "route_context": {
                    "active_workflow": "idle",
                    "pending_question": {},
                },
            },
            "对方又让我转账3000。",
        )

        self.assertEqual(case_state["risk_decay"]["status"], "reactivated")
        self.assertEqual(case_state["case_status"], "active")
        self.assertGreaterEqual(case_state["risk_score"], 35)
        self.assertEqual(case_state["route_context"]["active_workflow"], "risk_case_flow")

    def test_fact_clarification_all_denied_does_not_keep_exposure_pending(self):
        manager = MemoryManager()
        state = {
            "session_id": "s_test",
            "case_id": "case_test",
            "intent": "risk_fact_clarification",
            "route_name": "risk_fact_clarification",
            "case_status": "non_risk_task",
            "workflow_action": "",
            "missing_info": [],
            "slots": {
                "has_paid": FALSE,
                "has_shared_code": FALSE,
                "has_screen_share": FALSE,
                "has_downloaded_app": FALSE,
                "has_clicked_link": FALSE,
                "has_provided_identity_or_bank": FALSE,
            },
            "slot_evidence": {
                "has_paid": "都没有",
                "has_shared_code": "都没有",
                "has_screen_share": "都没有",
                "has_downloaded_app": "都没有",
                "has_clicked_link": "都没有",
                "has_provided_identity_or_bank": "都没有",
            },
            "route_decision": {
                "primary_intent": "risk_fact_clarification",
                "workflow_mode": "risk_fact_clarification",
            },
            "memory_context": {
                "pending_question": {
                    "type": "slot_check",
                    "target_slots": [
                        "has_paid",
                        "has_shared_code",
                        "has_screen_share",
                        "has_downloaded_app",
                        "has_clicked_link",
                        "has_provided_identity_or_bank",
                    ],
                },
                "session_state": {},
            },
        }

        case_state = manager.build_case_memory(state, {"case_id": "case_test", "session_id": "s_test"})
        session_state = manager.build_session_memory(state, case_state)

        self.assertEqual(case_state["route_context"]["pending_question"], {})
        self.assertEqual(session_state["pending_question"], {})
        self.assertFalse(case_state["exposure_memory"]["has_ever_paid"])
        self.assertFalse(case_state["exposure_memory"]["has_ever_shared_code"])


if __name__ == "__main__":
    unittest.main()
