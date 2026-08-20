import unittest
from unittest.mock import patch

from app.query_process.agent.nodes.compact_workflow_core import FALSE, TRUE, node_case_context, _rule_resolution_status
from app.query_process.services.emergency_exposure_mapper import map_exposures
from app.query_process.services.emergency_playbook_selector import select_emergency_playbooks
from app.query_process.services.emergency_state_machine import build_emergency_flow
from app.query_process.services.knowledge_repository import KnowledgeRepository, clear_knowledge_cache
from app.query_process.services.semantic_state_rewriter import rewrite_semantic_state


class EmergencyClosureModulesTest(unittest.TestCase):
    def setUp(self):
        clear_knowledge_cache()
        self.mongo_patch = patch(
            "app.query_process.services.knowledge_repository.get_business_mongo_tool",
            side_effect=RuntimeError("mongo offline for test"),
        )
        self.mongo_patch.start()
        self.repo = KnowledgeRepository()

    def tearDown(self):
        self.mongo_patch.stop()
        clear_knowledge_cache()

    def test_requested_code_is_suspected_not_confirmed_exposure(self):
        semantic = rewrite_semantic_state(
            current_text="对方让我给验证码",
            current_slots={},
            merged_slots={},
            route_decision={
                "safety_signals": {
                    "risky_requested_actions": [
                        {"goal": "stop_code_leak", "action": "提供验证码", "evidence": "让我给验证码"}
                    ]
                }
            },
        )

        exposures = map_exposures(semantic["slot_facts"], repository=self.repo)

        self.assertNotIn("code_exposed", exposures["exposure_ids"])
        self.assertIn("code_exposed", exposures["suspected_exposure_ids"])

    def test_current_denial_overrides_previous_paid_fact(self):
        semantic = rewrite_semantic_state(
            current_text="我没有转账",
            current_slots={"has_paid": FALSE},
            current_slot_evidence={"has_paid": "没有转账"},
            merged_slots={"has_paid": TRUE},
            previous_slot_facts={
                "has_paid": {
                    "value": TRUE,
                    "status": "confirmed",
                    "source": "case_memory",
                    "evidence_text": "我已经转账了",
                }
            },
        )

        self.assertEqual(semantic["slot_facts"]["has_paid"]["value"], FALSE)
        self.assertEqual(semantic["slot_facts"]["has_paid"]["status"], "denied")
        self.assertEqual(semantic["effective_slots"]["has_paid"], FALSE)

    def test_screen_share_selects_device_isolation_playbook_and_flow(self):
        semantic = rewrite_semantic_state(
            current_text="我现在正在和对方屏幕共享",
            current_slots={"has_screen_share": TRUE},
            current_slot_evidence={"has_screen_share": "正在和对方屏幕共享"},
            merged_slots={"has_screen_share": TRUE},
        )
        exposures = map_exposures(semantic["slot_facts"], semantic["effective_slots"], repository=self.repo)
        plan = select_emergency_playbooks(
            exposures["exposure_ids"],
            intervention_goal="stop_screen_share",
            repository=self.repo,
        )
        flow = build_emergency_flow(
            exposures,
            plan,
            slots=semantic["effective_slots"],
            risk_class="high_loss",
            intervention_goal="stop_screen_share",
            repository=self.repo,
        )

        self.assertIn("screen_share_active", exposures["exposure_ids"])
        self.assertIn("PB_SCREEN_SHARE_DEVICE_ISOLATION", plan["selected_playbook_ids"])
        self.assertIn("isolated_device", plan["resolution_action_ids"])
        self.assertFalse(flow["can_claim_resolved"])
        self.assertIn("isolated_device", flow["missing_action_ids"])

    def test_stopped_screen_share_alone_is_not_resolved(self):
        state = {
            "original_query": "我停止了屏幕共享",
            "risk": {"risk_class": "high_loss"},
            "slots": {"has_screen_share": TRUE, "has_stopped_operation": TRUE},
            "slot_facts": {
                "has_screen_share": {
                    "value": TRUE,
                    "status": "confirmed",
                    "source": "case_memory",
                    "evidence_text": "我正在屏幕共享",
                }
            },
        }
        exposures = map_exposures(state["slot_facts"], state["slots"], repository=self.repo)
        plan = select_emergency_playbooks(exposures["exposure_ids"], intervention_goal="stop_screen_share", repository=self.repo)
        state["exposures"] = exposures
        state["emergency_flow"] = build_emergency_flow(
            exposures,
            plan,
            slots=state["slots"],
            risk_class="high_loss",
            intervention_goal="stop_screen_share",
            repository=self.repo,
        )

        resolution = _rule_resolution_status(state)

        self.assertFalse(resolution["risk_resolved"])
        self.assertIn("isolated_device", resolution["missing_action_ids"])
        self.assertIn("checked_device_permissions", resolution["missing_action_ids"])

    def test_node_case_context_exposes_slot_facts(self):
        state = {
            "session_id": "",
            "history": [],
            "history_text": "",
            "original_query": "我现在正在和对方屏幕共享",
            "emergency_mode": True,
        }

        state = node_case_context(state)

        self.assertEqual(state["slot_facts"]["has_screen_share"]["status"], "confirmed")
        self.assertTrue(state["candidate_signals"])


if __name__ == "__main__":
    unittest.main()
