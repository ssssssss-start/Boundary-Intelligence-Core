import unittest
from pathlib import Path

from app.query_process.agent.nodes.common import INTENTS
from app.query_process.agent.nodes.compact_workflow_core import (
    FALSE,
    TRUE,
    _merge_resolution_status,
    _required_resolution_actions,
    _rule_resolution_status,
    node_case_context,
    node_scam_understanding,
)


class CompactChatWorkflowTest(unittest.TestCase):
    def test_main_graph_uses_six_compact_nodes(self):
        source = Path("app/query_process/agent/main_graph.py").read_text(encoding="utf-8")
        for node_name in [
            "NODE_CASE_CONTEXT",
            "NODE_SLOT_GATE",
            "NODE_SCAM_UNDERSTANDING",
            "NODE_BINARY_RISK_DECISION",
            "NODE_INTERVENTION",
            "NODE_RESOLUTION_OR_EDUCATION",
        ]:
            self.assertIn(node_name, source)

        for removed_node in [
            "node_case_context_analyze",
            "node_intent_recognize",
            "node_risk_feature_extract",
            "node_safety_status_assess",
            "node_answer_prompt_build",
        ]:
            self.assertNotIn(removed_node, source)

    def test_old_split_node_files_are_removed(self):
        removed_files = [
            "node_answer_prompt_build.py",
            "node_case_closure_decision.py",
            "node_case_context_analyze.py",
            "node_case_state_load.py",
            "node_case_state_save.py",
            "node_case_state_update.py",
            "node_intent_recognize.py",
            "node_intervention_decision.py",
            "node_query_rewrite.py",
            "node_risk_feature_extract.py",
            "node_risk_score.py",
            "node_route_decision.py",
            "node_safety_status_assess.py",
        ]
        nodes_dir = Path("app/query_process/agent/nodes")
        for file_name in removed_files:
            self.assertFalse((nodes_dir / file_name).exists(), file_name)

    def test_intent_enum_covers_public_modules(self):
        for intent in [
            "knowledge_consult",
            "risk_check",
            "url_check",
            "report_request",
            "loss_response",
            "game_request",
            "case_learning",
            "law_consult",
            "unknown",
        ]:
            self.assertIn(intent, INTENTS)

    def test_fake_police_denial_does_not_become_screen_share_case(self):
        state = {
            "session_id": "",
            "history": [
                {"role": "user", "text": "自称公安说我银行卡涉案，让我把钱转到安全账户。"},
            ],
            "history_text": "",
            "original_query": "都没有，我没有转账，没有给验证码，也没有共享屏幕。",
        }

        state = node_case_context(state)
        state = node_scam_understanding(state)

        self.assertEqual(state["fraud_type"], "冒充公检法诈骗")
        self.assertEqual(state["slots"]["has_screen_share"], FALSE)
        self.assertEqual(state["slots"]["has_shared_code"], FALSE)
        self.assertEqual(state["slots"]["has_paid"], FALSE)
        self.assertIn("要求垫付资金", state["risk_features"])
        self.assertNotIn("屏幕共享", state["risk_features"])
        self.assertNotIn("索要银行卡或身份信息", state["risk_features"])

    def test_uncertain_loss_claim_history_does_not_override_later_denial(self):
        state = {
            "session_id": "",
            "history": [
                {"role": "user", "text": "我被骗了"},
                {"role": "user", "text": "都没有"},
            ],
            "history_text": "",
            "original_query": "客服让我下载会议软件",
            "memory_context": {
                "case_state": {
                    "slots": {
                        "has_paid": FALSE,
                        "has_shared_code": FALSE,
                        "has_screen_share": FALSE,
                        "has_downloaded_app": FALSE,
                        "has_clicked_link": FALSE,
                        "has_provided_identity_or_bank": FALSE,
                    }
                }
            },
        }

        state = node_case_context(state)

        self.assertEqual(state["slots"]["has_paid"], FALSE)
        self.assertNotEqual(state["slots"]["has_downloaded_app"], TRUE)
        self.assertIn(state["slots"]["current_requested_action"], {"共享屏幕/远程控制", "下载陌生App"})

    def test_high_loss_can_be_marked_resolved_after_required_actions(self):
        state = {
            "original_query": "我保存了聊天记录和转账凭证，已经拨打110完成报警，也已经停止操作不再联系对方，暂不举报。",
            "risk": {"risk_class": "high_loss"},
            "intervention": {
                "actions": [
                    "立刻联系银行、微信/支付宝等支付平台，说明疑似诈骗并申请止付、冻结或交易拦截",
                    "报警或拨打96110咨询，按时间线说明接触渠道、金额、账户和对方话术",
                    "如需处置可疑账号、链接、电话或聊天内容，可以继续提交举报记录；暂不举报也要先保存证据",
                ],
            },
            "slots": {
                "has_paid": TRUE,
                "has_stopped_operation": TRUE,
                "has_contacted_bank": TRUE,
                "has_reported_police": TRUE,
                "has_preserved_evidence": TRUE,
                "has_report_decision_made": TRUE,
            },
        }
        rule_status = _rule_resolution_status(state)
        llm_status = {
            "available": True,
            "risk_resolved": True,
            "confidence": 0.9,
            "completed_actions": _required_resolution_actions("high_loss", state["slots"]),
            "missing_actions": [],
            "unsafe_signals": [],
            "reason": "用户明确完成止损动作。",
        }

        resolution = _merge_resolution_status(state, rule_status, llm_status)

        self.assertTrue(resolution["risk_resolved"])
        self.assertEqual(resolution["case_status"], "stop_loss_done")
        self.assertEqual(resolution["missing_action_ids"], [])

    def test_current_unsafe_signal_blocks_resolution(self):
        state = {
            "original_query": "我被骗了5000元，已经联系银行，也报警了，证据保存了，但是我还在共享屏幕。",
            "risk": {"risk_class": "high_loss"},
            "slots": {
                "has_paid": TRUE,
                "has_screen_share": TRUE,
                "has_stopped_operation": FALSE,
                "has_contacted_bank": TRUE,
                "has_reported_police": TRUE,
                "has_preserved_evidence": TRUE,
            },
        }
        rule_status = _rule_resolution_status(state)
        llm_status = {
            "available": True,
            "risk_resolved": False,
            "confidence": 0.9,
            "completed_actions": ["contacted_bank", "reported_police", "preserved_evidence"],
            "missing_actions": ["stopped_operation"],
            "unsafe_signals": ["用户还在共享屏幕"],
            "reason": "仍在执行危险操作。",
        }

        resolution = _merge_resolution_status(state, rule_status, llm_status)

        self.assertFalse(resolution["risk_resolved"])
        self.assertEqual(resolution["case_status"], "unresolved")
        self.assertIn("stopped_operation", resolution["missing_action_ids"])


if __name__ == "__main__":
    unittest.main()
