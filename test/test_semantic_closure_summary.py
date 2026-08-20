import unittest
from unittest.mock import patch

from app.query_process.services.semantic_risk_agent import (
    _compact_case_memory_for_prompt,
    _merge_analysis_with_memory,
    build_result_summary,
    generate_realtime_answer,
    persist_semantic_turn,
)


class _Message:
    def __init__(self, content):
        self.content = content


class _FakeLLM:
    def __init__(self, answer):
        self.answer = answer
        self.prompts = []

    def invoke(self, messages):
        self.prompts.append(messages[-1].content)
        return _Message(self.answer)


class SemanticClosureSummaryTest(unittest.TestCase):
    def _campus_loan_case(self):
        state = {
            "original_query": "好的，我已经按照你说的去做了",
            "is_stream": False,
            "session_id": "",
            "history": [
                {"role": "user", "text": "我在校园贷款App借了5000，实际到手3500，被扣1500服务费和砍头息。"},
                {"role": "user", "text": "身份证和银行卡也给了，是通过对方链接下载的App。"},
                {"role": "assistant", "text": "停止操作，保存证据，联系银行并报警。"},
            ],
        }
        analysis = {
            "scene": {"is_risk_scene": True, "scene_type": "post_loss_help"},
            "facts": {
                "case_summary": "用户通过对方链接下载校园贷款App，借款5000元实际到账3500元，被扣1500元服务费/砍头息，并提供过身份证和银行卡",
                "contact_channel": "对方提供的链接",
                "platform_or_app": "校园贷款App",
                "requested_actions": ["下载陌生贷款App", "提交身份证和银行卡", "支付服务费/砍头息"],
                "user_actions": {
                    "has_paid": "true",
                    "paid_amount": "借5000元实际到账3500元，被扣1500元服务费/砍头息",
                    "has_downloaded_app": "true",
                    "has_clicked_link": "true",
                    "has_provided_identity_or_bank": "true",
                    "has_stopped_operation": "true",
                    "has_preserved_evidence": "true",
                    "has_reported_police": "true",
                    "has_contacted_bank_or_payment_platform": "true",
                },
                "loss": {
                    "loss_confirmed": "true",
                    "loss_type": "money",
                    "amount_or_value": "1500元服务费/砍头息",
                },
                "evidence": ["校园贷款App", "借5000实际到账3500", "砍头息1500", "身份证和银行卡"],
            },
            "fraud": {
                "primary_type": "网络贷款诈骗",
                "candidate_types": ["网络贷款诈骗"],
                "matched_feature_names": ["贷款前收费", "校园贷包装", "诱导下载陌生APP", "索要银行卡或身份信息"],
            },
            "action_progress": {
                "turn_act": "completion_confirmation",
                "completion_scope": "all_previous_advice",
                "completed_actions": [
                    "no_more_transfer",
                    "preserved_evidence",
                    "reported_police",
                    "contacted_bank_or_payment_platform",
                ],
                "confidence": 0.9,
            },
            "case_lifecycle": {
                "case_status": "stop_loss_done",
                "post_resolution_answer_mode": "closure_with_education",
            },
            "resolution": {
                "risk_resolved": True,
                "ready_for_education": True,
                "post_resolution_education_delivered": True,
                "post_resolution_answer_mode": "closure_with_education",
                "completed_actions": [
                    "no_more_transfer",
                    "preserved_evidence",
                    "reported_police",
                    "contacted_bank_or_payment_platform",
                ],
            },
            "ask_goal": "",
            "missing_facts": [],
        }
        decision = {
            "is_risk_scene": True,
            "fraud_type": "网络贷款诈骗",
            "risk_features": ["贷款前收费", "校园贷包装", "诱导下载陌生APP", "索要银行卡或身份信息"],
            "has_loss_or_exposure": True,
            "risk_resolved": True,
            "ready_for_education": True,
            "case_status": "stop_loss_done",
            "post_resolution_answer_mode": "closure_with_education",
            "post_resolution_education_delivered": True,
            "risk_score": 92,
            "display_risk_level": "高风险",
        }
        knowledge = {
            "prevention_advice": [
                {"advice": "不要从陌生链接或二维码下载贷款App。"},
                {"advice": "正规贷款不会要求先交服务费、解冻费或刷流水。"},
            ]
        }
        return state, analysis, decision, knowledge

    def _generate_with_fake_llm(self, state, analysis, decision, knowledge, answer):
        fake = _FakeLLM(answer)
        with patch("app.query_process.services.semantic_risk_agent.get_llm_client", return_value=fake):
            actual = generate_realtime_answer(state, analysis, decision, knowledge)
        return actual, fake.prompts[-1]

    def test_closed_campus_loan_case_outputs_personalized_summary_and_prevention(self):
        state, analysis, decision, knowledge = self._campus_loan_case()
        llm_answer = (
            "那我帮你把这件事简单复盘一下。\n\n"
            "这次真正危险的地方，是对方把贷款包装成校园贷款App，还让你从链接下载，"
            "借5000元却只到账3500元，提前扣走1500元所谓服务费，这就是网络贷款诈骗里很典型的砍头息套路。"
            "你后来停止继续操作、保存证据、联系银行并报警，这几步方向是对的，尤其是身份证和银行卡已经给过对方，"
            "后续要重点防信息被继续滥用。\n\n"
            "以后碰到类似贷款，先看三件事：是不是让你先交钱、是不是让你从陌生链接下App、是不是索要身份证银行卡验证码。"
            "这三样只要出现一个，就先停下来，去银行、学校老师或派出所核实。"
        )

        answer, prompt = self._generate_with_fake_llm(state, analysis, decision, knowledge, llm_answer)

        self.assertIn('"mode": "expert_closure_summary"', prompt)
        self.assertIn("网络贷款诈骗", answer)
        self.assertIn("校园贷款App", answer)
        self.assertIn("砍头息", answer)
        self.assertIn("身份证", answer)
        self.assertIn("银行卡", answer)
        self.assertIn("陌生链接", answer)
        self.assertNotIn("本次诈骗总结", answer)
        self.assertNotIn("个性化总结", answer)
        self.assertNotIn("相关防范建议", answer)
        self.assertNotIn("这次先稳住了", answer)
        self.assertNotIn("我是您的反诈骗小卫士", answer)
        self.assertNotIn("请问您想咨询什么", answer)

        summary = build_result_summary(state, analysis, decision, knowledge, answer)
        self.assertTrue(summary["closure_summary_delivered"])
        self.assertEqual(summary["closure_summary_type"], "personalized_scam_summary")

    def test_closed_case_after_summary_still_uses_llm_without_summary_mode(self):
        state, analysis, decision, knowledge = self._campus_loan_case()
        analysis["case_lifecycle"]["post_resolution_answer_mode"] = "brief_ack_after_education"
        analysis["resolution"]["post_resolution_answer_mode"] = "brief_ack_after_education"
        decision["post_resolution_answer_mode"] = "brief_ack_after_education"
        llm_answer = "嗯，知道这个判断就好。后面如果对方再换话术催你操作，先停下来核实。"

        answer, prompt = self._generate_with_fake_llm(state, analysis, decision, knowledge, llm_answer)

        self.assertIn('"mode": "closed_followup_without_summary"', prompt)
        self.assertNotIn("本次诈骗总结", answer)
        self.assertNotIn("我是您的反诈骗小卫士", answer)

    def test_closed_case_without_semantic_completion_does_not_emit_summary(self):
        state, analysis, decision, knowledge = self._campus_loan_case()
        state["original_query"] = "我明白了"
        analysis["action_progress"] = {
            "turn_act": "followup_answer",
            "completion_scope": "none",
            "completed_actions": [],
            "confidence": 0.9,
        }
        analysis["facts"]["user_actions"].update(
            {
                "has_stopped_operation": "unknown",
                "has_preserved_evidence": "unknown",
                "has_reported_police": "unknown",
                "has_contacted_bank_or_payment_platform": "unknown",
            }
        )
        llm_answer = "明白就好。这个案子的处置结论不用再重复，你只要记得别再按对方要求继续操作。"

        answer, prompt = self._generate_with_fake_llm(state, analysis, decision, knowledge, llm_answer)

        self.assertIn('"mode": "closed_followup_without_summary"', prompt)
        self.assertNotIn("本次诈骗总结", answer)
        self.assertNotIn("个性化总结", answer)
        self.assertNotIn("相关防范建议", answer)

    def test_closure_summary_persistence_clears_risk_working_memory(self):
        state, analysis, decision, knowledge = self._campus_loan_case()
        state["session_id"] = "closure_reset_session"
        state["case_id"] = "case_old"
        state["case_state"] = {
            "case_id": "case_old",
            "session_id": "closure_reset_session",
            "fraud_type": "网络贷款诈骗",
            "fraud_stage": "事后处理",
            "risk_level": "高风险",
            "risk_score": 92,
            "risk_features": ["贷款前收费", "诱导下载陌生APP"],
            "slots": {"has_paid": "true", "has_downloaded_app": "true"},
            "semantic_risk_analysis": {"fraud": {"primary_type": "网络贷款诈骗"}},
            "risk_memory": {"fraud_type": "网络贷款诈骗"},
            "memory_summary": "用户遭遇网络贷款诈骗并已处置。",
            "route_context": {"active_workflow": "risk_case_flow", "pending_question": {"ask_goal": "确认是否报警"}},
        }
        answer = "那我帮你把这件事简单复盘一下。以后不要从陌生链接下载贷款App，也不要先交服务费。"
        summary = build_result_summary(state, analysis, decision, knowledge, answer)

        with (
            patch("app.query_process.services.semantic_risk_agent.save_case_state") as save_case_state,
            patch("app.query_process.services.semantic_risk_agent.save_risk_chat_message") as save_message,
            patch("app.query_process.services.semantic_risk_agent.set_task_result") as set_task,
        ):
            persist_semantic_turn(state, analysis, decision, knowledge, answer, summary)

        saved_case = save_case_state.call_args.args[1]
        self.assertTrue(saved_case["case_memory_cleared_after_closure"])
        self.assertTrue(saved_case["closure_summary_delivered"])
        self.assertTrue(saved_case["risk_resolved"])
        self.assertEqual(saved_case["case_status"], "closed")
        self.assertEqual(saved_case["fraud_type"], "")
        self.assertEqual(saved_case["fraud_stage"], "")
        self.assertEqual(saved_case["risk_level"], "")
        self.assertEqual(saved_case["risk_score"], 0)
        self.assertEqual(saved_case["risk_features"], [])
        self.assertEqual(saved_case["slots"], {})
        self.assertEqual(saved_case["semantic_risk_analysis"], {})
        self.assertEqual(saved_case["risk_memory"], {})
        self.assertEqual(saved_case["memory_summary"], "")
        self.assertEqual(saved_case["route_context"]["active_workflow"], "idle")
        self.assertEqual(saved_case["route_context"]["pending_question"], {})
        self.assertEqual(state["fraud_type"], "")
        self.assertEqual(state["risk_features"], [])
        self.assertEqual(state["slots"], {})
        self.assertEqual(summary["memory_context"]["memory_summary"], "")
        self.assertTrue(summary["memory_context"]["post_closure_memory_reset"])
        self.assertEqual(save_message.call_count, 2)
        self.assertTrue(set_task.called)

    def test_case_memory_after_delivered_summary_hides_old_scene_fields(self):
        memory = {
            "case_state": {
                "case_status": "closed",
                "risk_resolved": True,
                "closure_summary_delivered": True,
                "fraud_type": "虚假投资理财诈骗",
                "fraud_stage": "提现受阻",
                "risk_level": "高风险",
                "risk_features": ["投资老师带单", "无法提现"],
                "slots": {"has_paid": "true"},
                "semantic_risk_analysis": {"fraud": {"primary_type": "虚假投资理财诈骗"}},
            }
        }

        compact = _compact_case_memory_for_prompt(memory)

        self.assertTrue(compact["previous_case_is_closed"])
        self.assertTrue(compact["case_followup_disabled"])
        self.assertNotIn("fraud_type", compact)
        self.assertNotIn("risk_features", compact)
        self.assertNotIn("slots", compact)
        self.assertIn("旧案彻底结束", compact["memory_boundary"])

    def test_delivered_summary_resets_non_new_followup_semantics(self):
        analysis = {
            "scene": {"is_risk_scene": True, "scene_type": "risk_followup", "user_intent": "followup_answer"},
            "facts": {
                "case_summary": "用户表示理解",
                "requested_actions": [],
                "current_dangerous_actions": [],
                "user_actions": {},
                "loss": {"loss_confirmed": "unknown", "loss_type": "none", "amount_or_value": ""},
                "evidence": [],
            },
            "fraud": {"primary_type": "虚假投资理财诈骗", "candidate_types": ["虚假投资理财诈骗"], "matched_feature_names": ["无法提现"]},
            "action_progress": {
                "turn_act": "followup_answer",
                "completion_scope": "none",
                "completed_actions": [],
                "new_risk_signal": False,
                "confidence": 0.9,
            },
            "missing_facts": [{"field": "risk_stage", "why": "事实不足", "priority": 1}],
            "ask_goal": "继续确认旧案",
            "urgency": "normal",
        }
        state = {
            "original_query": "我明白了",
            "memory_context": {
                "case_state": {
                    "case_status": "closed",
                    "risk_resolved": True,
                    "closure_summary_delivered": True,
                    "fraud_type": "虚假投资理财诈骗",
                    "risk_features": ["无法提现"],
                    "slots": {"has_paid": "true"},
                }
            },
            "history": [
                {"role": "user", "text": "我在投资App提现失败"},
                {"role": "assistant", "text": "已经给过本案总结和防范建议。"},
            ],
        }

        merged = _merge_analysis_with_memory(analysis, state)

        self.assertFalse(merged["scene"]["is_risk_scene"])
        self.assertEqual(merged["scene"]["scene_type"], "post_closure_followup")
        self.assertEqual(merged["fraud"]["primary_type"], "")
        self.assertEqual(merged["fraud"]["matched_feature_names"], [])
        self.assertEqual(merged["missing_facts"], [])
        self.assertEqual(merged["ask_goal"], "")
        self.assertTrue(merged["post_closure_boundary"]["applied"])

    def test_delivered_summary_does_not_block_new_risk_semantics(self):
        analysis = {
            "scene": {"is_risk_scene": True, "scene_type": "personal_risk_scene", "user_intent": "judge_risk"},
            "facts": {
                "case_summary": "用户新遇到校园贷款App砍头息",
                "platform_or_app": "校园贷款App",
                "requested_actions": ["支付服务费"],
                "current_dangerous_actions": [],
                "user_actions": {"has_paid": "true", "has_downloaded_app": "true"},
                "loss": {"loss_confirmed": "true", "loss_type": "money", "amount_or_value": "1500元"},
                "evidence": ["校园贷款App", "砍头息"],
            },
            "fraud": {"primary_type": "网络贷款诈骗", "candidate_types": ["网络贷款诈骗"], "matched_feature_names": ["贷款前收费"]},
            "action_progress": {
                "turn_act": "risk_report",
                "completion_scope": "none",
                "completed_actions": [],
                "new_risk_signal": True,
                "confidence": 0.92,
            },
            "missing_facts": [],
            "ask_goal": "",
            "urgency": "urgent",
        }
        state = {
            "original_query": "我在校园贷款App借5000只到3500，还扣了服务费",
            "memory_context": {
                "case_state": {
                    "case_status": "closed",
                    "risk_resolved": True,
                    "closure_summary_delivered": True,
                    "fraud_type": "虚假投资理财诈骗",
                    "risk_features": ["无法提现"],
                    "slots": {"has_paid": "true"},
                }
            },
            "history": [{"role": "user", "text": "我之前投资App不能提现"}],
        }

        merged = _merge_analysis_with_memory(analysis, state)

        self.assertTrue(merged["scene"]["is_risk_scene"])
        self.assertEqual(merged["fraud"]["primary_type"], "网络贷款诈骗")
        self.assertEqual(merged["fraud"]["matched_feature_names"], ["贷款前收费"])
        self.assertEqual(merged["facts"]["platform_or_app"], "校园贷款App")
        self.assertNotIn("虚假投资理财诈骗", merged["fraud"].get("candidate_types", []))


if __name__ == "__main__":
    unittest.main()
