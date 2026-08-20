import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from app.modules.emergency_dissuasion.service import (
    build_emergency_route_decision,
    build_emergency_sync_result,
    run_emergency_graph,
)
from app.query_process.agent.nodes.compact_workflow_core import FALSE, TRUE, UNKNOWN, node_case_context
from app.query_process.agent.nodes.compact_workflow_core import _rule_resolution_status
from app.query_process.services.dynamic_response_planner import (
    build_dialogue_policy,
    build_dynamic_answer_prompt,
    build_realtime_structured_answer,
    build_scenario_frame,
    enforce_dynamic_answer_contract,
    fallback_dynamic_answer,
    requires_short_contract_answer,
)
from app.query_process.services.risk_intervention_dialogue_manager import build_intervention_dialogue
from app.utils.task_utils import clear_task


class _FakeMemoryManager:
    def load_context(self, session_id, user_query, intent_hint=""):
        return {
            "case_id": "",
            "route_context": {},
            "pending_question": {},
            "turn_memory": {},
            "memory_summary": "",
            "case_state": {},
        }

    def commit_turn(self, state):
        return None


class EmergencyDissuasionWorkflowTest(unittest.TestCase):
    def _reply_blocks(self, text):
        return [block.strip() for block in str(text or "").split("\n\n") if block.strip()]

    def test_emergency_route_always_enters_risk_flow_without_lightweight_branch(self):
        decision = build_emergency_route_decision("我好像被骗了", {"route_context": {}, "pending_question": {}})

        self.assertEqual(decision["primary_intent"], "emergency_help")
        self.assertEqual(decision["workflow_mode"], "risk_case_flow")
        self.assertEqual(decision["routing_decision"]["target"], "risk_case_flow")
        self.assertFalse(decision["routing_decision"]["force_high_risk"])
        self.assertIn("next_action", decision)

    def test_emergency_route_prefills_confirmed_exposure_but_does_not_force_high_risk(self):
        decision = build_emergency_route_decision("我已经转账了5000元，现在对方还让我继续补单", {})

        self.assertEqual(decision["routing_decision"]["target"], "risk_case_flow")
        self.assertFalse(decision["routing_decision"]["force_high_risk"])
        self.assertEqual(decision["routing_decision"]["prefill_slots"].get("has_paid"), TRUE)
        self.assertTrue(decision["risk_signals"]["confirmed_exposure_signal"])

    def test_emergency_service_no_longer_uses_general_router_or_lightweight_flow(self):
        source = Path("app/modules/emergency_dissuasion/service.py").read_text(encoding="utf-8")

        self.assertNotIn("route_user_input", source)
        self.assertNotIn("run_lightweight_flow", source)

    def test_emergency_mode_forces_risk_context_even_for_learning_like_text(self):
        state = {
            "session_id": "",
            "history": [],
            "history_text": "",
            "original_query": "什么是刷单诈骗",
            "emergency_mode": True,
        }

        state = node_case_context(state)

        self.assertEqual(state["intent"], "risk_check")

    def test_missing_resolution_actions_do_not_read_as_completed_actions(self):
        state = {
            "original_query": "我已经转账了，现在怎么办？",
            "risk": {"risk_class": "high_loss"},
            "slots": {"has_paid": TRUE},
        }

        resolution = _rule_resolution_status(state)

        self.assertEqual(resolution["completed_actions"], [])
        self.assertIn("stopped_operation", resolution["missing_action_ids"])
        for label in resolution["missing_resolution_actions"]:
            self.assertFalse(label.startswith("确认已经"), label)

    def test_brushing_rebate_closure_requires_report_choice(self):
        state = {
            "original_query": "我没有转账，已经停止联系，也知道不要继续付款，暂不举报。",
            "fraud_type": "刷单返利诈骗",
            "risk_features": ["要求垫付资金", "任务返佣"],
            "risk": {"risk_class": "medium_low_pre_loss"},
            "intervention": {
                "actions": [
                    "保留聊天记录、链接、账号和对方要求，先不要删除证据",
                    "可以选择一键举报可疑账号、链接、电话或聊天内容；也可以先暂不举报但继续保留证据",
                ]
            },
            "slots": {
                "has_paid": FALSE,
                "has_stopped_operation": TRUE,
                "user_no_longer_believes_scammer": TRUE,
                "has_report_decision_made": TRUE,
            },
        }

        resolution = _rule_resolution_status(state)

        self.assertTrue(resolution["risk_resolved"])
        self.assertEqual(resolution["case_status"], "prevented")
        self.assertEqual(resolution["closure_standard"]["standard_id"], "brushing_rebate_pre_loss_closure")
        self.assertNotIn("report_decision_made", resolution["missing_action_ids"])

    def test_customer_refund_closure_requires_screen_and_sensitive_confirmation(self):
        state = {
            "original_query": "已关闭屏幕共享，没有给验证码，也没有输入银行卡密码，暂不举报。",
            "fraud_type": "冒充客服退款诈骗",
            "risk_features": ["客服", "退款", "屏幕共享"],
            "risk": {"risk_class": "medium_low_pre_loss"},
            "intervention": {
                "actions": [
                    "通过官方App、官网、官方客服电话或线下机构核实，不要使用对方给的链接和号码",
                    "可以选择一键举报可疑账号、链接、电话或聊天内容；也可以先暂不举报但继续保留证据",
                ]
            },
            "slots": {
                "has_screen_share": FALSE,
                "has_shared_code": FALSE,
                "has_provided_identity_or_bank": FALSE,
                "has_report_decision_made": TRUE,
            },
        }

        resolution = _rule_resolution_status(state)

        self.assertTrue(resolution["risk_resolved"])
        self.assertEqual(resolution["closure_standard"]["standard_id"], "fake_customer_refund_pre_loss_closure")
        self.assertNotIn("confirmed_no_code_bank_password_exposed", resolution["missing_action_ids"])

    def test_paid_case_cannot_close_without_stoploss_guidance_and_report_choice(self):
        state = {
            "original_query": "我已经不再转了，聊天记录也保存了。",
            "fraud_type": "刷单返利诈骗",
            "risk_features": ["已发生转账", "要求缴纳解冻费"],
            "risk": {"risk_class": "high_loss"},
            "slots": {
                "has_paid": TRUE,
                "has_stopped_operation": TRUE,
                "has_preserved_evidence": TRUE,
            },
        }

        resolution = _rule_resolution_status(state)

        self.assertFalse(resolution["risk_resolved"])
        self.assertEqual(resolution["closure_standard"]["standard_id"], "post_transfer_stop_loss_closure")
        self.assertIn("contacted_bank_or_payment_platform", resolution["missing_action_ids"])
        self.assertIn("reported_police", resolution["missing_action_ids"])
        self.assertIn("report_decision_made", resolution["missing_action_ids"])

    def test_paid_case_closes_after_stoploss_evidence_police_and_report_choice(self):
        state = {
            "original_query": "我不再转账了，已经联系银行止付，保存了证据，也打了96110，暂不举报。",
            "fraud_type": "刷单返利诈骗",
            "risk_features": ["已发生转账", "要求缴纳解冻费"],
            "risk": {"risk_class": "high_loss"},
            "intervention": {
                "actions": [
                    "立刻联系银行、微信/支付宝等支付平台，说明疑似诈骗并申请止付、冻结或交易拦截",
                    "报警或拨打96110咨询，按时间线说明接触渠道、金额、账户和对方话术",
                    "如需处置可疑账号、链接、电话或聊天内容，可以继续提交举报记录；暂不举报也要先保存证据",
                ]
            },
            "slots": {
                "has_paid": TRUE,
                "has_stopped_operation": TRUE,
                "has_contacted_bank": TRUE,
                "has_preserved_evidence": TRUE,
                "has_reported_police": TRUE,
                "has_report_decision_made": TRUE,
            },
        }

        resolution = _rule_resolution_status(state)

        self.assertTrue(resolution["risk_resolved"])
        self.assertEqual(resolution["case_status"], "stop_loss_done")
        self.assertTrue(resolution["closure_standard"]["can_close"])

    def test_current_turn_slots_do_not_treat_memory_exposure_as_current_fact(self):
        state = {
            "session_id": "",
            "history": [{"role": "user", "text": "我已经转账了，现在怎么办？"}],
            "history_text": "",
            "original_query": "我现在正在和对方屏幕共享",
            "emergency_mode": True,
            "memory_context": {"case_state": {"slots": {"has_paid": TRUE}}},
        }

        state = node_case_context(state)

        self.assertEqual(state["slots"]["has_paid"], TRUE)
        self.assertEqual(state["slots"]["has_screen_share"], TRUE)
        self.assertEqual(state["current_turn_slots"]["has_paid"], UNKNOWN)
        self.assertEqual(state["current_turn_slots"]["has_screen_share"], TRUE)

    def test_pending_llm_paid_update_does_not_override_requested_training_fee(self):
        state = {
            "session_id": "",
            "history": [
                {"role": "user", "text": "我看到一个新媒体运营就业班，说学完可以推荐实习，月薪8000。"},
            ],
            "history_text": "",
            "original_query": "他们说先交16800培训费，不就业全额退款。",
            "emergency_mode": True,
            "memory_context": {
                "case_state": {"slots": {}},
                "pending_question": {
                    "type": "slot_check",
                    "target_slots": ["has_paid", "has_provided_identity_or_bank"],
                    "question_text": "你是否已经报名缴费或提供了个人信息？",
                },
            },
            "route_decision": {
                "pending_answer_decision": {
                    "is_pending_answer": True,
                    "slot_updates": {"has_paid": True},
                    "completed_actions": [],
                    "denied_actions": [],
                },
                "risk_prefill": {
                    "fraud_candidates": ["求职实习招聘诈骗"],
                    "risky_requested_actions": [
                        {
                            "goal": "stop_transfer",
                            "action": "对方要求先交培训费",
                            "evidence": "他们说先交16800培训费，不就业全额退款。",
                        }
                    ],
                    "slot_updates": {},
                },
            },
        }

        state = node_case_context(state)

        self.assertEqual(state["current_turn_slots"]["has_paid"], UNKNOWN)
        self.assertEqual(state["slots"]["has_paid"], UNKNOWN)
        self.assertNotIn("has_paid", state["slot_facts"])

    def test_scenario_frame_marks_paid_as_memory_when_current_turn_only_screen_share(self):
        state = {
            "original_query": "我现在正在和对方屏幕共享",
            "history": [{"role": "user", "text": "我已经转账了，现在怎么办？"}],
            "slots": {"has_paid": TRUE, "has_screen_share": TRUE},
            "current_turn_slots": {"has_screen_share": TRUE},
            "risk": {"risk_class": "high_loss"},
        }

        frame = build_scenario_frame(state)

        self.assertIn("已经转账/付款", frame["completed_actions"])
        self.assertIn("已经共享屏幕/远程控制", frame["completed_actions"])
        self.assertNotIn("已经转账/付款", frame["current_turn_completed_actions"])
        self.assertIn("已经共享屏幕/远程控制", frame["current_turn_completed_actions"])
        self.assertIn("已经转账/付款", frame["memory_completed_actions"])
        self.assertEqual(frame["slot_fact_provenance"]["has_paid"], "case_memory")
        self.assertEqual(frame["slot_fact_provenance"]["has_screen_share"], "current_turn")

    def test_dynamic_prompt_forbids_describing_memory_paid_as_just_happened(self):
        state = {
            "original_query": "我现在正在和对方屏幕共享",
            "history": [{"role": "user", "text": "我已经转账了，现在怎么办？"}],
            "slots": {"has_paid": TRUE, "has_screen_share": TRUE},
            "current_turn_slots": {"has_screen_share": TRUE},
            "risk": {"risk_class": "high_loss"},
            "resolution": {"completed_actions": [], "missing_resolution_actions": ["联系银行止付"]},
        }
        frame = build_scenario_frame(state)
        policy = build_dialogue_policy(state, frame)

        prompt = build_dynamic_answer_prompt(state, frame, policy, "")

        self.assertIn("memory_completed_actions", prompt)
        self.assertIn("根据前面记录", prompt)
        self.assertIn("不能写“你刚才已经转了钱”", prompt)
        self.assertIn("不要说“你已经联系银行", prompt)
        self.assertIn("大模型使用边界", prompt)
        self.assertIn("不能自行判断最终风险等级、诈骗类型或命中特征", prompt)
        self.assertIn("不得直接生成法律结论", prompt)

    def test_pre_loss_prompt_uses_short_blocking_contract_for_loan_cancellation(self):
        state = {
            "original_query": "昨天有人加我微信，说是某平台客服，告诉我之前开通过校园贷账户，如果不注销会影响征信，还可能产生高额利息。",
            "history": [],
            "slots": {},
            "current_turn_slots": {},
            "risk": {"risk_class": "medium_low_pre_loss"},
            "risk_level": "高风险（转账/信息暴露前）",
            "emergency_mode": True,
        }
        frame = build_scenario_frame(state)
        policy = build_dialogue_policy(state, frame)
        prompt = build_dynamic_answer_prompt(state, frame, policy, "")

        self.assertIn("注销/处理贷款账户", frame["requested_actions"])
        self.assertIn("最多3句话", policy["answer_contract"])
        self.assertTrue(requires_short_contract_answer(frame, policy))
        self.assertIn("判断一句 + 当前动作一句 + 一个关键追问", prompt)
        self.assertIn("不要一股脑输出完整套路", prompt)
        self.assertIn("注销贷款账户", prompt)

    def test_pre_loss_refund_case_keeps_exposure_unknown_and_short_formatted(self):
        state = {
            "original_query": "昨天有人加我微信，说是电商平台客服，告诉我之前买的商品质量有问题，可以给我退款。",
            "history": [],
            "slots": {},
            "current_turn_slots": {},
            "risk": {"risk_class": "medium_low_pre_loss"},
            "risk_level": "高风险（转账/信息暴露前）",
            "emergency_mode": True,
        }
        frame = build_scenario_frame(state)
        policy = build_dialogue_policy(state, frame)
        prompt = build_dynamic_answer_prompt(state, frame, policy, "")
        fallback = fallback_dynamic_answer(state, frame, policy)

        self.assertEqual(frame["exposure_state"], "unknown")
        self.assertIn("退款/理赔处理", frame["requested_actions"])
        self.assertIn("是否转账/付款", frame["unknown_exposure_actions"])
        self.assertIn("unknown_exposure_actions", prompt)
        self.assertIn("不能改写成“你目前还没做/你没有做/说明你还没被骗”", prompt)
        self.assertIn("输出必须易读", prompt)
        self.assertIn("退款、退费、理赔、商品质量问题", prompt)
        self.assertEqual(policy["move"], "block_then_ask_exposure")
        self.assertTrue(requires_short_contract_answer(frame, policy))
        self.assertEqual(fallback.count("\n\n"), 2)
        self.assertIn("冒充客服退款诈骗", fallback)
        self.assertIn("只通过平台App订单页或官网客服核实", fallback)
        self.assertTrue("是否" in fallback or "有没有" in fallback)
        self.assertNotIn("风险判断：", fallback)
        self.assertNotIn("先别做：", fallback)
        self.assertNotIn("现在只确认一件事：", fallback)
        self.assertEqual(fallback.count("\n1. "), 0)
        self.assertNotIn("**", fallback)
        self.assertNotIn("\n- ", fallback)
        self.assertNotIn("你目前还没做", fallback)
        self.assertNotIn("说明你还没被骗", fallback)
        self.assertNotIn("这是好事", fallback)

    def test_unknown_exposure_answer_contract_replaces_unfounded_safe_claims(self):
        state = {
            "original_query": "昨天有人加我微信，说是电商平台客服，告诉我之前买的商品质量有问题，可以给我退款。",
            "history": [],
            "slots": {},
            "current_turn_slots": {},
            "risk": {"risk_class": "medium_low_pre_loss"},
            "emergency_mode": True,
        }
        frame = build_scenario_frame(state)
        policy = build_dialogue_policy(state, frame)
        unsafe_answer = (
            "你遇到的情况非常典型。对方主动加你微信，自称电商平台客服，以商品质量问题退款为由联系你，"
            "这本身就是高危信号。你目前还没做任何危险动作，这是好事，说明你还没被骗。"
        )

        answer = enforce_dynamic_answer_contract(unsafe_answer, state, frame, policy)

        self.assertIn("只通过平台App订单页或官网客服核实", answer)
        self.assertTrue("是否" in answer or "有没有" in answer)
        self.assertNotIn("风险判断：", answer)
        self.assertNotIn("先别做：", answer)
        self.assertNotIn("现在只确认一件事：", answer)
        self.assertEqual(answer.count("\n1. "), 0)
        self.assertNotIn("**", answer)
        self.assertNotIn("\n- ", answer)
        self.assertNotIn("你目前还没做任何危险动作", answer)
        self.assertNotIn("说明你还没被骗", answer)
        self.assertGreaterEqual(answer.count("\n\n"), 2)

    def test_llm_boundary_rejects_changed_risk_level(self):
        state = {
            "original_query": "对方让我做点赞任务，先垫付300元，完成后返500元。",
            "fraud_type": "刷单返利诈骗",
            "risk_level": "高风险",
            "risk_score": 85,
            "rule_engine": {
                "fraud_type": "刷单返利诈骗",
                "risk_level": "高风险",
                "risk_score": 85,
                "risk_features": ["任务返佣", "要求垫付资金"],
            },
            "resolution": {"risk_resolved": False},
        }
        frame = build_scenario_frame(state)
        policy = build_dialogue_policy(state, frame)
        unsafe_answer = "我重新判断了一下，这只是低风险，不太像诈骗，可以继续观察。"

        answer = enforce_dynamic_answer_contract(unsafe_answer, state, frame, policy)

        self.assertIn("risk_level_mismatch", state["llm_boundary_violations"])
        self.assertNotIn("低风险", answer)
        self.assertIn("刷单返利诈骗", answer)
        self.assertNotIn("风险判断：", answer)

    def test_llm_boundary_rejects_changed_fraud_type(self):
        state = {
            "original_query": "对方让我做点赞任务，先垫付300元，完成后返500元。",
            "fraud_type": "刷单返利诈骗",
            "risk_level": "高风险",
            "risk_score": 85,
            "rule_engine": {
                "fraud_type": "刷单返利诈骗",
                "risk_level": "高风险",
                "risk_score": 85,
                "risk_features": ["任务返佣", "要求垫付资金"],
            },
            "resolution": {"risk_resolved": False},
        }
        frame = build_scenario_frame(state)
        policy = build_dialogue_policy(state, frame)
        unsafe_answer = "这是冒充公检法诈骗，风险等级高风险，请按公检法场景处理。"

        answer = enforce_dynamic_answer_contract(unsafe_answer, state, frame, policy)

        self.assertIn("fraud_type_mismatch", state["llm_boundary_violations"])
        self.assertNotIn("冒充公检法诈骗", answer)
        self.assertIn("刷单返利诈骗", answer)

    def test_llm_boundary_rejects_unsupported_legal_or_case_claim(self):
        state = {
            "original_query": "对方让我做点赞任务，先垫付300元，完成后返500元。",
            "fraud_type": "刷单返利诈骗",
            "risk_level": "高风险",
            "risk_score": 85,
            "rule_engine": {
                "fraud_type": "刷单返利诈骗",
                "risk_level": "高风险",
                "risk_score": 85,
                "risk_features": ["任务返佣", "要求垫付资金"],
            },
            "resolution": {"risk_resolved": False},
        }
        frame = build_scenario_frame(state)
        policy = build_dialogue_policy(state, frame)
        unsafe_answer = "根据《刑法》第266条，这一定构成诈骗罪。真实案例显示对方会被判刑。"

        answer = enforce_dynamic_answer_contract(unsafe_answer, state, frame, policy)

        self.assertIn("unsupported_legal_or_case_claim", state["llm_boundary_violations"])
        self.assertNotIn("第266条", answer)
        self.assertNotIn("真实案例", answer)
        self.assertIn("刷单返利诈骗", answer)

    def test_emergency_graph_refund_case_returns_short_answer_end_to_end(self):
        session_id = f"test-refund-short-{uuid.uuid4().hex}"
        text = "昨天有人加我微信，说是电商平台客服，告诉我之前买的商品质量有问题，可以给我退款。"
        fake_memory = _FakeMemoryManager()
        try:
            with (
                patch("app.modules.emergency_dissuasion.service.get_memory_manager", return_value=fake_memory),
                patch("app.modules.emergency_dissuasion.service.get_recent_messages", return_value=[]),
                patch("app.query_process.agent.nodes.compact_workflow_core.get_case_state", return_value={}),
                patch("app.query_process.agent.nodes.compact_workflow_core.save_case_state", return_value=None),
                patch("app.query_process.agent.nodes.compact_workflow_core.get_memory_manager", return_value=fake_memory),
                patch("app.query_process.agent.nodes.compact_workflow_core._knowledge_lookup", return_value=[]),
                patch("app.query_process.agent.nodes.compact_workflow_core._llm_resolution_judge", return_value={}),
                patch("app.query_process.agent.nodes.compact_workflow_core._save_history", return_value=None),
            ):
                run_emergency_graph(session_id, text, is_stream=False)
                result = build_emergency_sync_result(session_id)
        finally:
            clear_task(session_id)

        answer = result["answer"]
        summary = result["summary"]

        self.assertEqual(summary["dialogue_policy"]["move"], "block_then_ask_exposure")
        self.assertEqual(summary["scenario_frame"]["exposure_state"], "unknown")
        self.assertIn("退款/理赔处理", summary["scenario_frame"]["requested_actions"])
        self.assertIn("只通过平台App订单页或官网客服核实", answer)
        self.assertTrue("是否" in answer or "有没有" in answer)
        self.assertNotIn("风险判断：", answer)
        self.assertNotIn("先别做：", answer)
        self.assertNotIn("现在只确认一件事：", answer)
        self.assertEqual(answer.count("\n1. "), 0)
        self.assertNotIn("**", answer)
        self.assertNotIn("\n- ", answer)
        self.assertGreaterEqual(answer.count("\n\n"), 2)
        self.assertLessEqual(len(answer), 360)
        self.assertNotIn("你目前还没做", answer)
        self.assertNotIn("目前你还没提到", answer)
        self.assertNotIn("这是好事", answer)
        self.assertNotIn("说明你还没被骗", answer)

    def test_emergency_graph_brush_case_returns_structured_realtime_dissuasion(self):
        session_id = f"test-brush-realtime-{uuid.uuid4().hex}"
        text = "我最近加了一个好友，他叫我一起和她刷单，一单可以赚50，我已经刷了十几单了"
        fake_memory = _FakeMemoryManager()
        try:
            with (
                patch("app.modules.emergency_dissuasion.service.get_memory_manager", return_value=fake_memory),
                patch("app.modules.emergency_dissuasion.service.get_recent_messages", return_value=[]),
                patch("app.query_process.agent.nodes.compact_workflow_core.get_case_state", return_value={}),
                patch("app.query_process.agent.nodes.compact_workflow_core.save_case_state", return_value=None),
                patch("app.query_process.agent.nodes.compact_workflow_core.get_memory_manager", return_value=fake_memory),
                patch("app.query_process.agent.nodes.compact_workflow_core._knowledge_lookup", return_value=[]),
                patch("app.query_process.agent.nodes.compact_workflow_core._llm_resolution_judge", return_value={}),
                patch("app.query_process.agent.nodes.compact_workflow_core._save_history", return_value=None),
                patch("app.query_process.agent.nodes.compact_workflow_core.get_llm_client", side_effect=RuntimeError("LLM should not be called for structured realtime dissuasion")),
            ):
                run_emergency_graph(session_id, text, is_stream=False)
                result = build_emergency_sync_result(session_id)
        finally:
            clear_task(session_id)

        answer = result["answer"]
        dialogue = result["summary"]["intervention_dialogue"]

        self.assertEqual(result["fraud_type"], "刷单返利诈骗")
        self.assertEqual(dialogue["manager"], "multi_turn_risk_intervention_dialogue_manager")
        self.assertEqual(dialogue["state"], "S3_high_risk_confirm")
        self.assertEqual(dialogue["active_risk_case"]["risk_scene"], "刷单返利诈骗")
        self.assertEqual(dialogue["next_required_slot"], "has_advance_payment_request")
        self.assertIn("要求垫付", dialogue["quick_replies"])
        self.assertIn("single_step_response", dialogue)
        self.assertNotIn("风险研判：", answer)
        self.assertNotIn("命中的风险特征：", answer)
        self.assertNotIn("立即劝阻：", answer)
        self.assertNotIn("现在只确认一件事：", answer)
        self.assertIn("刷单返利诈骗", answer)
        self.assertIn("刷单", answer)
        self.assertIn("先垫付、充值或交保证金", answer)
        self.assertIn("不要", answer)
        self.assertNotIn("引导投资博彩刷单", answer)
        self.assertNotIn("共享、远控或网络", answer)
        self.assertNotIn("**", answer)
        self.assertNotIn("\n- ", answer)

    def test_intervention_dialogue_routes_resolved_case_to_report_before_education(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "已停止",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 85,
                "risk_level": "高风险",
                "ready_for_education": True,
                "resolution": {
                    "risk_resolved": True,
                    "completed_actions": ["stopped_operation"],
                },
                "slots": {"has_stopped_operation": TRUE},
                "risk_features": ["要求垫付资金", "任务返佣"],
            }
        )

        self.assertEqual(dialogue["state"], "S6_report_and_evidence")
        self.assertEqual(dialogue["policy"], "start_report_flow")
        self.assertEqual(dialogue["next_required_slot"], "evidence_saved")
        self.assertIn("证据还在", dialogue["quick_replies"])
        self.assertIn("证据保存和举报", dialogue["single_step_response"])

    def test_intervention_dialogue_allows_education_after_evidence_is_saved(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "我想知道这种骗局怎么骗",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 85,
                "risk_level": "高风险",
                "ready_for_education": True,
                "route_decision": {
                    "primary_intent": "anti_fraud_qa",
                    "workflow_mode": "knowledge_answer",
                },
                "resolution": {
                    "risk_resolved": True,
                    "completed_actions": ["stopped_operation", "preserved_evidence"],
                },
                "slots": {
                    "has_stopped_operation": TRUE,
                    "has_preserved_evidence": TRUE,
                },
            }
        )

        self.assertEqual(dialogue["state"], "S7_education_review")
        self.assertEqual(dialogue["policy"], "knowledge_education")
        self.assertEqual(dialogue["next_required_slot"], "education_topic")
        self.assertIn("查看案例", dialogue["quick_replies"])
        self.assertTrue(dialogue["response_generation_constraints"]["allow_education_expansion"])
        self.assertEqual(dialogue["response_generation_constraints"]["max_reply_blocks"], 5)

    def test_linked_education_uses_resolved_brushing_case_context(self):
        state = {
            "original_query": "这种骗局怎么防？",
            "fraud_type": "刷单返利诈骗",
            "risk_score": 85,
            "risk_level": "高风险",
            "ready_for_education": True,
            "resolution": {
                "risk_resolved": True,
                "ready_for_education": True,
                "completed_actions": ["stopped_operation", "preserved_evidence"],
            },
            "slots": {
                "has_stopped_operation": TRUE,
                "has_preserved_evidence": TRUE,
            },
            "risk_features": ["要求垫付资金", "任务返佣"],
            "intervention_dialogue": {
                "state": "S7_education_review",
                "active_risk_case": {
                    "risk_scene": "刷单返利诈骗",
                    "hit_features": ["要求垫付资金", "任务返佣"],
                    "resolved": True,
                },
                "response_generation_constraints": {
                    "max_reply_blocks": 5,
                    "must_include": ["review_summary", "education_or_prevention"],
                    "allow_education_expansion": True,
                },
            },
        }
        frame = build_scenario_frame(state)
        policy = build_dialogue_policy(state, frame)

        answer = fallback_dynamic_answer(state, frame, policy)

        self.assertIn("你刚才遇到的是“刷单返利诈骗”", answer)
        self.assertIn("用兼职、点赞、做任务吸引你", answer)
        self.assertIn("先给小额返利建立信任", answer)
        self.assertIn("要求你垫付更大金额", answer)
        self.assertIn("凡是要求先垫付再返利", answer)

    def test_linked_education_uses_resolved_fake_customer_service_context(self):
        state = {
            "original_query": "这种情况后面怎么防？",
            "fraud_type": "冒充客服退款诈骗",
            "risk_score": 86,
            "risk_level": "高风险",
            "ready_for_education": True,
            "resolution": {
                "risk_resolved": True,
                "ready_for_education": True,
                "completed_actions": ["stopped_operation", "preserved_evidence"],
            },
            "slots": {
                "has_stopped_operation": TRUE,
                "has_preserved_evidence": TRUE,
            },
            "risk_features": ["客服退款", "会议软件", "屏幕共享"],
            "intervention_dialogue": {
                "state": "S7_education_review",
                "active_risk_case": {
                    "risk_scene": "冒充客服退款诈骗",
                    "hit_features": ["客服退款", "会议软件", "屏幕共享"],
                    "resolved": True,
                },
                "response_generation_constraints": {
                    "max_reply_blocks": 5,
                    "must_include": ["review_summary", "education_or_prevention"],
                    "allow_education_expansion": True,
                },
            },
        }
        frame = build_scenario_frame(state)
        policy = build_dialogue_policy(state, frame)

        answer = fallback_dynamic_answer(state, frame, policy)

        self.assertIn("你刚才遇到的是“冒充客服退款诈骗”", answer)
        self.assertIn("退款、理赔、订单异常", answer)
        self.assertIn("下载会议软件、共享屏幕", answer)
        self.assertIn("正规客服不会要求屏幕共享", answer)
        self.assertNotIn("请把", answer)

    def test_intervention_dialogue_outputs_safety_gate_confirmation(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "那刷单诈骗是什么？",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 85,
                "risk_level": "高风险",
                "route_decision": {
                    "safety_gate": {
                        "required": True,
                        "gate_name": "Safety Gate：高风险安全确认门",
                        "blocked_function": "knowledge_education",
                        "confirm_slot": "has_stopped_operation",
                        "question": "我可以给你讲，但先确认一件事：你现在是否已经停止转账或付款？",
                    }
                },
                "resolution": {"risk_resolved": False},
                "slots": {},
                "risk_features": ["要求垫付资金", "任务返佣"],
            }
        )

        self.assertEqual(dialogue["state"], "S2_safety_gate")
        self.assertEqual(dialogue["policy"], "safety_gate_confirm_stop")
        self.assertEqual(dialogue["next_required_slot"], "has_stopped_operation")
        self.assertTrue(dialogue["safety_gate"]["required"])
        self.assertIn("已停止", dialogue["quick_replies"])
        self.assertIn("先确认一件事", dialogue["single_step_response"])

    def test_intervention_dialogue_routes_mitigated_case_to_report_flow(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "我没有转账，已经拉黑对方了。",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 55,
                "risk_level": "高风险",
                "risk_decay": {
                    "status": "mitigated",
                    "current_risk_score": 55,
                    "risk_level": "高风险",
                },
                "resolution": {"risk_resolved": False},
                "slots": {"has_stopped_operation": TRUE},
                "risk_features": ["要求垫付资金", "任务返佣"],
            }
        )

        self.assertEqual(dialogue["state"], "S6_report_and_evidence")
        self.assertEqual(dialogue["policy"], "start_report_flow")
        self.assertEqual(dialogue["active_risk_case"]["risk_decay"]["status"], "mitigated")
        self.assertLessEqual(dialogue["active_risk_case"]["current_risk_score"], 55)

    def test_intervention_dialogue_puts_observation_case_into_monitoring(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "这个靠谱吗？",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 35,
                "risk_level": "中风险",
                "risk_decay": {
                    "status": "observation",
                    "current_risk_score": 35,
                    "risk_level": "中风险",
                },
                "resolution": {"risk_resolved": False},
                "slots": {},
                "risk_features": ["任务返佣"],
            }
        )

        self.assertEqual(dialogue["state"], "S8_closed_monitoring")
        self.assertEqual(dialogue["policy"], "monitoring")
        self.assertEqual(dialogue["confirmation_question"], "")
        self.assertIn("继续观察", dialogue["quick_replies"])

    def test_intervention_dialogue_keeps_report_as_secondary_after_blocking_screen_share(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "我要举报这个客服，他还让我共享屏幕。",
                "fraud_type": "冒充客服退款诈骗",
                "risk_score": 86,
                "risk_level": "高风险",
                "route_decision": {
                    "multi_intent_conflict": {
                        "has_conflict": True,
                        "primary_priority": "P1",
                        "primary_function": "real_time_intervention",
                        "secondary_functions": ["suspicious_report"],
                        "detected_intents": [
                            {"priority": "P1", "function_route": "real_time_intervention", "intent": "risk_help"},
                            {"priority": "P2", "function_route": "suspicious_report", "intent": "report_submit"},
                        ],
                    }
                },
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "冒充客服退款诈骗",
                    "risk_score": 86,
                    "risk_level": "高风险",
                    "evidence": ["客服", "屏幕共享"],
                },
                "resolution": {"risk_resolved": False},
                "slots": {"current_requested_action": "共享屏幕"},
                "risk_features": ["客服", "屏幕共享"],
            }
        )

        self.assertEqual(dialogue["state"], "S3_high_risk_confirm")
        self.assertIn("请先不要共享屏幕", dialogue["single_step_response"])
        self.assertIn("我会继续帮你举报这个客服", dialogue["single_step_response"])
        self.assertEqual(dialogue["next_required_slot"], "has_screen_sharing")
        self.assertIn("共享屏幕可能导致银行卡、验证码或支付信息泄露", dialogue["single_step_response"])

    def test_intervention_dialogue_auto_generates_report_draft_for_high_risk_case(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "客服让我下载会议软件并共享屏幕",
                "fraud_type": "冒充客服退款诈骗",
                "risk_score": 86,
                "risk_level": "高风险",
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "冒充客服退款诈骗",
                    "risk_score": 86,
                    "risk_level": "高风险",
                    "evidence": ["客服", "退款", "会议软件", "屏幕共享"],
                },
                "resolution": {"risk_resolved": False},
                "slots": {"current_requested_action": "下载会议软件并共享屏幕"},
                "risk_features": ["客服", "退款", "会议软件", "屏幕共享"],
            }
        )

        draft = dialogue["report_draft"]
        card = dialogue["report_draft_card"]

        self.assertEqual(draft["status"], "draft")
        self.assertEqual(draft["report_type"], "冒充客服退款诈骗")
        self.assertEqual(draft["risk_level"], "高风险")
        self.assertEqual(draft["risk_score"], 86)
        self.assertEqual(draft["suspicious_content"], "客服让我下载会议软件并共享屏幕")
        self.assertEqual(draft["hit_features"], ["客服", "退款", "会议软件", "屏幕共享"])
        self.assertIn("聊天记录", draft["suggested_evidence"])
        self.assertIn("对方账号", draft["suggested_evidence"])
        self.assertIn("可疑链接", draft["suggested_evidence"])
        self.assertIn("转账凭证", draft["suggested_evidence"])
        self.assertFalse(draft["auto_submit"])
        self.assertEqual(card["title"], "系统已为你生成举报草稿")
        self.assertIn("系统已为你生成举报草稿", card["display_text"])
        self.assertIn("诈骗类型：冒充客服退款诈骗", card["display_text"])
        self.assertEqual([item["label"] for item in card["actions"]], ["提交", "补充信息", "暂不提交"])
        self.assertEqual(dialogue["active_risk_case"]["report_draft"]["report_type"], "冒充客服退款诈骗")

    def test_customer_refund_slot_priority_asks_download_before_screen_share(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "客服说我快递丢了，要给我退款，让我下载会议软件。",
                "fraud_type": "冒充客服退款诈骗",
                "risk_score": 82,
                "risk_level": "高风险",
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "冒充客服退款诈骗",
                    "risk_score": 82,
                    "risk_level": "高风险",
                    "evidence": ["客服", "退款", "会议软件"],
                },
                "resolution": {"risk_resolved": False},
                "slots": {"current_requested_action": "下载陌生App"},
                "risk_features": ["客服", "退款", "诱导下载陌生APP"],
            }
        )

        self.assertEqual(dialogue["next_required_slot"], "has_downloaded_app")
        self.assertIn("是否已经下载或打开", dialogue["confirmation_question"])
        self.assertEqual(dialogue["slot_priority_scene"], "fake_customer_refund")
        self.assertEqual(dialogue["slot_priority_schema"][0]["slot"], "has_downloaded_app")

    def test_customer_refund_slot_priority_skips_known_download_and_asks_screen_share(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "客服说退款要下载会议软件。",
                "fraud_type": "冒充客服退款诈骗",
                "risk_score": 82,
                "risk_level": "高风险",
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "冒充客服退款诈骗",
                    "risk_score": 82,
                    "risk_level": "高风险",
                    "evidence": ["客服", "退款", "会议软件"],
                },
                "resolution": {"risk_resolved": False},
                "slots": {"has_downloaded_app": FALSE},
                "risk_features": ["客服", "退款", "诱导下载陌生APP"],
            }
        )

        self.assertEqual(dialogue["next_required_slot"], "has_screen_sharing")
        self.assertIn("共享屏幕", dialogue["confirmation_question"])

    def test_brushing_slot_priority_asks_advance_payment_first(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "有人说做任务可以赚钱。",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 45,
                "risk_level": "中风险",
                "resolution": {"risk_resolved": False},
                "slots": {},
                "risk_features": ["任务返佣"],
            }
        )

        self.assertEqual(dialogue["next_required_slot"], "has_advance_payment_request")
        self.assertIn("先垫付、充值或交保证金", dialogue["confirmation_question"])
        self.assertEqual(dialogue["slot_priority_scene"], "brushing_rebate")

    def test_brushing_slot_priority_asks_amount_after_payment_status_known(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "他说先垫付完成后返佣。",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 85,
                "risk_level": "高风险",
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "刷单返利诈骗",
                    "risk_score": 85,
                    "risk_level": "高风险",
                    "evidence": ["要求垫付资金", "任务返佣"],
                },
                "resolution": {"risk_resolved": False},
                "slots": {
                    "has_advance_payment_request": TRUE,
                    "has_paid": FALSE,
                },
                "risk_features": ["要求垫付资金", "任务返佣"],
            }
        )

        self.assertEqual(dialogue["next_required_slot"], "money_amount")
        self.assertIn("多少金额", dialogue["confirmation_question"])

    def test_intervention_dialogue_single_step_response_has_hard_reply_constraints(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "我准备给对方转500保证金，返800。",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 92,
                "risk_level": "紧急风险",
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "刷单返利诈骗",
                    "risk_score": 92,
                    "risk_level": "紧急风险",
                    "evidence": ["要求垫付资金", "任务返佣"],
                },
                "resolution": {"risk_resolved": False},
                "slots": {"current_requested_action": "转账/付款"},
                "risk_features": ["要求垫付资金", "任务返佣"],
            }
        )

        answer = dialogue["single_step_response"]
        constraints = dialogue["response_generation_constraints"]

        self.assertEqual(constraints["max_reply_blocks"], 3)
        self.assertFalse(constraints["allow_education_expansion"])
        self.assertLessEqual(len(self._reply_blocks(answer)), 3)
        self.assertIn("刷单返利诈骗", answer)
        self.assertIn("不要", answer)
        self.assertIn("还没付款、准备付款，还是已经付款", answer)
        self.assertNotIn("风险判断：", answer)
        self.assertNotIn("先别做：", answer)
        self.assertNotIn("现在只确认一件事：", answer)
        self.assertNotIn("防范建议", answer)
        self.assertNotIn("常见流程", answer)
        self.assertNotIn("96110", answer)

    def test_realtime_structured_answer_drops_extra_advice_before_risk_is_blocked(self):
        state = {
            "original_query": "客服让我下载会议软件退款，还让我共享屏幕。",
            "fraud_type": "冒充客服退款诈骗",
            "risk_score": 90,
            "risk_level": "高风险",
            "slots": {"current_requested_action": "共享屏幕"},
            "realtime_dissuasion": {
                "enabled": True,
                "fraud_type": "冒充客服退款诈骗",
                "risk_score": 90,
                "risk_level": "高风险",
                "primary_warning": "请先不要共享屏幕。",
                "immediate_actions": ["请先不要共享屏幕。", "不要输入验证码。"],
                "dont_do": ["不要继续聊天。", "不要提供银行卡。"],
                "prevention_advice": ["以后只通过官方App核实退款。"],
                "followup_question": "你是否已经开启屏幕共享？",
                "evidence": ["客服退款", "会议软件", "屏幕共享"],
            },
            "resolution": {"risk_resolved": False},
        }
        frame = build_scenario_frame(state)
        policy = build_dialogue_policy(state, frame)

        answer = build_realtime_structured_answer(state, frame, policy)

        self.assertLessEqual(len(self._reply_blocks(answer)), 3)
        self.assertEqual(answer.count("\n1. "), 0)
        self.assertIn("屏幕共享", answer)
        self.assertIn("请先不要共享屏幕", answer)
        self.assertIn("你是否已经开启屏幕共享", answer)
        self.assertNotIn("风险判断：", answer)
        self.assertNotIn("先别做：", answer)
        self.assertNotIn("现在只确认一件事：", answer)
        self.assertNotIn("防范建议：", answer)
        self.assertNotIn("不要继续做：", answer)

    def test_emergency_graph_exposes_report_draft_in_summary(self):
        session_id = f"test-report-draft-{uuid.uuid4().hex}"
        text = "客服让我下载会议软件并共享屏幕"
        fake_memory = _FakeMemoryManager()
        try:
            with (
                patch("app.modules.emergency_dissuasion.service.get_memory_manager", return_value=fake_memory),
                patch("app.modules.emergency_dissuasion.service.get_recent_messages", return_value=[]),
                patch("app.query_process.agent.nodes.compact_workflow_core.get_case_state", return_value={}),
                patch("app.query_process.agent.nodes.compact_workflow_core.save_case_state", return_value=None),
                patch("app.query_process.agent.nodes.compact_workflow_core.get_memory_manager", return_value=fake_memory),
                patch("app.query_process.agent.nodes.compact_workflow_core._knowledge_lookup", return_value=[]),
                patch("app.query_process.agent.nodes.compact_workflow_core._llm_resolution_judge", return_value={}),
                patch("app.query_process.agent.nodes.compact_workflow_core._save_history", return_value=None),
                patch("app.query_process.agent.nodes.compact_workflow_core.get_llm_client", side_effect=RuntimeError("LLM should not be called")),
            ):
                run_emergency_graph(session_id, text, is_stream=False)
                result = build_emergency_sync_result(session_id)
        finally:
            clear_task(session_id)

        summary = result["summary"]
        draft = summary["report_draft"]

        self.assertEqual(draft["status"], "draft")
        self.assertEqual(draft["report_type"], "冒充客服退款诈骗")
        self.assertTrue(any("屏幕" in item and "共享" in item for item in draft["hit_features"]))
        self.assertEqual(summary["intervention"]["report_draft"]["report_type"], "冒充客服退款诈骗")
        self.assertEqual(summary["report_draft_card"]["actions"][0]["label"], "提交")

    def test_pending_question_uses_intervention_next_slot_only(self):
        from app.query_process.agent.memory.memory_manager import MemoryManager

        manager = MemoryManager()
        state = {
            "session_id": "s_test",
            "case_id": "case_test",
            "case_status": "unresolved",
            "route_decision": {
                "primary_intent": "risk_help",
                "workflow_mode": "risk_case_flow",
            },
            "intervention_dialogue": {
                "next_required_slot": "has_screen_sharing",
                "confirmation_question": "对方是否要求你共享屏幕？",
            },
        }

        pending = manager._pending_question_from_state(state)

        self.assertEqual(pending["target_slots"], ["has_screen_share"])
        self.assertEqual(pending["question_text"], "对方是否要求你共享屏幕？")


if __name__ == "__main__":
    unittest.main()
