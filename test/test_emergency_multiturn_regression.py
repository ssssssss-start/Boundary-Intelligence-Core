import unittest
from unittest.mock import patch

from app.query_process.agent.nodes.compact_workflow_core import (
    FALSE,
    TRUE,
    UNKNOWN,
    node_binary_risk_decision,
    node_case_context,
    node_intervention,
    node_resolution_or_education,
    node_scam_understanding,
    node_slot_gate,
    _rule_resolution_status,
)
from app.query_process.services.dynamic_response_planner import (
    build_dialogue_policy,
    build_linked_education_answer,
    build_scenario_frame,
)
from app.query_process.services.risk_intervention_dialogue_manager import build_intervention_dialogue


def run_until_intervention(query, case_state=None, history=None):
    state = {
        "session_id": "",
        "history": history or [],
        "history_text": "",
        "original_query": query,
        "emergency_mode": True,
        "memory_context": {"case_state": case_state or {}},
    }
    with patch("app.query_process.agent.nodes.compact_workflow_core._knowledge_lookup", return_value=[]):
        for node in [node_case_context, node_slot_gate, node_scam_understanding, node_binary_risk_decision, node_intervention]:
            state = node(state)
    return state


def run_full_risk_turn(query, case_state=None, history=None):
    memory_context = {
        "case_state": case_state or {},
        "pending_question": (case_state or {}).get("pending_question", {}),
        "route_context": (case_state or {}).get("route_context", {}),
        "session_id": "",
    }
    state = {
        "session_id": "",
        "history": history or [],
        "history_text": "",
        "original_query": query,
        "emergency_mode": True,
        "memory_context": memory_context,
        "route_decision": {
            "primary_intent": "risk_help",
            "workflow_mode": "risk_case_flow",
            "confidence": 1.0,
            "reason": "risk regression test fixture",
            "routing_decision": {"target": "risk_case_flow", "force_high_risk": False, "prefill_slots": {}},
        },
    }
    with (
        patch("app.query_process.agent.nodes.compact_workflow_core._knowledge_lookup", return_value=[]),
        patch("app.query_process.agent.nodes.compact_workflow_core.invoke_json_llm", return_value=({}, "")),
    ):
        for node in [
            node_case_context,
            node_slot_gate,
            node_scam_understanding,
            node_binary_risk_decision,
            node_intervention,
            node_resolution_or_education,
        ]:
            state = node(state)
    return state


class EmergencyMultiturnRegressionTest(unittest.TestCase):
    def _reply_blocks(self, text):
        return [block.strip() for block in str(text or "").split("\n\n") if block.strip()]

    def test_fake_police_sensitive_info_request_is_not_treated_as_provided(self):
        state = run_until_intervention("我最近接到一个电话 说我网购了一个违法物品 叫我提供个人信息和银行流水 还有卡号给他")

        self.assertEqual(state["fraud_type"], "冒充公检法诈骗")
        self.assertIn("涉案违法物品恐吓", state["risk_features"])
        self.assertIn("索要银行流水或卡号", state["risk_features"])
        self.assertEqual(state["slots"]["has_provided_identity_or_bank"], "unknown")
        self.assertNotIn("id_card_exposed", state["exposures"]["exposure_ids"])
        self.assertNotIn("bank_card_exposed", state["exposures"]["exposure_ids"])
        self.assertIn("id_card_exposed", state["exposures"]["suspected_exposure_ids"])
        self.assertIn("bank_card_exposed", state["exposures"]["suspected_exposure_ids"])
        self.assertEqual(state["realtime_dissuasion"]["goal"], "stop_sensitive_info")
        self.assertIn("不要提供个人信息、银行流水、银行卡号", state["realtime_dissuasion"]["primary_warning"])

        dialogue = build_intervention_dialogue(state)
        self.assertEqual(dialogue["state"], "S3_high_risk_confirm")
        self.assertEqual(dialogue["next_required_slot"], "has_given_bank_info")
        self.assertIn("是否已经提供过个人信息、银行流水、银行卡号", dialogue["confirmation_question"])
        self.assertIn("请先不要提供个人信息、银行流水、银行卡号", dialogue["single_step_response"])

    def test_fake_police_request_keeps_requested_action_unknown_after_turn_rewrite(self):
        state = run_full_risk_turn("我最近接到一个电话 说我网购了一个违法物品 叫我提供个人信息和银行流水 还有卡号给他")
        dialogue = state["intervention_dialogue"]
        answer = dialogue["single_step_response"]

        self.assertEqual(state["slots"]["has_provided_identity_or_bank"], UNKNOWN)
        self.assertEqual(state["slots"]["has_paid"], UNKNOWN)
        self.assertEqual(dialogue["state"], "S3_high_risk_confirm")
        self.assertEqual(dialogue["next_required_slot"], "has_given_bank_info")
        self.assertIn("高度疑似冒充公检法诈骗", answer)
        self.assertIn("请先不要提供个人信息、银行流水、银行卡号", answer)
        self.assertIn("是否已经提供过个人信息、银行流水、银行卡号", answer)
        self.assertNotIn("依据：", answer)
        self.assertNotIn("命中的风险特征", answer)
        self.assertNotIn("风险判断：", answer)
        self.assertNotIn("先别做：", answer)
        self.assertNotIn("通话记录、聊天记录、来电号码或对方账号是否还在", answer)

    def test_fake_police_provided_sensitive_info_requires_stop_before_evidence(self):
        first = run_full_risk_turn("我最近接到一个电话 说我网购了一个违法物品 叫我提供个人信息和银行流水 还有卡号给他")
        second = run_full_risk_turn("我已经提供了怎么办", case_state=first["case_state"])
        dialogue = second["intervention_dialogue"]
        answer = dialogue["single_step_response"]

        self.assertEqual(second["slots"]["has_provided_identity_or_bank"], TRUE)
        self.assertEqual(dialogue["state"], "S5_emergency_stop_loss")
        self.assertEqual(dialogue["next_required_slot"], "has_stopped_operation")
        self.assertIn("请立即停止和对方沟通", answer)
        self.assertIn("直接告诉我", answer)
        self.assertNotIn("通话记录、聊天记录、来电号码或对方账号是否还在", answer)

    def test_evidence_confirmed_advances_to_report_decision_not_education(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "还在",
                "fraud_type": "冒充公检法诈骗",
                "risk_score": 70,
                "risk_level": "高风险",
                "risk_decay": {
                    "status": "mitigated",
                    "current_risk_score": 70,
                    "risk_level": "高风险",
                },
                "realtime_dissuasion": {
                    "enabled": True,
                    "goal": "stop_sensitive_info",
                    "fraud_type": "冒充公检法诈骗",
                    "risk_score": 70,
                    "risk_level": "高风险",
                    "evidence": ["涉案违法物品恐吓", "索要银行流水或卡号"],
                },
                "resolution": {
                    "risk_resolved": False,
                    "completed_actions": ["stopped_operation", "evidence_preservation_reminded"],
                },
                "slots": {
                    "has_provided_identity_or_bank": TRUE,
                    "has_stopped_operation": TRUE,
                    "has_preserved_evidence": TRUE,
                    "has_report_decision_made": "unknown",
                },
                "risk_features": ["涉案违法物品恐吓", "索要银行流水或卡号"],
            }
        )

        self.assertEqual(dialogue["state"], "S6_report_and_evidence")
        self.assertEqual(dialogue["next_required_slot"], "report_needed")
        self.assertIn("是否需要我帮你生成一条举报记录", dialogue["confirmation_question"])
        self.assertIn("举报草稿", dialogue["single_step_response"])
        self.assertEqual(dialogue["report_draft"]["report_type"], "冒充公检法诈骗")

    def test_report_decision_answer_does_not_repeat_report_question(self):
        first = run_full_risk_turn("我最近接到一个电话 说我网购了一个违法物品 叫我提供个人信息和银行流水 还有卡号给他")
        second = run_full_risk_turn("我已经提供了怎么办", case_state=first["case_state"])
        third = run_full_risk_turn("已停止", case_state=second["case_state"])
        fourth = run_full_risk_turn("还在", case_state=third["case_state"])

        self.assertEqual(fourth["intervention_dialogue"]["next_required_slot"], "report_needed")

        fifth = run_full_risk_turn("暂不举报", case_state=fourth["case_state"])
        dialogue = fifth["intervention_dialogue"]

        self.assertEqual(fifth["slots"]["has_report_decision_made"], TRUE)
        self.assertNotEqual(dialogue["next_required_slot"], "report_needed")
        self.assertNotIn("是否需要我帮你生成一条举报记录", dialogue["single_step_response"])
        self.assertIn(dialogue["state"], {"S7_education_review", "S8_closed_monitoring"})

    def test_s5_after_stopped_operation_does_not_ask_stop_again(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "已关闭",
                "fraud_type": "冒充客服退款诈骗",
                "risk_score": 92,
                "risk_level": "紧急风险",
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "冒充客服退款诈骗",
                    "risk_score": 92,
                    "risk_level": "紧急风险",
                    "evidence": ["客服", "退款", "屏幕共享"],
                },
                "risk": {"risk_class": "high_loss"},
                "resolution": {"risk_resolved": False},
                "slots": {
                    "has_screen_share": TRUE,
                    "has_stopped_operation": TRUE,
                    "current_requested_action": "共享屏幕",
                },
                "risk_features": ["客服", "退款", "屏幕共享"],
            }
        )

        self.assertEqual(dialogue["state"], "S5_emergency_stop_loss")
        self.assertEqual(dialogue["next_required_slot"], "has_given_code")
        self.assertNotIn("停止后回复", dialogue["single_step_response"])
        self.assertIn("验证码", dialogue["confirmation_question"])

    def test_screen_share_then_stopped_still_requires_device_isolation(self):
        first = run_until_intervention("我现在正在和对方屏幕共享")
        second = run_until_intervention("我停止了屏幕共享", case_state=first["case_state"])

        self.assertEqual(second["slots"]["has_screen_share"], TRUE)
        self.assertEqual(second["slots"]["has_stopped_operation"], TRUE)
        self.assertIn("screen_share_active", second["exposures"]["exposure_ids"])
        self.assertFalse(second["emergency_flow"]["can_claim_resolved"])
        self.assertIn("isolated_device", second["emergency_flow"]["missing_action_ids"])
        self.assertIn("checked_device_permissions", second["emergency_flow"]["missing_action_ids"])

    def test_screen_share_then_isolated_still_requires_permission_check(self):
        first = run_until_intervention("我现在正在和对方屏幕共享")
        second = run_until_intervention("我已经断网关机了，但还没检查权限", case_state=first["case_state"])

        self.assertEqual(second["slots"]["has_isolated_device"], TRUE)
        self.assertFalse(second["emergency_flow"]["can_claim_resolved"])
        self.assertNotIn("isolated_device", second["emergency_flow"]["missing_action_ids"])
        self.assertIn("checked_device_permissions", second["emergency_flow"]["missing_action_ids"])

    def test_bank_or_police_ambiguous_does_not_complete_both_actions(self):
        first = run_until_intervention("我已经转账5000元，现在怎么办")
        second = run_until_intervention("我已经联系银行或报警", case_state=first["case_state"])
        resolution = _rule_resolution_status(second)

        self.assertNotEqual(second["slots"].get("has_contacted_bank"), TRUE)
        self.assertNotEqual(second["slots"].get("has_reported_police"), TRUE)
        self.assertIn("contacted_bank_or_payment_platform", resolution["missing_action_ids"])
        self.assertIn("reported_police", resolution["missing_action_ids"])

    def test_future_transfer_intent_is_suspected_not_paid(self):
        state = run_until_intervention("我准备按他说的转账保证金")

        self.assertNotIn("money_paid", state["exposures"]["exposure_ids"])
        self.assertIn("money_paid", state["exposures"]["suspected_exposure_ids"])
        self.assertEqual(state["risk"]["risk_class"], "medium_low_pre_loss")
        self.assertTrue(state["realtime_dissuasion"]["enabled"])

    def test_requested_code_is_not_treated_as_code_exposed(self):
        state = run_until_intervention("对方让我把验证码发给他")

        self.assertNotIn("code_exposed", state["exposures"]["exposure_ids"])
        self.assertIn("code_exposed", state["exposures"]["suspected_exposure_ids"])
        self.assertEqual(state["risk"]["risk_class"], "medium_low_pre_loss")

    def test_brushing_friend_channel_small_rebate_returned_stays_brushing_and_asks_next_funding(self):
        first = run_full_risk_turn("最近有一个人加我好友 叫我做淘宝刷单 我已经刷了2单 赚了300了")

        self.assertEqual(first["fraud_type"], "刷单返利诈骗")
        self.assertNotEqual(first["fraud_type"], "冒充熟人诈骗")
        self.assertIn("任务返佣", first["risk_features"])
        self.assertIn("小额返利", first["risk_features"])
        self.assertEqual(first["intervention_dialogue"]["next_required_slot"], "has_advance_payment_request")
        self.assertIn("先垫付、充值或交保证金", first["intervention_dialogue"]["confirmation_question"])

        second = run_full_risk_turn("对", case_state=first["case_state"])

        self.assertEqual(second["slots"]["has_advance_payment_request"], TRUE)
        self.assertEqual(second["fraud_type"], "刷单返利诈骗")
        self.assertEqual(second["intervention_dialogue"]["next_required_slot"], "has_transfer")

        third = run_full_risk_turn("已经付款了 然后他已经返回给我了 现在我还能刷吗", case_state=second["case_state"])
        dialogue = third["intervention_dialogue"]

        self.assertEqual(third["fraud_type"], "刷单返利诈骗")
        self.assertEqual((third["rule_engine"] or {}).get("fraud_type"), "刷单返利诈骗")
        self.assertEqual(third["slots"]["has_paid"], TRUE)
        self.assertEqual(third["slots"]["has_received_rebate"], TRUE)
        self.assertEqual(third["slots"]["has_unrecovered_loss"], FALSE)
        self.assertNotIn("已发生转账", third["risk_features"])
        self.assertNotIn("money_paid", third["exposures"]["exposure_ids"])
        self.assertEqual(third["risk"]["risk_class"], "medium_low_pre_loss")
        self.assertLessEqual(int(third["risk_score"]), 86)
        self.assertNotEqual(dialogue["state"], "S5_emergency_stop_loss")
        self.assertEqual(dialogue["next_required_slot"], "has_continue_payment_request")
        self.assertIn("小额返利诱导阶段", dialogue["single_step_response"])
        self.assertIn("请不要继续刷下一单", dialogue["single_step_response"])
        self.assertIn("继续刷下一单、充值或垫付更大金额", dialogue["confirmation_question"])
        self.assertNotIn("风险判断：", dialogue["single_step_response"])
        self.assertNotIn("先别做：", dialogue["single_step_response"])
        self.assertEqual(third["anti_fraud_engine"]["risk_scene_name"], "刷单返利诈骗")

        fourth = run_full_risk_turn("还在", case_state=third["case_state"])
        fourth_dialogue = fourth["intervention_dialogue"]

        self.assertEqual(fourth["fraud_type"], "刷单返利诈骗")
        self.assertEqual(fourth["slots"]["has_continue_payment_request"], TRUE)
        self.assertEqual(fourth["slots"]["has_preserved_evidence"], UNKNOWN)
        self.assertNotIn("已发生转账", fourth["risk_features"])
        self.assertNotIn("money_paid", fourth["exposures"]["exposure_ids"])
        self.assertEqual(fourth["risk"]["risk_class"], "medium_low_pre_loss")
        self.assertEqual(fourth_dialogue["state"], "S4_real_time_intervention")
        self.assertEqual(fourth_dialogue["next_required_slot"], "has_stopped_operation")
        self.assertIn("请不要继续刷下一单", fourth_dialogue["single_step_response"])
        self.assertIn("停止继续刷单、充值或垫付", fourth_dialogue["confirmation_question"])

    def test_complex_brushing_rebate_flow_proves_multiturn_state_progression(self):
        clue = build_intervention_dialogue(
            {
                "original_query": "有人加我说做任务点赞可以赚钱",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 45,
                "risk_level": "中风险",
                "resolution": {"risk_resolved": False},
                "slots": {},
                "risk_features": ["任务返佣"],
            }
        )

        self.assertEqual(clue["state"], "S1_suspicious_clue")
        self.assertEqual(clue["policy"], "ask_next_key_question")
        self.assertEqual(clue["priority"], "P3")
        self.assertEqual(clue["next_required_slot"], "has_advance_payment_request")
        self.assertIn("先垫付、充值或交保证金", clue["confirmation_question"])
        self.assertLessEqual(len(self._reply_blocks(clue["single_step_response"])), 3)

        high_risk = build_intervention_dialogue(
            {
                "original_query": "他说先垫付300，完成后返500",
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
                "slots": {"has_advance_payment_request": TRUE},
                "risk_features": ["要求垫付资金", "任务返佣"],
            }
        )

        self.assertEqual(high_risk["state"], "S3_high_risk_confirm")
        self.assertEqual(high_risk["policy"], "confirm_action_status")
        self.assertEqual(high_risk["next_required_slot"], "has_transfer")
        self.assertIn("还没付款、准备付款，还是已经付款", high_risk["confirmation_question"])
        self.assertEqual(high_risk["report_draft"]["report_type"], "刷单返利诈骗")
        self.assertFalse(high_risk["report_draft"]["auto_submit"])

        realtime = build_intervention_dialogue(
            {
                "original_query": "我现在准备转账",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 92,
                "risk_level": "紧急风险",
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "刷单返利诈骗",
                    "risk_score": 92,
                    "risk_level": "紧急风险",
                    "primary_warning": "请立即暂停转账。",
                    "evidence": ["要求垫付资金", "任务返佣"],
                },
                "resolution": {"risk_resolved": False},
                "slots": {
                    "has_advance_payment_request": TRUE,
                    "current_requested_action": "转账/付款",
                },
                "risk_features": ["要求垫付资金", "任务返佣"],
            }
        )

        self.assertEqual(realtime["state"], "S4_real_time_intervention")
        self.assertEqual(realtime["policy"], "real_time_intervention")
        self.assertEqual(realtime["priority"], "P1")
        self.assertEqual(realtime["next_required_slot"], "has_stopped_operation")
        self.assertIn("停止继续刷单", realtime["confirmation_question"])
        self.assertLessEqual(len(self._reply_blocks(realtime["single_step_response"])), 3)

        mitigated = build_intervention_dialogue(
            {
                "original_query": "我还没转，已经停止联系并拉黑了",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 55,
                "risk_level": "高风险",
                "risk_decay": {
                    "status": "mitigated",
                    "current_risk_score": 55,
                    "risk_level": "高风险",
                },
                "resolution": {"risk_resolved": False},
                "slots": {
                    "has_advance_payment_request": TRUE,
                    "has_paid": FALSE,
                    "has_stopped_operation": TRUE,
                },
                "risk_features": ["要求垫付资金", "任务返佣"],
            }
        )

        self.assertEqual(mitigated["state"], "S6_report_and_evidence")
        self.assertEqual(mitigated["policy"], "start_report_flow")
        self.assertEqual(mitigated["priority"], "P4")
        self.assertEqual(mitigated["next_required_slot"], "evidence_saved")
        self.assertIn("聊天记录、收款账号或付款凭证", mitigated["confirmation_question"])
        self.assertEqual(mitigated["active_risk_case"]["risk_decay"]["status"], "mitigated")

        education_state = {
            "original_query": "这种骗局怎么防？",
            "fraud_type": "刷单返利诈骗",
            "risk_score": 35,
            "risk_level": "低风险",
            "risk_decay": {
                "status": "resolved",
                "current_risk_score": 35,
                "risk_level": "低风险",
            },
            "ready_for_education": True,
            "resolution": {
                "risk_resolved": True,
                "ready_for_education": True,
                "completed_actions": ["stopped_operation", "report_decision_made"],
            },
            "slots": {
                "has_advance_payment_request": TRUE,
                "has_paid": FALSE,
                "has_stopped_operation": TRUE,
                "has_report_decision_made": TRUE,
            },
            "risk_features": ["要求垫付资金", "任务返佣"],
        }
        education_dialogue = build_intervention_dialogue(education_state)
        education_state["intervention_dialogue"] = education_dialogue
        frame = build_scenario_frame(education_state)
        policy = build_dialogue_policy(education_state, frame)
        answer = build_linked_education_answer(education_state, frame, policy)

        self.assertEqual(education_dialogue["state"], "S7_education_review")
        self.assertEqual(education_dialogue["policy"], "knowledge_education")
        self.assertEqual(education_dialogue["priority"], "P5")
        self.assertIn("你刚才遇到的是“刷单返利诈骗”", answer)
        self.assertIn("要求先垫付再返利", answer)

    def test_complex_customer_refund_flow_preserves_slot_priority(self):
        first = build_intervention_dialogue(
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
        second = build_intervention_dialogue(
            {
                "original_query": "他说要共享屏幕才能退款。",
                "fraud_type": "冒充客服退款诈骗",
                "risk_score": 86,
                "risk_level": "高风险",
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "冒充客服退款诈骗",
                    "risk_score": 86,
                    "risk_level": "高风险",
                    "evidence": ["客服", "退款", "屏幕共享"],
                },
                "resolution": {"risk_resolved": False},
                "slots": {"has_downloaded_app": FALSE, "current_requested_action": "共享屏幕"},
                "risk_features": ["客服", "退款", "屏幕共享"],
            }
        )
        third = build_intervention_dialogue(
            {
                "original_query": "已经开了。",
                "fraud_type": "冒充客服退款诈骗",
                "risk_score": 92,
                "risk_level": "紧急风险",
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "冒充客服退款诈骗",
                    "risk_score": 92,
                    "risk_level": "紧急风险",
                    "evidence": ["客服", "退款", "屏幕共享"],
                },
                "risk": {"risk_class": "high_loss"},
                "resolution": {"risk_resolved": False},
                "slots": {
                    "has_downloaded_app": FALSE,
                    "has_screen_share": TRUE,
                    "current_requested_action": "共享屏幕",
                },
                "risk_features": ["客服", "退款", "屏幕共享"],
            }
        )
        fourth = build_intervention_dialogue(
            {
                "original_query": "已关闭，没有给验证码，也没有输入银行卡密码。",
                "fraud_type": "冒充客服退款诈骗",
                "risk_score": 55,
                "risk_level": "高风险",
                "risk_decay": {
                    "status": "mitigated",
                    "current_risk_score": 55,
                    "risk_level": "高风险",
                },
                "resolution": {"risk_resolved": False},
                "slots": {
                    "has_downloaded_app": FALSE,
                    "has_screen_share": FALSE,
                    "has_shared_code": FALSE,
                    "has_provided_identity_or_bank": FALSE,
                },
                "risk_features": ["客服", "退款", "屏幕共享"],
            }
        )

        self.assertEqual(first["slot_priority_scene"], "fake_customer_refund")
        self.assertEqual(first["next_required_slot"], "has_downloaded_app")
        self.assertIn("是否已经下载或打开", first["confirmation_question"])
        self.assertEqual(second["next_required_slot"], "has_screen_sharing")
        self.assertTrue(
            "共享屏幕" in second["confirmation_question"] or "屏幕共享" in second["confirmation_question"],
            second["confirmation_question"],
        )
        self.assertEqual(third["state"], "S5_emergency_stop_loss")
        self.assertEqual(third["priority"], "P0")
        self.assertEqual(third["next_required_slot"], "has_stopped_operation")
        self.assertIn("请马上关闭屏幕共享", third["single_step_response"])
        self.assertEqual(fourth["state"], "S6_report_and_evidence")
        self.assertEqual(fourth["next_required_slot"], "evidence_saved")
        self.assertLessEqual(len(self._reply_blocks(fourth["single_step_response"])), 3)

    def test_screen_share_closed_asks_code_before_evidence(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "已关闭",
                "fraud_type": "冒充客服退款诈骗",
                "risk_score": 91,
                "risk_level": "紧急风险",
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "冒充客服退款诈骗",
                    "risk_score": 91,
                    "risk_level": "紧急风险",
                    "evidence": ["客服", "退款", "屏幕共享"],
                },
                "risk": {"risk_class": "high_loss"},
                "resolution": {"risk_resolved": False},
                "slots": {
                    "has_stopped_operation": TRUE,
                    "current_requested_action": "共享屏幕",
                },
                "risk_features": ["客服", "退款", "屏幕共享"],
            }
        )

        self.assertEqual(dialogue["state"], "S5_emergency_stop_loss")
        self.assertEqual(dialogue["next_required_slot"], "has_given_code")
        self.assertIn("验证码", dialogue["confirmation_question"])

    def test_evidence_negative_branch_does_not_repeat_same_question(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "没有",
                "fraud_type": "冒充客服退款诈骗",
                "risk_score": 58,
                "risk_level": "高风险",
                "risk_decay": {
                    "status": "mitigated",
                    "current_risk_score": 58,
                    "risk_level": "高风险",
                },
                "resolution": {"risk_resolved": False},
                "slots": {
                    "has_stopped_operation": TRUE,
                    "has_shared_code": FALSE,
                    "has_provided_identity_or_bank": FALSE,
                    "has_preserved_evidence": FALSE,
                },
                "risk_features": ["客服", "退款", "屏幕共享"],
            }
        )

        self.assertEqual(dialogue["state"], "S6_report_and_evidence")
        self.assertEqual(dialogue["next_required_slot"], "report_needed")
        self.assertIn("还能找到的来电号码", dialogue["single_step_response"])
        self.assertNotIn("聊天记录和对方账号是否还在", dialogue["single_step_response"])

    def test_mitigated_case_can_enter_linked_education(self):
        dialogue = build_intervention_dialogue(
            {
                "original_query": "那刷单诈骗是什么",
                "fraud_type": "刷单返利诈骗",
                "risk_score": 55,
                "risk_level": "高风险",
                "risk_decay": {
                    "status": "mitigated",
                    "current_risk_score": 55,
                    "risk_level": "高风险",
                },
                "resolution": {"risk_resolved": False},
                "route_decision": {
                    "primary_intent": "anti_fraud_qa",
                    "workflow_mode": "knowledge_answer",
                },
                "slots": {
                    "has_stopped_operation": TRUE,
                    "has_paid": FALSE,
                },
                "risk_features": ["要求垫付资金", "任务返佣"],
            }
        )

        self.assertEqual(dialogue["state"], "S7_education_review")
        self.assertEqual(dialogue["policy"], "knowledge_education")

    def test_investment_paid_in_first_turn_is_treated_as_exposure(self):
        state = run_full_risk_turn("投资老师说带我赚钱，我已经入金2000")

        self.assertEqual(state["fraud_type"], "虚假投资理财诈骗")
        self.assertEqual(state["slots"]["has_paid"], TRUE)
        self.assertEqual(state["risk"]["risk_class"], "high_loss")
        self.assertEqual(state["intervention_dialogue"]["state"], "S5_emergency_stop_loss")
        self.assertIn("请不要再转任何钱", state["intervention_dialogue"]["single_step_response"])

    def test_complex_multi_intent_report_and_code_or_screen_share_prioritizes_intervention(self):
        code_conflict = build_intervention_dialogue(
            {
                "original_query": "我要举报这个链接，他还让我输入验证码。",
                "fraud_type": "钓鱼链接/虚假网站诈骗",
                "risk_score": 88,
                "risk_level": "高风险",
                "route_decision": {
                    "multi_intent_conflict": {
                        "has_conflict": True,
                        "primary_priority": "P1",
                        "primary_function": "real_time_intervention",
                        "secondary_functions": ["suspicious_report"],
                        "detected_intents": [
                            {"priority": "P1", "function_route": "real_time_intervention"},
                            {"priority": "P2", "function_route": "suspicious_report"},
                        ],
                    }
                },
                "realtime_dissuasion": {
                    "enabled": True,
                    "fraud_type": "钓鱼链接/虚假网站诈骗",
                    "risk_score": 88,
                    "risk_level": "高风险",
                    "evidence": ["可疑链接", "验证码"],
                },
                "resolution": {"risk_resolved": False},
                "slots": {"current_requested_action": "输入验证码"},
                "risk_features": ["可疑链接", "索要验证码"],
            }
        )
        screen_conflict = build_intervention_dialogue(
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
                            {"priority": "P1", "function_route": "real_time_intervention"},
                            {"priority": "P2", "function_route": "suspicious_report"},
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

        self.assertIn(code_conflict["state"], {"S3_high_risk_confirm", "S4_real_time_intervention"})
        self.assertNotEqual(code_conflict["state"], "S6_report_and_evidence")
        self.assertEqual(code_conflict["next_required_slot"], "has_given_code")
        self.assertIn("请先不要输入或告诉对方验证码", code_conflict["single_step_response"])
        self.assertIn("我会继续帮你举报这个链接", code_conflict["single_step_response"])
        self.assertEqual(code_conflict["report_draft"]["status"], "draft")

        self.assertEqual(screen_conflict["state"], "S3_high_risk_confirm")
        self.assertEqual(screen_conflict["next_required_slot"], "has_screen_sharing")
        self.assertIn("请先不要共享屏幕", screen_conflict["single_step_response"])
        self.assertIn("我会继续帮你举报这个客服", screen_conflict["single_step_response"])
        self.assertEqual(screen_conflict["report_draft"]["report_type"], "冒充客服退款诈骗")


if __name__ == "__main__":
    unittest.main()
