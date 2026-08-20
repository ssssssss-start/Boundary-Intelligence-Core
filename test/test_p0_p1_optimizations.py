import unittest
from unittest.mock import patch

from app.modules.knowledge_assistant.service import (
    _build_local_knowledge_answer,
    _knowledge_answer_satisfies_contract,
    _local_unified_route,
    _route_for_unified_assistant,
)
from app.query_process.services.risk_service import evaluate_risk_text
from app.query_process.services.semantic_risk_agent import (
    _deterministic_realtime_answer,
    build_structured_safety_card,
    decide_risk_from_analysis,
    generate_realtime_answer,
)


class P0P1OptimizationTest(unittest.TestCase):
    def test_behavior_combinations_emit_stable_types(self):
        cases = {
            "演唱会门票让我加微信，平台外先付定金": "校园二手/票务交易诈骗",
            "收卡中介说实名办卡交给他刷流水，按月给租金": "两卡出租出借与跑分诈骗",
            "视频里像亲友，说急需手术费，马上转账": "AI换脸冒充熟人诈骗",
            "金融平台客服说影响征信，要把贷款额度转到认证对接账户": "征信修复/注销账户诈骗",
            "跑腿取现后把钱转到指定银行卡，平台外收款": "两卡出租出借与跑分诈骗",
            "低价房源要求先付押金，拒绝实地看房和签合同": "租房合租押金诈骗",
            "航班取消，客服要求提供支付验证码才能退票": "机票火车票退改签诈骗",
            "短信称助学金到账，链接要求填身份证和银行卡验证码": "奖助学金/学费退费诈骗",
            "视频裸聊后威胁把通讯录发给家人，要求转账删视频": "裸聊敲诈勒索诈骗",
            "游戏账号买家让你登录平台并缴保证金解冻交易": "游戏交易诈骗",
            "物流客服称包裹理赔，要打开会议软件共享屏幕": "冒充客服诈骗",
            "民警称涉嫌洗钱，要求保密并把钱转入安全账户": "冒充公检法诈骗",
        }
        for text, expected in cases.items():
            result = evaluate_risk_text(text)
            self.assertEqual(result["primary_type"], expected, text)
            self.assertTrue(result["fraud_type_id"], text)
            self.assertIn(expected, result["candidate_types"], text)

    def test_alias_features_do_not_create_unknown_warning(self):
        result = evaluate_risk_text("视频里像亲友，说急需借钱，不方便电话核实")
        self.assertIn("拒绝二次核验", result["risk_features"])
        self.assertIn("AI换脸冒充", result["risk_features"])
        self.assertFalse(result["warnings"])

    def test_case_study_route_stays_knowledge_and_live_risk_is_fast(self):
        case_text = "有人碰到了下面的情况：客服让你开启远程控制，此时最稳妥的第一步是什么？"
        case_route = _route_for_unified_assistant(case_text, "p0-case-study")
        self.assertEqual(case_route["workflow_mode"], "knowledge_answer")
        self.assertTrue(case_route["is_case_study"])
        self.assertFalse(case_route["is_personal_risk_scene"])

        live_route = _route_for_unified_assistant(
            "我遇到客服让我打开会议软件，现在正在屏幕共享",
            "p0-live-risk",
        )
        self.assertEqual(live_route["workflow_mode"], "risk_case_flow")
        self.assertTrue(live_route["deterministic_risk_route"])
        self.assertEqual(live_route["first_response_mode"], "structured_safety_card")

    def test_concrete_knowledge_template_has_typed_evidence_contract(self):
        answer = _build_local_knowledge_answer(
            "什么是票务诈骗？",
            "definition",
            [{"fraud_type": "校园二手/票务交易诈骗"}],
            [],
        )
        self.assertTrue(_knowledge_answer_satisfies_contract(answer, "校园二手/票务交易诈骗", [], ""))
        self.assertIn("为什么这样判断", answer)
        self.assertIn("安全原则", answer)

    def _risk_analysis(self):
        return {
            "scene": {"is_risk_scene": True, "reason": "用户正在被要求付款"},
            "facts": {
                "requested_actions": ["继续转账"],
                "current_dangerous_actions": ["继续转账"],
                "user_actions": {
                    "has_paid": "true",
                    "has_unrecovered_money_loss": "true",
                    "has_shared_code": "unknown",
                    "has_screen_shared_or_remote_control": "unknown",
                },
                "loss": {"loss_confirmed": "true", "loss_type": "money"},
                "evidence": ["派单客服要求补单", "提现前继续交费"],
            },
            "fraud": {
                "primary_type": "刷单返利诈骗",
                "candidate_types": ["刷单返利诈骗"],
                "matched_feature_names": ["要求垫付资金", "已发生转账"],
            },
            "urgency": "urgent",
        }

    def test_safety_card_and_bad_llm_answer_fallback(self):
        analysis = self._risk_analysis()
        decision = decide_risk_from_analysis(analysis)
        card = build_structured_safety_card(analysis, decision)
        self.assertEqual(card["required_categories"], [
            "stop_current_action",
            "official_verification",
            "preserve_evidence",
            "post_loss_response",
        ])

        class BadResponse:
            content = "请注意风险。"

        class BadClient:
            def invoke(self, *_args, **_kwargs):
                return BadResponse()

        with patch("app.query_process.services.semantic_risk_agent.get_llm_client", return_value=BadClient()):
            answer = generate_realtime_answer(
                {"original_query": "我已经转账了", "is_stream": False},
                analysis,
                decision,
                {},
            )
        self.assertIn("刷单返利诈骗", answer)
        self.assertIn("止付", answer)
        self.assertIn("官方", answer)
        self.assertIn("保存", answer)
        self.assertEqual(_deterministic_realtime_answer({"original_query": ""}, analysis, decision), answer)


if __name__ == "__main__":
    unittest.main()
