import unittest
from unittest.mock import patch

from app.query_process.agent.nodes.compact_workflow_core import (
    node_binary_risk_decision,
    node_case_context,
    node_intervention,
    node_scam_understanding,
)
from app.query_process.services.dynamic_response_planner import fallback_dynamic_answer
from app.query_process.services.safety_signal_extractor import extract_safety_signals
from app.query_process.services.scam_rule_engine import evaluate_rule_text


class DynamicSceneAgentTest(unittest.TestCase):
    def _run_to_intervention(self, text, history=None, route_decision=None):
        state = {
            "session_id": "",
            "history": history or [],
            "history_text": "",
            "original_query": text,
            "route_decision": route_decision or {"safety_signals": {"risky_requested_actions": []}},
        }
        for node in [node_case_context, node_scam_understanding, node_binary_risk_decision]:
            state = node(state)
        with patch("app.query_process.agent.nodes.compact_workflow_core._knowledge_lookup", return_value=[]):
            state = node_intervention(state)
        return state

    def test_roommate_new_wechat_password_code_uses_scene_facts(self):
        text = "我室友用一个新的微信号加我，叫我把我的微信密码告诉他，并且他要我的手机验证码，我还不知道那个新的号是不是我的室友"
        signals = extract_safety_signals(text)
        self.assertTrue(signals["requested_action_signal"])
        self.assertIn("提供账号密码/支付密码", [item["action"] for item in signals["risky_requested_actions"]])
        self.assertIn("提供验证码", [item["action"] for item in signals["risky_requested_actions"]])

        state = self._run_to_intervention(text, route_decision={"safety_signals": signals})
        frame = state["scenario_frame"]
        answer = fallback_dynamic_answer(state, frame, state["dialogue_policy"])

        self.assertEqual(frame["actor_claim"], "室友")
        self.assertEqual(frame["contact_channel"], "新微信号")
        self.assertIn("微信密码", "、".join(frame["requested_actions"]))
        self.assertIn("验证码", "、".join(frame["requested_actions"]))
        self.assertIn("室友", answer)
        self.assertIn("新微信号", answer)
        self.assertIn("密码", answer)
        self.assertIn("验证码", answer)
        self.assertNotIn("陌生人", answer)

    def test_prize_code_scenario_is_prize_plus_code_not_generic_template(self):
        text = "今天我收到一条短信显示我中奖100w，叫我之后收到验证码发给他领取"
        state = self._run_to_intervention(text)
        frame = state["scenario_frame"]
        answer = fallback_dynamic_answer(state, frame, state["dialogue_policy"])

        self.assertIn("虚假中奖/免费礼品诈骗", frame["likely_scam_types"])
        self.assertIn("验证码", frame["one_key_question"])
        self.assertIn("中奖", answer)
        self.assertIn("验证码", answer)
        self.assertNotIn("命中依据", answer)

    def test_plain_code_does_not_pull_unrelated_package_features(self):
        result = evaluate_rule_text("对方让我发验证码", context={"slots": {}})
        features = set(result["normalized_risk_features"])

        self.assertIn("索要验证码", features)
        self.assertNotIn("领奖填写银行卡验证码", features)
        self.assertNotIn("补贴验证码索取", features)
        self.assertNotIn("退改签索要验证码银行卡", features)


if __name__ == "__main__":
    unittest.main()
