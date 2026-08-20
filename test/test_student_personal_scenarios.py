import unittest
from unittest.mock import patch

from app.query_process.agent.nodes.compact_workflow_core import TRUE, _extract_slots
from app.query_process.services.knowledge_repository import KnowledgeRepository, clear_knowledge_cache
from app.query_process.services.realtime_dissuasion_engine import build_realtime_dissuasion
from app.query_process.services.scam_rule_engine import evaluate_rule_text, load_scam_packages


class StudentPersonalScenarioTest(unittest.TestCase):
    def setUp(self):
        clear_knowledge_cache()
        load_scam_packages.cache_clear()
        self.mongo_patch = patch(
            "app.query_process.services.knowledge_repository.get_business_mongo_tool",
            side_effect=RuntimeError("mongo offline for test"),
        )
        self.mongo_patch.start()
        self.repo = KnowledgeRepository()

    def tearDown(self):
        self.mongo_patch.stop()
        clear_knowledge_cache()
        load_scam_packages.cache_clear()

    def _run(self, text):
        slots, _ = _extract_slots(text, text)
        rule_result = evaluate_rule_text(text, context={"slots": slots})
        realtime = build_realtime_dissuasion(rule_result, slots, {}, repository=self.repo)
        return slots, rule_result, realtime

    def test_game_asset_loss_routes_to_emergency_and_call_police(self):
        text = "我被我室友骗了20w，他人已经失联了，他叫我把游戏的装备给他，我已经都给他了，这里价值20w"
        slots, rule_result, realtime = self._run(text)

        self.assertEqual(slots["has_transferred_virtual_asset"], TRUE)
        self.assertEqual(slots["counterparty_disappeared"], TRUE)
        self.assertEqual(rule_result["fraud_type"], "游戏交易诈骗")
        self.assertEqual(rule_result["intervention_goal"], "call_police")
        self.assertTrue(realtime["enabled"])
        self.assertEqual(realtime["primary_warning"], "现在先按已发生财产损失处理，不要再给对方任何账号、装备或钱。")
        self.assertEqual(realtime["knowledge_used"]["template_id"], "ADV_GAME_ASSET_LOSS_001")

    def test_roommate_cheated_me_amount_routes_to_emergency(self):
        text = "我室友骗我了300w"
        slots, rule_result, realtime = self._run(text)

        self.assertEqual(slots["has_paid"], TRUE)
        self.assertGreaterEqual(rule_result["risk_score"], 90)
        self.assertEqual(rule_result["intervention_goal"], "call_police")
        self.assertTrue(realtime["enabled"])

    def test_requested_game_asset_delivery_is_pre_loss_not_emergency(self):
        text = "游戏群里有人叫我把装备先给他验货，再付钱给我，靠谱吗"
        slots, rule_result, realtime = self._run(text)

        self.assertNotEqual(slots["has_transferred_virtual_asset"], TRUE)
        self.assertEqual(rule_result["fraud_type"], "游戏交易诈骗")
        self.assertGreaterEqual(rule_result["risk_score"], 80)
        self.assertTrue(realtime["enabled"])
        self.assertEqual(realtime["goal"], "stop_transfer")

    def test_campus_fee_impersonation(self):
        text = "班级群里一个自称辅导员的人让扫码交资料费，说今天截止，直接微信转账"
        _, rule_result, realtime = self._run(text)

        self.assertEqual(rule_result["fraud_type"], "冒充老师辅导员收费诈骗")
        self.assertEqual(realtime["primary_warning"], "先不要扫码缴费或转账。")
        self.assertEqual(realtime["goal"], "stop_transfer")

    def test_job_training_loan(self):
        text = "实习内推说保offer，但入职前要先交培训费，还让我办培训贷"
        _, rule_result, realtime = self._run(text)

        self.assertEqual(rule_result["fraud_type"], "求职实习招聘诈骗")
        self.assertEqual(realtime["primary_warning"], "先不要交押金、培训费，也不要办理培训贷。")

    def test_scholarship_code_phishing(self):
        text = "有人说我的助学金到账异常，让我点链接填银行卡身份证和短信验证码"
        _, rule_result, realtime = self._run(text)

        self.assertEqual(rule_result["fraud_type"], "奖助学金/学费退费诈骗")
        self.assertEqual(realtime["goal"], "stop_code_leak")
        self.assertEqual(realtime["primary_warning"], "不要填写或发送验证码，也不要提交银行卡和身份证信息。")

    def test_two_cards_running_points(self):
        text = "兼职群说出租银行卡跑分一天几百，只要帮忙收款再转出去"
        _, rule_result, realtime = self._run(text)

        self.assertEqual(rule_result["fraud_type"], "两卡出租出借与跑分诈骗")
        self.assertEqual(realtime["goal"], "preserve_evidence")
        self.assertEqual(realtime["primary_warning"], "不要出租、出借或出售银行卡、电话卡、收款码和实名账号。")

    def test_travel_refund_screen_share(self):
        text = "客服说我的航班取消，要下载会议软件共享屏幕办理退票理赔"
        _, rule_result, realtime = self._run(text)

        self.assertEqual(rule_result["fraud_type"], "机票火车票退改签诈骗")
        self.assertEqual(realtime["goal"], "stop_screen_share")
        self.assertEqual(realtime["primary_warning"], "请立刻退出会议或关闭屏幕共享。")

    def test_nude_extortion_call_police(self):
        text = "我裸聊后对方拿偷拍视频和通讯录威胁我，不转账就发给同学"
        _, rule_result, realtime = self._run(text)

        self.assertEqual(rule_result["fraud_type"], "裸聊敲诈勒索诈骗")
        self.assertEqual(realtime["goal"], "call_police")
        self.assertEqual(realtime["primary_warning"], "现在先止损，不要再给对方转任何钱。")

    def test_two_cards_knowledge_query_does_not_trigger_emergency(self):
        _, rule_result, realtime = self._run("什么是两卡犯罪风险，怎么防范？")

        self.assertLess(rule_result["risk_score"], 80)
        self.assertFalse(realtime["enabled"])


if __name__ == "__main__":
    unittest.main()
