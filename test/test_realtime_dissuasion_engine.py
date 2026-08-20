import unittest
from unittest.mock import patch

from app.query_process.services.knowledge_repository import KnowledgeRepository, clear_knowledge_cache
from app.query_process.services.realtime_dissuasion_engine import build_realtime_dissuasion


class RealtimeDissuasionEngineTest(unittest.TestCase):
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

    def _build(self, rule_result, slots=None):
        return build_realtime_dissuasion(rule_result, slots or {}, {}, repository=self.repo)

    def _assert_enabled(self, result, warning, goal):
        self.assertTrue(result["enabled"])
        self.assertEqual(result["primary_warning"], warning)
        self.assertEqual(result["goal"], goal)
        self.assertTrue(result["immediate_actions"])
        self.assertIn("evidence", result)
        self.assertIn("followup_question", result)

    def test_brush_rebate_with_small_return_and_withdrawal_blocked(self):
        result = self._build({
            "fraud_type": "刷单返利诈骗",
            "risk_stage": "提现受阻阶段",
            "risk_score": 100,
            "risk_level": "高风险",
            "intervention_goal": "stop_transfer",
            "advice_template_id": "ADV_BRUSH_HIGH_001",
            "matched_rules": ["RULE_BRUSH_CORE_001"],
            "evidence": ["点赞任务", "前两单返了钱", "垫付3000", "才能提现"],
        })

        self._assert_enabled(result, "先不要转账或继续补单。", "stop_transfer")
        self.assertIn("ADV_BRUSH_HIGH_001", result["knowledge_used"]["template_id"])
        self.assertIn("LAW_PRE_TRANSFER_DISSUASION_001", result["knowledge_used"]["law_ids"])

    def test_fake_customer_service_screen_share_and_code(self):
        result = self._build({
            "fraud_type": "冒充客服诈骗",
            "risk_stage": "屏幕共享阶段",
            "risk_score": 94,
            "risk_level": "高风险",
            "intervention_goal": "stop_screen_share",
            "advice_template_id": "ADV_SERVICE_SCREEN_HIGH_001",
            "evidence": ["退款", "会议软件", "屏幕共享", "验证码"],
        })

        self._assert_enabled(result, "请立刻退出会议或关闭屏幕共享。", "stop_screen_share")
        self.assertEqual(result["dissuasion_level"], "emergency")
        self.assertIn("LAW_SCREEN_SHARE_DISSUASION_001", result["knowledge_used"]["law_ids"])

    def test_fake_customer_service_code_only_does_not_use_screen_share_goal(self):
        result = self._build({
            "fraud_type": "冒充客服诈骗",
            "risk_stage": "验证码索取阶段",
            "risk_score": 94,
            "risk_level": "高风险",
            "intervention_goal": "stop_screen_share",
            "advice_template_id": "ADV_SERVICE_SCREEN_HIGH_001",
            "risk_features": ["冒充客服", "索要验证码"],
            "evidence": ["退款", "短信验证码"],
        })

        self._assert_enabled(result, "不要发送验证码。", "stop_code_leak")
        self.assertEqual(result["knowledge_used"]["template_id"], "ADV_CODE_HIGH_001")

    def test_job_training_fee_prefers_transfer_goal_over_generic_code_goal(self):
        result = self._build({
            "fraud_type": "求职实习招聘诈骗",
            "risk_stage": "资金转账前阶段",
            "risk_score": 93,
            "risk_level": "高风险",
            "intervention_goal": "stop_code_leak",
            "advice_template_id": "ADV_CODE_HIGH_001",
            "risk_features": ["轻松高薪诱导", "入职前收费"],
            "evidence": ["新媒体运营就业班", "推荐实习", "培训费", "不就业全额退款"],
        })

        self._assert_enabled(result, "先不要交押金、培训费，也不要办理培训贷。", "stop_transfer")
        self.assertEqual(result["knowledge_used"]["template_id"], "ADV_JOB_FEE_HIGH_001")

    def test_fake_police_safe_account_transfer(self):
        result = self._build({
            "fraud_type": "冒充公检法诈骗",
            "risk_stage": "资金转账前阶段",
            "risk_score": 99,
            "risk_level": "高风险",
            "intervention_goal": "stop_transfer",
            "advice_template_id": "ADV_POLICE_HIGH_001",
            "evidence": ["涉嫌洗钱", "安全账户", "转账自证清白"],
        })

        self._assert_enabled(result, "先不要向任何所谓安全账户转账。", "stop_transfer")

    def test_fake_investment_teacher_high_return_withdrawal_blocked(self):
        result = self._build({
            "fraud_type": "虚假投资理财诈骗",
            "risk_stage": "提现受阻阶段",
            "risk_score": 95,
            "risk_level": "高风险",
            "intervention_goal": "stop_transfer",
            "advice_template_id": "ADV_INVEST_HIGH_001",
            "evidence": ["老师带单", "高收益", "提现失败", "缴税费"],
        })

        self._assert_enabled(result, "先不要继续入金或缴纳任何提现费用。", "stop_transfer")

    def test_fake_loan_pre_fee(self):
        result = self._build({
            "fraud_type": "网络贷款诈骗",
            "risk_stage": "资金转账前阶段",
            "risk_score": 93,
            "risk_level": "高风险",
            "intervention_goal": "stop_transfer",
            "advice_template_id": "ADV_LOAN_HIGH_001",
            "evidence": ["放款前", "保证金", "解冻费"],
        })

        self._assert_enabled(result, "先不要交保证金、解冻费或刷流水。", "stop_transfer")

    def test_phishing_link_bank_id_code(self):
        result = self._build({
            "fraud_type": "钓鱼链接诈骗",
            "risk_stage": "验证码索取阶段",
            "risk_score": 90,
            "risk_level": "高风险",
            "intervention_goal": "stop_click_link",
            "advice_template_id": "ADV_PHISHING_HIGH_001",
            "evidence": ["陌生链接", "银行卡", "身份证", "验证码"],
        })

        self._assert_enabled(result, "不要点击或继续填写这个链接。", "stop_click_link")

    def test_ai_face_video_borrow(self):
        result = self._build({
            "fraud_type": "AI换脸冒充熟人诈骗",
            "risk_stage": "资金转账前阶段",
            "risk_score": 88,
            "risk_level": "高风险",
            "intervention_goal": "stop_transfer",
            "advice_template_id": "ADV_AI_FACE_HIGH_001",
            "evidence": ["视频通话", "声音很像", "急用钱", "马上转账"],
        })

        self._assert_enabled(result, "先不要转账。", "stop_transfer")
        self.assertIn("LAW_PRE_TRANSFER_DISSUASION_001", result["knowledge_used"]["law_ids"])

    def test_unknown_app_install_has_local_law_guide(self):
        result = self._build({
            "fraud_type": "虚假投资理财诈骗",
            "risk_stage": "下载陌生 App 阶段",
            "risk_score": 90,
            "risk_level": "高风险",
            "intervention_goal": "stop_app_install",
            "risk_features": ["诱导下载陌生APP", "陌生投资平台"],
            "evidence": ["陌生App", "投资平台"],
        })

        self._assert_enabled(result, "不要下载或安装对方指定的陌生App。", "stop_app_install")
        self.assertIn("LAW_APP_INSTALL_RISK_001", result["knowledge_used"]["law_ids"])

    def test_meeting_software_download_request_prefers_app_install_block(self):
        result = self._build(
            {
                "fraud_type": "冒充客服诈骗",
                "risk_stage": "下载陌生 App 阶段",
                "risk_score": 90,
                "risk_level": "高风险",
                "intervention_goal": "stop_screen_share",
                "risk_features": ["客服", "退款", "会议软件"],
                "evidence": ["客服", "退款", "下载会议软件"],
            },
            slots={"current_requested_action": "下载会议软件"},
        )

        self._assert_enabled(result, "不要下载或安装对方指定的陌生App。", "stop_app_install")

    def test_payment_request_after_app_install_prioritizes_transfer_blocking(self):
        result = self._build(
            {
                "fraud_type": "网络贷款诈骗",
                "risk_stage": "提现受阻阶段",
                "risk_score": 94,
                "risk_level": "高风险",
                "intervention_goal": "stop_app_install",
                "risk_features": ["诱导下载陌生APP", "要求缴纳解冻费", "贷款前收费"],
                "evidence": ["贷款App", "保证金", "解冻费"],
            },
            slots={"has_downloaded_app": "true", "current_requested_action": "缴纳解冻费"},
        )

        self._assert_enabled(result, "先不要交保证金、解冻费或刷流水。", "stop_transfer")

    def test_already_transferred_upgrades_to_call_police(self):
        result = self._build(
            {
                "fraud_type": "刷单返利诈骗",
                "risk_stage": "提现受阻阶段",
                "risk_score": 90,
                "risk_level": "高风险",
                "intervention_goal": "stop_transfer",
                "advice_template_id": "ADV_BRUSH_HIGH_001",
                "evidence": ["已经转账", "继续补单"],
            },
            slots={"has_paid": "true"},
        )

        self._assert_enabled(result, "现在先止损，不要继续给对方任何钱或信息。", "call_police")
        self.assertEqual(result["dissuasion_level"], "emergency")
        self.assertTrue(result["knowledge_used"]["law_ids"])

    def test_code_leaked_upgrades_to_emergency(self):
        result = self._build(
            {
                "fraud_type": "冒充客服诈骗",
                "risk_stage": "验证码索取阶段",
                "risk_score": 92,
                "risk_level": "高风险",
                "intervention_goal": "stop_screen_share",
                "advice_template_id": "ADV_SERVICE_SCREEN_HIGH_001",
                "evidence": ["退款", "验证码已经发给对方"],
            },
            slots={"has_shared_code": "true"},
        )

        self._assert_enabled(result, "不要发送验证码。", "stop_code_leak")
        self.assertEqual(result["dissuasion_level"], "emergency")

    def test_local_law_guides_are_merged_when_mongo_has_unrelated_rows(self):
        self.mongo_patch.stop()

        class _Cursor:
            def sort(self, *args, **kwargs):
                return self

            def limit(self, *args, **kwargs):
                return self

            def __iter__(self):
                return iter([
                    {
                        "law_id": "LAW_UNRELATED",
                        "related_behaviors": ["无关行为"],
                        "title": "无关条款",
                    }
                ])

        class _Collection:
            def find(self, *args, **kwargs):
                return _Cursor()

        class _Tool:
            db = {"law_clauses": _Collection()}

        try:
            with patch("app.query_process.services.knowledge_repository.get_business_mongo_tool", return_value=_Tool()):
                repo = KnowledgeRepository()
                result = build_realtime_dissuasion(
                    {
                        "fraud_type": "冒充客服诈骗",
                        "risk_stage": "验证码索取阶段",
                        "risk_score": 92,
                        "risk_level": "高风险",
                        "intervention_goal": "stop_code_leak",
                        "advice_template_id": "ADV_CODE_HIGH_001",
                        "evidence": ["短信验证码"],
                    },
                    {},
                    {},
                    repository=repo,
                )
        finally:
            self.mongo_patch.start()

        self.assertIn("LAW_CODE_LEAK_001", result["knowledge_used"]["law_ids"])

    def test_knowledge_only_query_does_not_trigger_realtime_dissuasion(self):
        result = self._build({
            "fraud_type": "刷单返利诈骗",
            "risk_stage": "科普学习",
            "risk_score": 20,
            "risk_level": "低风险",
            "intervention_goal": "ask_clarification",
            "evidence": ["刷单返利是什么"],
        })

        self.assertFalse(result["enabled"])
        self.assertEqual(result["goal"], "ask_clarification")

    def test_brush_rebate_pre_loss_defaults_to_stop_transfer(self):
        result = self._build({
            "fraud_type": "刷单返利诈骗",
            "risk_stage": "建立信任阶段",
            "risk_score": 85,
            "risk_level": "高风险",
            "intervention_goal": "ask_clarification",
            "risk_features": ["任务返佣", "承诺返利"],
            "evidence": ["刷单", "返钱"],
        })

        self._assert_enabled(result, "先不要转账或继续补单。", "stop_transfer")


if __name__ == "__main__":
    unittest.main()
