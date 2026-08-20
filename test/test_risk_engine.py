import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.query_process.agent.nodes.node_rule_engine import _load_rules
from app.query_process.services.rule_config_manager import (
    list_rule_config_backups,
    rollback_rule_config,
    upsert_hot_rule_config,
)
from app.query_process.services.scam_rule_engine import evaluate_rule_state, load_scam_packages, reload_rule_config
from app.query_process.services.risk_service import evaluate_risk_text


class RiskEngineTest(unittest.TestCase):
    def setUp(self):
        self.patches = [
            patch("app.query_process.agent.nodes.node_rule_engine.get_enabled_risk_rules", return_value=[]),
            patch("app.query_process.agent.nodes.node_rule_engine.seed_risk_rules_from_json", return_value=0),
        ]
        for item in self.patches:
            item.start()
        _load_rules.cache_clear()
        load_scam_packages.cache_clear()

    def tearDown(self):
        _load_rules.cache_clear()
        load_scam_packages.cache_clear()
        for item in reversed(self.patches):
            item.stop()

    def test_high_risk_recall_from_sample_cases(self):
        cases = json.loads(Path("data/test_cases/risk_cases.json").read_text(encoding="utf-8"))
        high_cases = [item for item in cases if item.get("enabled", True) and item.get("expected_risk_score_min", 0) >= 60]
        hits = 0
        for case in high_cases:
            result = evaluate_risk_text(case["user_text"])
            if result["risk_score"] >= case["expected_risk_score_min"]:
                hits += 1
        self.assertGreaterEqual(hits / len(high_cases), 0.95)

    def test_rule_result_contains_intervention_metadata(self):
        result = evaluate_risk_text("有人让我做点赞任务，先垫付300元，做完返400元。")
        self.assertEqual(result["scam_type"], "刷单返利诈骗")
        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertTrue(result["matched_rules"])
        self.assertIn("intervention_goal", result["matched_rules"][0])
        self.assertTrue(result["evidence"])
        self.assertEqual(result["intervention_goal"], "stop_transfer")
        card = result["risk_judgement_card"]
        self.assertEqual(card["user_intent"]["name"], "风险求助")
        self.assertEqual(card["risk_scene"]["name"], "刷单返利诈骗")
        self.assertEqual(card["risk_stage"]["name"], "行为临界")
        self.assertIn(card["risk_level"]["name"], {"高风险", "紧急风险"})
        self.assertIn("要求垫付资金", card["evidence"]["features"])

    def test_brush_scam_keyword_overrides_broad_friend_alias(self):
        result = evaluate_risk_text("我最近加了一个好友，他叫我一起和她刷单，一单可以赚50，我已经刷了十几单了")

        self.assertEqual(result["scam_type"], "刷单返利诈骗")
        self.assertEqual(result["possible_fraud_types"][0], "刷单返利诈骗")
        self.assertIn("任务返佣", result["risk_features"])
        self.assertNotIn("引导投资博彩刷单", result["risk_features"])

    def test_romance_investment_context_keeps_package_feature(self):
        result = evaluate_risk_text("疑似杀猪盘，我网恋对象每天关心我，说带我投资虚拟币平台，保证高收益，还让我刷单一起赚钱。")

        self.assertEqual(result["scam_type"], "杀猪盘诈骗")
        self.assertIn("引导投资博彩刷单", result["risk_features"])
        self.assertIn("情感交友诱导投资诈骗", result["possible_fraud_types"])

    def test_customer_service_code_only_uses_code_intervention(self):
        result = evaluate_risk_text("自称平台客服说给我退款，让我把短信验证码发过去。")

        self.assertEqual(result["scam_type"], "冒充客服诈骗")
        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertTrue(result["matched_rules"])
        self.assertEqual(result["matched_rules"][0]["rule_id"], "PKG_SERVICE_CODE_001")
        self.assertEqual(result["intervention_goal"], "stop_code_leak")
        self.assertEqual(result["advice_template_id"], "ADV_CODE_HIGH_001")

    def test_customer_service_screen_share_uses_screen_intervention(self):
        result = evaluate_risk_text("客服让我下载会议软件，现在正在屏幕共享。")

        self.assertEqual(result["scam_type"], "冒充客服诈骗")
        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertTrue(result["matched_rules"])
        self.assertEqual(result["matched_rules"][0]["rule_id"], "PKG_SERVICE_SCREEN_001")
        self.assertEqual(result["intervention_goal"], "stop_screen_share")
        self.assertEqual(result["advice_template_id"], "ADV_SERVICE_SCREEN_HIGH_001")
        self.assertNotIn("退改签屏幕共享", result["risk_features"])
        self.assertNotIn("PKG_TRAVEL_REFUND_SCREEN_001", [rule["rule_id"] for rule in result["matched_rules"]])

    def test_conflict_matrix_keeps_specific_scene_and_goal(self):
        brush = evaluate_risk_text("什么是刷单诈骗，我正准备转保证金")

        self.assertEqual(brush["scam_type"], "刷单返利诈骗")
        self.assertEqual(brush["possible_fraud_types"][0], "刷单返利诈骗")
        self.assertNotIn("网络贷款诈骗", brush["possible_fraud_types"])
        self.assertEqual(brush["intervention_goal"], "stop_transfer")
        self.assertEqual(brush["matched_rules"][0]["rule_id"], "RULE_BRUSH_CORE_001")

        investment = evaluate_risk_text("老师带我投资虚拟币稳赚，让我下载App充值，现在提现失败还要交解冻费")

        self.assertEqual(investment["scam_type"], "虚假投资理财诈骗")
        self.assertEqual(investment["intervention_goal"], "stop_transfer")
        self.assertNotIn("网络贷款诈骗", investment["possible_fraud_types"])
        self.assertNotIn("杀猪盘诈骗", investment["possible_fraud_types"])
        self.assertNotIn("贷款前收费", investment["risk_features"])

        acquaintance = evaluate_risk_text("朋友换了新微信号，说不方便电话，让我先借他5000周转")

        self.assertEqual(acquaintance["scam_type"], "冒充熟人诈骗")
        self.assertGreaterEqual(acquaintance["risk_score"], 60)
        self.assertEqual(acquaintance["intervention_goal"], "stop_transfer")
        self.assertEqual(acquaintance["matched_rules"][0]["rule_id"], "RULE_ACQUAINTANCE_CORE_001")

    def test_job_employment_class_training_fee_uses_job_dissuasion(self):
        result = evaluate_risk_text("新媒体运营就业班说学完推荐实习月薪8000，先交16800培训费，不就业全额退款。")

        self.assertEqual(result["scam_type"], "求职实习招聘诈骗")
        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertTrue(result["matched_rules"])
        self.assertEqual(result["matched_rules"][0]["rule_id"], "PKG_JOB_FEE_HIGH_001")
        self.assertEqual(result["intervention_goal"], "stop_transfer")
        self.assertEqual(result["advice_template_id"], "ADV_JOB_FEE_HIGH_001")

    def test_multiturn_customer_service_code_request_keeps_code_goal(self):
        state = {
            "original_query": "现在让我把短信验证码发过去。",
            "history": [
                {"role": "user", "text": "有个自称平台客服的人说可以给我退款。"},
            ],
            "slots": {},
        }

        result = evaluate_rule_state(state)

        self.assertEqual(result["scam_type"], "冒充客服诈骗")
        self.assertEqual(result["matched_rules"][0]["rule_id"], "PKG_SERVICE_CODE_001")
        self.assertEqual(result["intervention_goal"], "stop_code_leak")
        self.assertEqual(result["advice_template_id"], "ADV_CODE_HIGH_001")

    def test_multiturn_job_refund_word_keeps_job_training_fee_goal(self):
        state = {
            "original_query": "他们说先交16800培训费，不就业全额退款。",
            "history": [
                {"role": "user", "text": "我看到一个新媒体运营就业班，说学完可以推荐实习，月薪8000。"},
            ],
            "slots": {},
        }

        result = evaluate_rule_state(state)

        self.assertEqual(result["scam_type"], "求职实习招聘诈骗")
        self.assertEqual(result["matched_rules"][0]["rule_id"], "PKG_JOB_FEE_HIGH_001")
        self.assertEqual(result["intervention_goal"], "stop_transfer")
        self.assertEqual(result["advice_template_id"], "ADV_JOB_FEE_HIGH_001")

    def test_route_prefill_fraud_candidate_can_anchor_rule_state(self):
        state = {
            "original_query": "他们说先交16800培训费，不就业全额退款。",
            "history": [],
            "slots": {},
            "route_decision": {
                "risk_prefill": {"fraud_candidates": ["求职实习招聘诈骗"]},
                "semantic_frame": {"fraud_candidates": ["求职实习招聘诈骗"]},
            },
        }

        result = evaluate_rule_state(state)

        self.assertEqual(result["scam_type"], "求职实习招聘诈骗")
        self.assertEqual(result["matched_rules"][0]["rule_id"], "PKG_JOB_FEE_HIGH_001")
        self.assertEqual(result["intervention_goal"], "stop_transfer")

    def test_scam_package_adds_ai_face_scam_without_core_code_rule(self):
        result = evaluate_risk_text("朋友视频通话说急用钱，声音很像本人，让我马上转账还说不要告诉别人。")

        self.assertEqual(result["scam_type"], "AI换脸冒充熟人诈骗")
        self.assertGreaterEqual(result["risk_score"], 80)
        self.assertTrue(result["matched_rules"])
        self.assertEqual(result["matched_rules"][0]["rule_id"], "RULE_AI_FACE_FAMILY_001")
        self.assertEqual(result["intervention_goal"], "stop_transfer")

    def test_knowledge_style_question_stays_low_risk(self):
        result = evaluate_risk_text("老师让我们写反诈作业，刷单返利诈骗是什么意思？")

        self.assertLess(result["risk_score"], 30)
        self.assertEqual(result["scam_type"], "刷单返利诈骗")
        self.assertFalse(result["matched_rules"])

    def test_rule_state_does_not_turn_memory_summary_into_current_evidence(self):
        state = {
            "original_query": "我目前没有转过钱，这个靠谱吗，我可以赚钱吗",
            "history": [
                {"role": "user", "text": "我看到了QQ有一个好友和我说 让我帮他刷单 给我返钱 这靠谱吗"},
            ],
            "memory_summary": "系统曾提醒不要屏幕共享、不要给验证码、不要继续转账。",
            "rewritten_query": "用户追问刷单返利是否靠谱，系统应解释风险，不要注入屏幕共享。",
            "slots": {
                "has_paid": "false",
                "has_screen_share": "false",
                "has_shared_code": "false",
            },
            "risk_features": ["屏幕共享", "已发生转账"],
            "normalized_risk_features": ["屏幕共享", "已发生转账"],
        }

        result = evaluate_rule_state(state)

        self.assertIn("任务返佣", result["risk_features"])
        self.assertIn("承诺返利", result["risk_features"])
        self.assertNotIn("已发生转账", result["risk_features"])
        self.assertNotIn("屏幕共享", result["risk_features"])
        self.assertNotIn("远程控制", result["risk_features"])

    def test_case_fact_text_isolates_followup_from_older_risk_history(self):
        state = {
            "original_query": "那我现在应该怎么办",
            "history": [
                {"role": "user", "text": "我最近加了一个好友，他叫我刷单，一单赚50，我已经刷了十几单"},
            ],
            "case_fact_text": "最近我手机有一个消息说我中奖了，我点进去那个链接，他要我提供身份证信息，我给他提供了",
            "slots": {"has_clicked_link": "true", "has_provided_identity_or_bank": "true"},
        }

        result = evaluate_rule_state(state)

        self.assertNotIn("刷单返利诈骗", result["possible_fraud_types"])
        self.assertNotIn("任务返佣", result["risk_features"])
        self.assertIn("索要银行卡或身份信息", result["risk_features"])

    def test_rental_case_fact_text_overrides_older_prize_history(self):
        state = {
            "original_query": "那我现在还能把钱要回来吗？",
            "history": [
                {"role": "user", "text": "我最近加了一个好友，他叫我刷单，一单赚50"},
                {"role": "user", "text": "中奖链接要身份证，我给了"},
            ],
            "case_fact_text": "我在学校附近看房，遇到一个自称房东的人。他带我看了房，说房子很抢手，让我当天交押金。我已经交了",
            "slots": {"has_paid": "true"},
        }

        result = evaluate_rule_state(state)

        self.assertEqual(result["scam_type"], "租房合租押金诈骗")
        self.assertNotIn("刷单返利诈骗", result["possible_fraud_types"])
        self.assertNotIn("虚假中奖/免费礼品诈骗", result["possible_fraud_types"])

    def test_denied_brush_payment_does_not_create_repay_or_topup_feature(self):
        state = {
            "original_query": "我还没垫付，也没补单",
            "history": [],
            "case_fact_text": "我最近加了一个好友，他叫我一起和她刷单，一单可以赚50，我已经刷了十几单了 我还没垫付，也没补单",
            "slots": {"has_paid": "false"},
        }

        result = evaluate_rule_state(state)

        self.assertEqual(result["scam_type"], "刷单返利诈骗")
        self.assertNotIn("要求继续补单", result["risk_features"])
        self.assertNotIn("要求垫付资金", result["risk_features"])

    def test_realistic_verified_processes_remain_normal(self):
        cases = [
            "我在游戏自带市场挂了道具，钱先冻结在平台，买家确认后系统到账，全程没加联系方式。",
            "我在银行网点申请装修贷，柜台面签，合同写清利率，钱进本人卡，没有先交保证金。",
            "朋友当面跟我借两万，我们核对身份证和本人银行卡，也写了借条，后来按约还了第一期。",
        ]

        for text in cases:
            with self.subTest(text=text):
                result = evaluate_risk_text(text)
                self.assertEqual(result["risk_score"], 0)
                self.assertEqual(result["fraud_type"], "未知")

    def test_realistic_short_ambiguous_questions_require_clarification(self):
        for text in ["游戏里那个交易咋弄啊，急。", "客服说能退，我咋整？", "他换号了问我借点，能给吗？"]:
            with self.subTest(text=text):
                result = evaluate_risk_text(text)
                self.assertEqual(result["risk_score"], 0)
                self.assertEqual(result["fraud_type"], "未知")
                self.assertEqual(result["intervention_goal"], "ask_clarification")

    def test_realistic_behavior_combinations_use_upstream_scene(self):
        police = evaluate_risk_text(
            "我在视频会议里，对方让我把几张卡的余额都念出来，还开着共享，下一步要做归集，也不让我开门。"
        )
        game = evaluate_risk_text("买家让我装远程看号的软件看仓库，解绑短信到了还要我念给他。")
        ai_acquaintance = evaluate_risk_text(
            "舅舅视频让我替他打款，脸有点卡只会点头，不肯说暗号，收款人也不是他。"
        )

        self.assertEqual(police["primary_type"], "冒充公检法诈骗")
        self.assertGreaterEqual(police["risk_score"], 80)
        self.assertEqual(police["intervention_goal"], "stop_screen_share")
        self.assertEqual(game["primary_type"], "游戏交易诈骗")
        self.assertGreaterEqual(game["risk_score"], 80)
        self.assertEqual(ai_acquaintance["primary_type"], "AI换脸冒充熟人诈骗")
        self.assertGreaterEqual(ai_acquaintance["risk_score"], 80)

    def test_hot_rule_config_can_reload_and_rollback_keyword_rule(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch.dict("os.environ", {"ANTI_FRAUD_RULES_DIR": temp_dir}),
                patch("app.query_process.services.scam_rule_engine._load_rules", return_value=[]),
            ):
                reload_rule_config()

                base_rule = {
                    "rule_id": "R_REFUND_HOT_001",
                    "risk_scene": "冒充客服退款诈骗",
                    "conditions": {
                        "must_include_any": [
                            ["客服", "商家", "快递", "平台"],
                            ["退款", "理赔", "订单异常"],
                            ["会议软件", "屏幕共享", "验证码", "银行卡"],
                        ]
                    },
                    "score": 70,
                    "min_level": "高风险",
                    "intervention_action": "stop_screen_sharing",
                    "explanation": "命中冒充客服退款高危组合：客服身份 + 退款理由 + 远程控制或敏感信息索取。",
                }
                saved = upsert_hot_rule_config(base_rule)
                self.assertTrue(saved["hot_reloaded"])

                result = evaluate_risk_text("快递客服说订单异常要退款，让我打开会议软件共享屏幕。")
                self.assertEqual(result["matched_rules"][0]["rule_id"], "R_REFUND_HOT_001")
                self.assertEqual(result["scam_type"], "冒充客服退款诈骗")
                self.assertEqual(result["matched_rules"][0]["risk_score"], 70)
                self.assertEqual(result["intervention_goal"], "stop_screen_share")
                self.assertEqual(result["matched_rules"][0]["matched_keywords"], ["客服", "退款", "会议软件"])

                updated_rule = {**base_rule, "score": 88}
                updated = upsert_hot_rule_config(updated_rule)
                self.assertTrue(updated["backup_id"])
                result_after_update = evaluate_risk_text("快递客服说订单异常要退款，让我打开会议软件共享屏幕。")
                self.assertEqual(result_after_update["matched_rules"][0]["risk_score"], 88)

                backups = list_rule_config_backups("runtime_hot_rules")
                self.assertGreaterEqual(backups["total"], 1)
                rollback_rule_config(updated["backup_id"])
                result_after_rollback = evaluate_risk_text("快递客服说订单异常要退款，让我打开会议软件共享屏幕。")
                self.assertEqual(result_after_rollback["matched_rules"][0]["risk_score"], 70)

                load_scam_packages.cache_clear()
                _load_rules.cache_clear()


if __name__ == "__main__":
    unittest.main()
