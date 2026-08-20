import unittest
from unittest.mock import patch

from app.query_process.services.knowledge_repository import (
    KnowledgeRepository,
    clear_knowledge_cache,
)


class KnowledgeLookupTest(unittest.TestCase):
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

    def test_template_exact_id_has_highest_priority(self):
        template = self.repo.get_dissuasion_template(
            fraud_type="刷单返利诈骗",
            risk_stage="提现受阻阶段",
            intervention_goal="stop_transfer",
            risk_level="高风险",
            template_id="ADV_BRUSH_HIGH_001",
        )

        self.assertEqual(template["template_id"], "ADV_BRUSH_HIGH_001")
        self.assertEqual(template["opening"], "先不要转账或继续补单。")

    def test_template_falls_back_by_goal(self):
        template = self.repo.get_dissuasion_template(
            fraud_type="不存在的诈骗类型",
            risk_stage="资金转账前阶段",
            intervention_goal="stop_transfer",
            risk_level="高风险",
        )

        self.assertEqual(template["template_id"], "FALLBACK_STOP_TRANSFER")
        self.assertEqual(template["intervention_goal"], "stop_transfer")

    def test_report_and_evidence_guides_use_specific_then_generic(self):
        report = self.repo.get_report_guide("url", "钓鱼链接诈骗")
        evidence = self.repo.get_evidence_guide("刷单返利诈骗", "提现受阻阶段")
        generic_evidence = self.repo.get_evidence_guide("未知类型", "未知阶段")

        self.assertEqual(report["guide_id"], "REPORT_URL_001")
        self.assertEqual(evidence["guide_id"], "EVIDENCE_BRUSH_001")
        self.assertEqual(generic_evidence["guide_id"], "EVIDENCE_COMMON_001")

    def test_prevention_cases_and_law_guides_available(self):
        advice = self.repo.get_prevention_advice("虚假投资理财诈骗", "提现受阻阶段", "stop_transfer")
        cases = self.repo.get_typical_cases("虚假投资理财诈骗", "提现受阻阶段")
        laws = self.repo.get_law_guides(["已发生转账", "证据保存"])

        self.assertTrue(advice)
        self.assertEqual(advice[0]["advice_id"], "PREVENT_INVEST_001")
        self.assertTrue(cases)
        self.assertTrue(any(item["law_id"] == "LAW_STOP_PAYMENT_001" for item in laws))


if __name__ == "__main__":
    unittest.main()
