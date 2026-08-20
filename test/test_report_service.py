import unittest
from unittest.mock import patch

from app.report_process.services.desensitize_service import desensitize_text
from app.report_process.services.report_service import create_report


class ReportServiceTest(unittest.TestCase):
    def test_desensitize_masks_sensitive_values(self):
        text = "手机号13812345678，身份证330102200101011234，银行卡6222021234567890，验证码123456"
        masked = desensitize_text(text)
        self.assertIn("138****5678", masked)
        self.assertIn("330102********1234", masked)
        self.assertIn("622202********7890", masked)
        self.assertIn("验证码：******", masked)

    def test_create_report_persists_sanitized_ticket(self):
        fake_risk = {
            "risk_score": 82,
            "risk_level": "高风险",
            "scam_type": "钓鱼链接诈骗",
            "matched_rules": [],
            "advice": "不要点击链接。",
        }
        fake_url = {
            "risk_score": 80,
            "risk_level": "高风险",
            "risk_rules": ["使用非 HTTPS 链接"],
            "advice": "不要点击该链接。",
        }
        with patch("app.report_process.services.report_service.count_report_tickets_for_day", return_value=0), \
             patch("app.report_process.services.report_service.evaluate_risk_text", return_value=fake_risk), \
             patch("app.report_process.services.report_service.check_url_content", return_value=fake_url), \
             patch("app.report_process.services.report_service.create_report_ticket") as create_ticket, \
             patch("app.report_process.services.report_service.write_audit_log"):
            report = create_report({
                "report_type": "链接",
                "content": "http://bad.example 验证码123456 手机号13812345678",
                "platform": "短信",
                "has_paid": False,
                "amount": "",
                "contact": "13812345678",
                "note": "银行卡6222021234567890",
            })

        self.assertTrue(report["report_id"].startswith("FS-"))
        self.assertEqual(report["risk_level"], "极高风险")
        self.assertIn("evidence_checklist", report)
        create_ticket.assert_called_once()
        saved = create_ticket.call_args.args[0]
        self.assertIn("138****5678", saved["content"])
        self.assertIn("622202********7890", saved["note"])


if __name__ == "__main__":
    unittest.main()
