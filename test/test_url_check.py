import unittest

from app.query_process.services.risk_service import check_url_content


class UrlCheckTest(unittest.TestCase):
    def test_high_risk_url_detects_multiple_signals(self):
        result = check_url_content(
            "http://bank-login-security-check.example.com 要求填写银行卡、身份证和验证码"
        )
        self.assertGreaterEqual(result["risk_score"], 60)
        self.assertFalse(result["should_click"])
        self.assertTrue(result["suggest_report"])
        self.assertIn("不要点击", result["advice"])

    def test_normal_url_remains_low_risk(self):
        result = check_url_content("请通过官方App查看账单。")
        self.assertEqual(result["risk_score"], 0)
        self.assertTrue(result["should_click"])


if __name__ == "__main__":
    unittest.main()
