from app.modules.suspicious_report.report_intel import validate_report_intel
from app.modules.suspicious_report.rules import (
    analyze_keyword_blacklist,
    analyze_url_features,
    build_report_advice,
    classify_suspicious_type,
    score_suspicious_item,
)


def _evaluate(text: str):
    url_result = analyze_url_features(text)
    keyword_result = analyze_keyword_blacklist(text)
    risk = score_suspicious_item(url_result, keyword_result)
    return url_result, keyword_result, risk, classify_suspicious_type(url_result, keyword_result)


def test_report_intel_database_is_valid():
    assert validate_report_intel() == []


def test_fake_loan_upfront_fee_is_high_risk():
    text = "无抵押秒到账贷款，对方说银行卡填错了，要先交服务费和解冻费，还让我提供身份证、银行卡和验证码。"
    _, _, risk, fraud_type = _evaluate(text)
    assert risk["risk_score"] >= 90
    assert "虚假网络贷款诈骗" in fraud_type


def test_brush_rebate_withdraw_blocked_is_high_risk():
    text = "我在群里刷单做任务，前几单返了钱，后来让我垫付联单，现在提现失败，说要补单交解冻费。"
    _, _, risk, fraud_type = _evaluate(text)
    assert risk["risk_score"] >= 90
    assert "刷单返利诈骗" in fraud_type


def test_normal_deepseek_share_link_is_not_high_risk():
    text = "https://chat.deepseek.com/a/chat/s/4be7f388-bc73-496c-ba38-0868289f4f68"
    url_result, keyword_result, risk, fraud_type = _evaluate(text)
    assert url_result["urls"]
    assert keyword_result["rule_hits"] == []
    assert risk["risk_score"] <= 25
    assert fraud_type == "暂未识出诈骗风险"


def test_prize_plus_private_contact_is_high_risk():
    text = "恭喜中奖，复制链接领取奖品，加V联系客服领奖。"
    _, _, risk, fraud_type = _evaluate(text)
    assert risk["risk_score"] >= 80
    assert "中奖领奖钓鱼诈骗" in fraud_type


def test_prevention_statement_does_not_trigger_code_theft():
    text = "反诈科普：验证码不要告诉任何人。"
    _, keyword_result, risk, fraud_type = _evaluate(text)
    assert keyword_result["rule_hits"] == []
    assert risk["risk_score"] <= 25
    assert fraud_type == "暂未识出诈骗风险"


def test_advice_uses_report_intel_specific_guidance():
    text = "校园贷无抵押秒到账，平台先扣服务费，又说要交解冻费才能提现。"
    url_result, keyword_result, risk, _ = _evaluate(text)
    advice = build_report_advice(url_result, keyword_result, int(risk["risk_score"]))
    assert any("正规贷款不会" in item for item in advice)
