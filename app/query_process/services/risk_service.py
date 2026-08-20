from typing import Any, Dict, List

from app.query_process.services.anti_fraud_engine import build_anti_fraud_engine_result
from app.query_process.services.scam_rule_engine import (
    evaluate_rule_text,
    infer_fraud_types,
    risk_level_from_score,
)
from app.query_process.services.suspicious_rules import (
    analyze_keyword_blacklist,
    analyze_url_features,
    build_report_advice,
    score_suspicious_item,
)


def _public_safety_card(result: Dict[str, Any]) -> Dict[str, Any]:
    """Expose the same executable action categories as the realtime agent."""
    score = int(result.get("risk_score", 0) or 0)
    active = score >= 30
    has_exposure = any(
        feature in set(result.get("risk_features") or [])
        for feature in ["已发生转账", "索要验证码", "屏幕共享", "远程控制", "诱导下载陌生APP", "索要银行卡或身份信息"]
    )
    stop = ["在身份和交易未通过官方渠道核验前，先暂停付款、充值、补单和信息提交"]
    if "屏幕共享" in (result.get("risk_features") or []) or "远程控制" in (result.get("risk_features") or []):
        stop.insert(0, "立即关闭屏幕共享/远程控制并退出对方要求打开的 App")
    return {
        "version": "safety-card-v1",
        "status": "active" if active else "not_applicable",
        "risk_stage": result.get("risk_stage", ""),
        "fraud_type_id": result.get("fraud_type_id", ""),
        "stop_current_action": stop,
        "official_verification": ["通过官方 App、官网客服电话或线下机构独立核验，不使用对方提供的联系方式"],
        "preserve_evidence": ["保存聊天记录、来电号码、链接、账号、收款码和转账凭证"],
        "post_loss_response": ["如已付款或泄露信息，立即联系银行/支付平台申请止付、冻结或改密，并拨打 110/96110"] if has_exposure else [],
        "required_categories": [
            "stop_current_action",
            "official_verification",
            "preserve_evidence",
            *( ["post_loss_response"] if has_exposure else []),
        ],
    }


def evaluate_risk_text(text: str) -> Dict[str, Any]:
    result = evaluate_rule_text(text)
    has_identified_risk = int(result.get("risk_score", 0) or 0) >= 30 or str(result.get("fraud_type") or "") not in {
        "",
        "未知",
        "暂未识出诈骗风险",
        "暂未识别诈骗风险",
    }
    response = {
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "scam_type": result["scam_type"],
        "fraud_type": result["fraud_type"],
        "fraud_type_id": result.get("fraud_type_id", ""),
        "primary_type": result.get("primary_type", result.get("fraud_type", "")),
        "candidate_types": result.get("candidate_types", []),
        "candidate_type_ids": result.get("candidate_type_ids", []),
        "type_candidates": result.get("type_candidates", []),
        "type_confidence": result.get("type_confidence", result.get("confidence", 0.0)),
        "confidence": result.get("confidence", result.get("type_confidence", 0.0)),
        "risk_stage": result["risk_stage"],
        "possible_fraud_types": result["possible_fraud_types"],
        "risk_features": result["risk_features"],
        "normalized_risk_features": result["normalized_risk_features"],
        "matched_rules": result["matched_rules"],
        "evidence": result["evidence"],
        "intervention_goal": result["intervention_goal"],
        "advice_template_id": result.get("advice_template_id", ""),
        "advice": result["advice"],
        "next_actions": result["next_actions"],
        "entities": result["entities"],
        "engine_version": result["engine_version"],
        "warnings": result["warnings"],
        "safety_card": _public_safety_card(result),
    }
    response["anti_fraud_engine"] = build_anti_fraud_engine_result(
        input_text=text,
        route_decision={
            "primary_intent": "risk_help" if has_identified_risk else "risk_fact_clarification",
            "workflow_mode": "risk_case_flow",
            "confidence": 1.0,
            "reason": "public risk check",
        },
        risk_result=result,
    )
    response["risk_judgement_card"] = response["anti_fraud_engine"].get("risk_judgement_card", {})
    return response


def check_url_content(content: str) -> Dict[str, Any]:
    url_result = analyze_url_features(content)
    keyword_result = analyze_keyword_blacklist(content)
    risk = score_suspicious_item(url_result, keyword_result)
    score = int(risk.get("risk_score", 0) or 0)
    risk_rules: List[str] = []
    for item in (url_result.get("matched_rules") or []) + (keyword_result.get("matched_rules") or []):
        if item not in risk_rules:
            risk_rules.append(item)
    advice_list = build_report_advice(url_result, keyword_result, score)
    response = {
        "risk_score": score,
        "risk_level": risk_level_from_score(score),
        "risk_rules": risk_rules,
        "url_rules": url_result.get("matched_rules", []),
        "keyword_rules": keyword_result.get("matched_rules", []),
        "urls": url_result.get("urls", []),
        "should_click": score < 30,
        "suggest_report": score >= 30,
        "advice": "；".join(advice_list)
        if score >= 30
        else "未发现明显高危 URL 特征，但仍建议通过官方 App 或官网入口访问。",
    }
    response["anti_fraud_engine"] = build_anti_fraud_engine_result(
        input_text=content,
        route_decision={
            "primary_intent": "url_check",
            "workflow_mode": "url_check",
            "confidence": 1.0,
            "reason": "public url/content check",
        },
        url_result=response,
    )
    response["risk_judgement_card"] = response["anti_fraud_engine"].get("risk_judgement_card", {})
    return response
