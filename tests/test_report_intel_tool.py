from app.modules.report_intel_tool import service


def _patch_storage():
    stored = {"drafts": {}, "tickets": []}

    def create_draft(draft):
        stored["drafts"][draft["analysis_id"]] = dict(draft)
        return draft

    def get_draft(analysis_id):
        return stored["drafts"].get(analysis_id)

    def update_draft(analysis_id, update):
        stored["drafts"][analysis_id].update(update)
        return stored["drafts"][analysis_id]

    def create_ticket(report):
        stored["tickets"].append(dict(report))
        return report

    service.create_report_analysis_draft = create_draft
    service.get_report_analysis_draft = get_draft
    service.update_report_analysis_draft = update_draft
    service.create_report_ticket = create_ticket
    service.count_report_tickets_for_day = lambda day: len(stored["tickets"])
    service.write_audit_log = lambda *args, **kwargs: None
    service.analyze_report_semantics = lambda content, url_result, keyword_result, risk_result: {
        "enabled": True,
        "status": "unavailable",
        "judge_source": "test",
        "input_kind": "free_text",
        "is_suspicious": False,
        "risk_score": 0,
        "risk_level": "风险未知",
        "suspected_scam_ids": [],
        "suspected_type": "暂未识出诈骗风险",
        "semantic_features": [],
        "reasoning_summary": "",
        "recommended_actions": [],
        "confidence": 0,
    }
    service._MEMORY_DRAFTS.clear()
    return stored


def test_report_intel_analyze_creates_independent_draft():
    stored = _patch_storage()
    result = service.analyze_report_content(
        "无抵押秒到账贷款，对方说要先交服务费和解冻费。",
        tool_session_id="report-tool-test",
    )
    assert result["analysis_id"]
    assert result["analysis_mode"] == "single_turn_content_judgement"
    assert result["report_intel"]["analysis_mode"] == "single_turn_content_judgement"
    assert result["report_intel"]["analysis_id"] == result["analysis_id"]
    assert result["tool_session_id"] == "report-tool-test"
    assert result["fraud_type"] == "虚假网络贷款诈骗"
    assert result["status"] == "draft_saved"
    assert "session_id" not in stored["drafts"][result["analysis_id"]]


def test_report_intel_confirm_writes_ticket_without_chat_session():
    stored = _patch_storage()
    analysis = service.analyze_report_content(
        "我刷单做任务，提现失败后对方让我补单交解冻费。",
        tool_session_id="report-tool-test",
    )
    confirmed = service.confirm_report_analysis(
        analysis["analysis_id"],
        tool_session_id="report-tool-test",
    )
    assert confirmed["report_id"].startswith("FS-")
    assert confirmed["status"] == "confirmed"
    assert stored["tickets"]
    ticket = stored["tickets"][0]
    assert ticket["analysis_id"] == analysis["analysis_id"]
    assert ticket["tool_session_id"] == "report-tool-test"
    assert ticket["session_id"] == ""
    assert ticket["source"] == "report_intel_modal"


def test_report_intel_llm_semantic_result_can_raise_rule_only_low_risk():
    _patch_storage()

    def fake_llm(content, url_result, keyword_result, risk_result):
        return {
            "enabled": True,
            "status": "completed",
            "judge_source": "test_llm",
            "input_kind": "url_with_text",
            "is_suspicious": True,
            "risk_score": 86,
            "risk_level": "极高风险",
            "suspected_scam_ids": ["scam_prize_phishing"],
            "suspected_type": "中奖领奖钓鱼诈骗",
            "semantic_features": [
                {
                    "rule_id": "LLM_SEMANTIC_1",
                    "label": "中奖诱导添加私域账号",
                    "feature_name": "中奖诱导添加私域账号",
                    "evidence": "中奖+v",
                    "score": 86,
                    "scam_id": "scam_prize_phishing",
                    "scam_type": "中奖领奖钓鱼诈骗",
                    "source": "test",
                }
            ],
            "reasoning_summary": "内容把中奖和加 V 领奖放在一起，存在私域引流后的钓鱼风险。",
            "recommended_actions": ["不要添加陌生微信或点击对方后续发来的领奖链接。"],
            "confidence": 0.86,
        }

    service.analyze_report_semantics = fake_llm
    result = service.analyze_report_content(
        "http://127.0.0.1:8001/chat.html?x=1 中奖+v",
        tool_session_id="report-tool-test",
    )
    assert result["risk_score"] >= 80
    assert result["fraud_type"] == "中奖领奖钓鱼诈骗"
    assert result["report_intel"]["semantic_hits"]
    assert any("中奖" in item for item in result["matched_rules"])
