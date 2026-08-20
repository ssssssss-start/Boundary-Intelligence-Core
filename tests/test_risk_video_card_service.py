from app.query_process.services import risk_video_card_service as video_service


VIDEO_CARD = {
    "video_id": "rv_brush_rebate_001",
    "scam_id": "scam_brush_rebate",
    "title": "Official anti-fraud video",
    "cover_url": "https://example.com/cover.jpg",
    "source_url": "https://example.com/video",
    "publisher": "公安机关",
    "platform": "official_site",
    "duration_seconds": 180,
    "orientation": "vertical",
    "label": "官方反诈视频",
}


def _knowledge_response():
    return {
        "answer": "原有回答",
        "assistant_mode": "knowledge_education",
        "workflow_mode": "knowledge_answer",
        "fraud_type": "刷单返利诈骗",
    }


def test_resolve_response_scam_id_uses_existing_taxonomy():
    response = {
        "fraud_type_id": "scam_brush_rebate",
        "fraud_type": "不应覆盖已存在的稳定 ID",
    }

    assert video_service.resolve_response_scam_id(response) == "scam_brush_rebate"


def test_attach_video_cards_adds_optional_attachment_without_changing_answer(monkeypatch):
    monkeypatch.setattr(video_service, "list_video_cards", lambda **_: [VIDEO_CARD])
    monkeypatch.setattr(video_service, "_claim_delivery", lambda *args: True)
    response = _knowledge_response()

    result = video_service.attach_video_cards(response, "session-1")

    assert result["answer"] == response["answer"]
    assert result["video_cards"] == [VIDEO_CARD]
    assert "video_delivery" not in result


def test_attach_video_cards_does_not_repeat_automatic_delivery(monkeypatch):
    monkeypatch.setattr(video_service, "list_video_cards", lambda **_: [VIDEO_CARD])
    claims = iter([True, False])
    monkeypatch.setattr(video_service, "_claim_delivery", lambda *args: next(claims))
    response = _knowledge_response()

    first = video_service.attach_video_cards(response, "session-1")
    second = video_service.attach_video_cards(response, "session-1")

    assert first["video_cards"] == [VIDEO_CARD]
    assert "video_cards" not in second
    assert second["answer"] == response["answer"]


def test_missing_video_keeps_response_unchanged(monkeypatch):
    response = _knowledge_response()
    monkeypatch.setattr(video_service, "list_video_cards", lambda **_: [])

    result = video_service.attach_video_cards(response, "session-1")

    assert result == response


def test_existing_summary_video_cards_are_forwarded_without_reclaiming(monkeypatch):
    response = {"answer": "original", "summary": {"video_cards": [VIDEO_CARD]}}

    def fail_claim(*args):
        raise AssertionError("already attached cards must not be claimed again")

    monkeypatch.setattr(video_service, "_claim_delivery", fail_claim)

    result = video_service.attach_video_cards(response, "session-1")

    assert result["video_cards"] == [VIDEO_CARD]


def test_video_service_failure_keeps_response_unchanged(monkeypatch):
    response = _knowledge_response()

    def fail(**kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(video_service, "list_video_cards", fail)

    result = video_service.attach_video_cards(response, "session-1")

    assert result == response


def test_manual_delivery_can_bypass_repeat_claim(monkeypatch):
    monkeypatch.setattr(video_service, "list_video_cards", lambda **_: [VIDEO_CARD])
    monkeypatch.setattr(video_service, "_claim_delivery", lambda *args: False)

    result = video_service.attach_video_cards(_knowledge_response(), "session-1", force=True)

    assert result["video_cards"] == [VIDEO_CARD]
