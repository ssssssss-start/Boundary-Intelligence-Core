from app.query_process.services.llm_scene_router import _normalize_route


def test_disabled_chat_report_route_is_normalized_to_knowledge_answer():
    route = _normalize_route(
        {
            "scene": {"scene_type": "report_or_evidence_help", "confidence": 0.9},
            "primary_intent": "report_submit",
            "workflow_mode": "report_flow",
            "reason": "disabled report route",
            "confidence": 0.9,
        },
        "我要举报这个链接",
    )
    assert route["primary_intent"] == "anti_fraud_qa"
    assert route["workflow_mode"] == "knowledge_answer"
    assert route["semantic_scene"]["scene_type"] == "knowledge_consultation"


def test_disabled_chat_url_check_route_is_normalized_to_knowledge_answer():
    route = _normalize_route(
        {
            "scene": {"scene_type": "url_or_content_check", "confidence": 0.9},
            "primary_intent": "url_check",
            "workflow_mode": "url_check",
            "reason": "disabled url route",
            "confidence": 0.9,
        },
        "这个链接安全吗",
    )
    assert route["primary_intent"] == "anti_fraud_qa"
    assert route["workflow_mode"] == "knowledge_answer"
    assert route["routing_decision"]["target"] == "knowledge_answer"
