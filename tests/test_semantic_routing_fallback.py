import os

from app.modules.knowledge_assistant.service import (
    GENERAL_TRANSFER_TOPIC,
    _build_knowledge_query_plan,
    _build_smalltalk_unified_response,
    _heuristic_knowledge_strategy,
    _local_unified_route,
    _run_knowledge_dialogue_flow,
)
from app.modules.knowledge_assistant.web_fallback import search_trusted_web


def test_local_route_treats_short_knowledge_request_as_knowledge():
    route = _local_unified_route("好的 给我科普一下租房骗局")

    assert route["workflow_mode"] == "knowledge_answer"
    assert route["primary_intent"] == "anti_fraud_qa"
    assert route["normalized_topic"] == "租房合租押金诈骗"
    assert route["fraud_type_id"]


def test_local_route_maps_bank_transfer_to_general_transfer_topic():
    route = _local_unified_route("科普银行转账骗局")

    assert route["workflow_mode"] == "knowledge_answer"
    assert route["normalized_topic"] == GENERAL_TRANSFER_TOPIC
    assert route["fraud_type_id"] == "general_anti_fraud"


def test_local_route_keeps_personal_deposit_request_in_risk_flow():
    route = _local_unified_route("对方让我先交押金看房")

    assert route["workflow_mode"] == "risk_case_flow"
    assert route["risk_signals"]["personal_risk_claim"] is True
    assert route["risk_signals"]["has_current_transfer_request"] is True


def test_smalltalk_uses_persona_fallback_when_llm_unavailable():
    response = _build_smalltalk_unified_response(
        "test-session",
        {
            "workflow_mode": "fallback",
            "primary_intent": "smalltalk",
            "semantic_scene": {"user_text": "你好你是谁"},
        },
    )

    assert response["workflow_mode"] == "fallback"
    assert response["intent"] == "smalltalk"
    assert response["answer"]
    assert "一秒识破它" not in response["answer"]


def test_heuristic_strategy_uses_web_for_general_transfer_topic():
    strategy = _heuristic_knowledge_strategy(
        {"normalized_topic": GENERAL_TRANSFER_TOPIC},
        {
            "general_topic": True,
            "item_count": 0,
            "top_score": 0,
            "weak_only": True,
            "mismatch_types": [],
        },
    )

    assert strategy["strategy"] == "use_web_fallback"


def test_web_fallback_without_key_is_explicitly_unavailable():
    old_tavily = os.environ.pop("TAVILY_API_KEY", None)
    old_web = os.environ.pop("WEB_SEARCH_API_KEY", None)
    try:
        result = search_trusted_web("转账前如何识别诈骗")
    finally:
        if old_tavily is not None:
            os.environ["TAVILY_API_KEY"] = old_tavily
        if old_web is not None:
            os.environ["WEB_SEARCH_API_KEY"] = old_web

    assert result["web_status"] == "unavailable"
    assert result["items"] == []


def test_cross_border_broad_query_uses_semantic_query_plan():
    route = _local_unified_route("科普一下境外诈骗")
    response = _run_knowledge_dialogue_flow(
        "科普一下境外诈骗",
        session_id="test-cross-border-broad",
        route_decision=route,
        use_llm=False,
        limit=5,
    )

    understanding = response["query_understanding"]
    assert response["workflow_mode"] == "knowledge_answer"
    assert understanding["query_type"] == "broad_domain"
    assert understanding["domain"] == "cross_border_fraud"
    assert "转账前防骗" not in response["answer"]
    assert "境外/跨境诈骗" in response["answer"]
    assert response["retrieval_quality"]["item_count"] > 0 or response["retrieval_quality"]["scored_count"] > 0


def test_cross_border_prevention_retrieves_semantic_materials():
    route = _local_unified_route("跨境诈骗怎么防")
    response = _run_knowledge_dialogue_flow(
        "跨境诈骗怎么防",
        session_id="test-cross-border-prevention",
        route_decision=route,
        use_llm=False,
        limit=5,
    )

    assert response["query_understanding"]["domain"] == "cross_border_fraud"
    assert response["retrieval_quality"]["scored_count"] > 0
    assert "domain_recall" in response["retrieval_paths"]
    assert "转账前防骗" not in response["answer"]


def test_cross_border_high_salary_candidate_topic_is_planned():
    plan = _build_knowledge_query_plan("境外高薪工作靠谱吗", {}, use_llm=False)
    candidates = {item["fraud_type"] for item in plan["candidate_topics"]}

    assert plan["domain"] == "cross_border_fraud"
    assert "跨境高薪招工诱骗诈骗" in candidates


def test_cross_border_passport_border_request_enters_risk_flow():
    route = _local_unified_route("对方让我去边境集合交护照")

    assert route["workflow_mode"] == "risk_case_flow"
    assert "跨境出行或证件高危要求" in route["risk_signals"]["risk_features"]
