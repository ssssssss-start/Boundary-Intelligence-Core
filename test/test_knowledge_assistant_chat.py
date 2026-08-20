import unittest
from unittest.mock import patch

from app.modules.knowledge_assistant.service import (
    INTENT_DEFINITION,
    INTENT_LAW,
    INTENT_PREVENTION,
    clear_education_cache,
    clear_education_memory,
    classify_education_intent,
    knowledge_chat,
)


class KnowledgeAssistantChatTest(unittest.TestCase):
    def setUp(self):
        clear_education_cache()
        clear_education_memory()
        self.mongo_patch = patch(
            "app.modules.knowledge_assistant.service.get_business_mongo_tool",
            side_effect=RuntimeError("mongo offline for test"),
        )
        self.mongo_patch.start()

    def tearDown(self):
        self.mongo_patch.stop()
        clear_education_cache()
        clear_education_memory()

    def test_definition_intent_and_topic_match(self):
        result = knowledge_chat("什么是游戏交易诈骗？", session_id="edu_test", use_llm=False)

        self.assertEqual(result["intent"], INTENT_DEFINITION)
        self.assertEqual(result["topics"][0]["fraud_type"], "游戏交易诈骗")
        self.assertTrue(result["references"])
        self.assertNotIn("slots", result)
        self.assertNotIn("routing_decision", result)

    def test_followup_uses_previous_topic(self):
        first = knowledge_chat("讲讲游戏交易诈骗", session_id="edu_follow", use_llm=False)
        second = knowledge_chat("那怎么防？", session_id="edu_follow", use_llm=False)

        self.assertEqual(first["topics"][0]["fraud_type"], "游戏交易诈骗")
        self.assertEqual(second["intent"], INTENT_PREVENTION)
        self.assertEqual(second["topics"][0]["fraud_type"], "游戏交易诈骗")
        self.assertIn("游戏交易诈骗", second["answer"])

    def test_student_specific_scene_retrieval(self):
        result = knowledge_chat("奖助学金退费诈骗怎么识别？", session_id="edu_student", use_llm=False)
        fraud_types = {item["fraud_type"] for item in result["references"]}

        self.assertIn("奖助学金/学费退费诈骗", fraud_types)
        self.assertIn("奖助学金/学费退费诈骗", result["answer"])

    def test_law_intent_uses_law_materials_without_emergency_slots(self):
        result = knowledge_chat("两卡出租出借有什么法律风险？", session_id="edu_law", use_llm=False)
        doc_types = {item["doc_type"] for item in result["references"]}

        self.assertEqual(result["intent"], INTENT_LAW)
        self.assertIn("law_clause", doc_types)
        self.assertNotIn("has_paid", str(result))
        self.assertNotIn("has_shared_code", str(result))

    def test_quiz_request_returns_disabled_message(self):
        result = knowledge_chat("给我来一道反诈测试题", session_id="edu_quiz", use_llm=False)

        self.assertEqual(result["message"], "反诈测试题功能未启用")
        self.assertEqual(result["source"], "policy")
        self.assertEqual(result["topics"], [])
        self.assertIn("不提供反诈测试题", result["answer"])

    def test_live_risk_words_do_not_create_emergency_workflow_payload(self):
        result = knowledge_chat("我已经转账给刷单平台了，这是怎么骗的？", session_id="edu_boundary", use_llm=False)

        self.assertEqual(result["module"], "knowledge_assistant")
        self.assertEqual(result["scope"], "anti_fraud_education_rag")
        self.assertEqual(result["topics"][0]["fraud_type"], "刷单返利诈骗")
        self.assertNotIn("slots", result)
        self.assertNotIn("workflow_mode", result)
        self.assertNotIn("routing_decision", result)

    def test_compare_matches_common_short_names(self):
        result = knowledge_chat("刷单返利和虚假投资有什么区别？", session_id="edu_compare", use_llm=False)
        topics = [item["fraud_type"] for item in result["topics"]]

        self.assertIn("刷单返利诈骗", topics)
        self.assertIn("虚假投资理财诈骗", topics)

    def test_intent_classifier(self):
        self.assertEqual(classify_education_intent("刷单和虚假投资有什么区别"), "compare")
        self.assertEqual(classify_education_intent("讲个冒充公检法案例"), "case")
        self.assertEqual(classify_education_intent("帮我总结给同学听"), "summary")


if __name__ == "__main__":
    unittest.main()
