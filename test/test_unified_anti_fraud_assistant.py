import unittest
import json
from unittest.mock import patch

from app.modules.knowledge_assistant.service import (
    ASSISTANT_MODE_KNOWLEDGE,
    ASSISTANT_MODE_RISK,
    clear_education_cache,
    clear_education_memory,
    unified_anti_fraud_chat,
)
from app.query_process.services.realtime_dissuasion_engine import build_realtime_dissuasion
from app.query_process.services.scam_rule_engine import evaluate_rule_text
from app.query_process.services.semantic_risk_agent import (
    ASSISTANT_CLOSED_SCENE_TEXT,
    generate_realtime_answer,
)
from app.utils.task_utils import TASK_STATUS_COMPLETED, set_task_result, update_task_status


class _FakeMemoryManager:
    def load_context(self, session_id, user_text, intent_hint=""):
        return {
            "session_id": session_id,
            "case_id": "case_unified_test",
            "intent_hint": intent_hint or "",
            "session_state": {},
            "case_state": {},
            "pending_question": {},
            "recent_user_messages": [],
            "memory_summary": "",
            "route_context": {},
            "turn_memory": {},
        }

    def commit_turn(self, state):
        state.setdefault("case_state", {})
        return state


def _fake_risk_graph(session_id, user_query, is_stream=True, intent_hint="risk_help", route_decision_override=None, history_override=None):
    route_decision = route_decision_override or {}
    slots = (route_decision.get("routing_decision") or {}).get("prefill_slots") or {}
    rule_result = evaluate_rule_text(
        user_query,
        context={"slots": slots, "route_decision": route_decision},
        route_decision=route_decision,
    )
    if not rule_result.get("matched_rules") and rule_result.get("risk_score", 0) >= 60:
        rule_result["matched_rules"] = [
            {
                "rule_id": "ROUTE_PREFILL_SYNTHETIC",
                "rule_name": "入口路由风险预填规则",
                "fraud_type": rule_result.get("fraud_type", ""),
                "risk_level": rule_result.get("risk_level", ""),
                "risk_score": rule_result.get("risk_score", 0),
                "matched_features": rule_result.get("risk_features", []),
                "intervention_goal": rule_result.get("intervention_goal", ""),
            }
        ]
    realtime = build_realtime_dissuasion(rule_result, slots, {})
    summary = {
        "risk_score": rule_result.get("risk_score"),
        "risk_level": rule_result.get("risk_level"),
        "fraud_type": rule_result.get("fraud_type"),
        "workflow_mode": "risk_case_flow",
        "route_decision": route_decision,
        "risk_features": rule_result.get("risk_features", []),
        "matched_rules": rule_result.get("matched_rules", []),
        "intervention_goal": realtime.get("goal") or rule_result.get("intervention_goal", ""),
        "realtime_dissuasion": realtime,
    }
    set_task_result(session_id, "answer", realtime.get("primary_warning") or "已进入风险劝阻。")
    set_task_result(session_id, "result_summary", json.dumps(summary, ensure_ascii=False))
    update_task_status(session_id, TASK_STATUS_COMPLETED, is_stream)


class UnifiedAntiFraudAssistantTest(unittest.TestCase):
    def setUp(self):
        clear_education_cache()
        clear_education_memory()
        self.patches = [
            patch("app.modules.knowledge_assistant.service.get_business_mongo_tool", side_effect=RuntimeError("mongo offline for test")),
            patch("app.query_process.services.knowledge_repository.get_business_mongo_tool", side_effect=RuntimeError("mongo offline for test")),
            patch("app.query_process.agent.memory.get_memory_manager", return_value=_FakeMemoryManager()),
            patch("app.modules.knowledge_assistant.service.get_memory_manager", return_value=_FakeMemoryManager(), create=True),
            patch("app.query_process.services.semantic_turn_extractor.invoke_json_llm", side_effect=RuntimeError("llm offline for deterministic semantic frame")),
            patch("app.query_process.services.knowledge_service.search_knowledge", return_value={"source": "test", "items": []}),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        clear_education_cache()
        clear_education_memory()

    def test_knowledge_question_stays_in_structured_education_mode(self):
        route = {
            "primary_intent": "anti_fraud_qa",
            "workflow_mode": "knowledge_answer",
            "confidence": 0.91,
            "reason": "用户在询问反诈定义",
            "risk_signals": {},
            "routing_decision": {"target": "knowledge_answer", "force_high_risk": False, "prefill_slots": {}},
        }
        with patch("app.modules.knowledge_assistant.service._route_for_unified_assistant", return_value=route):
            result = unified_anti_fraud_chat("什么是游戏交易诈骗？", session_id="unified_edu", use_llm=False)

        self.assertEqual(result["module"], "unified_anti_fraud_assistant")
        self.assertEqual(result["assistant_mode"], ASSISTANT_MODE_KNOWLEDGE)
        self.assertEqual(result["workflow_mode"], "knowledge_answer")
        self.assertEqual(result["topics"][0]["fraud_type"], "游戏交易诈骗")
        self.assertTrue(result["references"])
        self.assertNotIn("slots", result)

    def test_risk_scene_enters_realtime_dissuasion_workflow(self):
        route = {
            "primary_intent": "risk_help",
            "workflow_mode": "risk_case_flow",
            "confidence": 0.93,
            "reason": "用户描述对方要求交服务费并承诺退款",
            "risk_signals": {"has_current_transfer_request": True},
            "routing_decision": {"target": "risk_case_flow", "force_high_risk": False, "prefill_slots": {}},
        }
        emergency_result = {
            "message": "处理完成！",
            "session_id": "unified_risk",
            "answer": "先不要交这三万元服务费。",
            "risk_score": 82,
            "risk_level": "高风险",
            "fraud_type": "升学保研服务骗局",
            "summary": {
                "risk_score": 82,
                "risk_level": "高风险",
                "fraud_type": "升学保研服务骗局",
                "workflow_mode": "risk_case_flow",
                "route_decision": route,
            },
        }
        with (
            patch("app.modules.knowledge_assistant.service._route_for_unified_assistant", return_value=route),
            patch("app.modules.emergency_dissuasion.service.run_emergency_graph") as run_graph,
            patch("app.modules.emergency_dissuasion.service.build_emergency_sync_result", return_value=emergency_result),
        ):
            history = [{"role": "user", "text": "我看到一个新媒体运营就业班，说学完可以推荐实习。"}]
            result = unified_anti_fraud_chat(
                "他们说交三万元服务费就能拿到推荐名额，不成功全额退款。",
                session_id="unified_risk",
                history=history,
                use_llm=False,
            )

        run_graph.assert_called_once()
        self.assertEqual(run_graph.call_args.kwargs["history_override"], history)
        self.assertEqual(result["module"], "unified_anti_fraud_assistant")
        self.assertEqual(result["assistant_mode"], ASSISTANT_MODE_RISK)
        self.assertEqual(result["workflow_mode"], "risk_case_flow")
        self.assertEqual(result["risk_level"], "高风险")
        self.assertEqual(result["summary"]["assistant_mode"], ASSISTANT_MODE_RISK)
        self.assertEqual(result["route_decision"]["workflow_mode"], "risk_case_flow")

    def test_frontend_history_recovery_followup_stays_in_risk_workflow(self):
        emergency_result = {
            "message": "处理完成！",
            "session_id": "unified_rental",
            "answer": "先别再交任何钱，立刻保留证据并联系支付平台尝试止付，同时报警。",
            "risk_score": 88,
            "risk_level": "高风险",
            "fraud_type": "租房押金诈骗",
            "summary": {
                "risk_score": 88,
                "risk_level": "高风险",
                "fraud_type": "租房押金诈骗",
                "workflow_mode": "risk_case_flow",
            },
        }
        history = [
            {
                "role": "user",
                "content": "我在学校附近看房，遇到一个自称房东的人。他带我看了房，说房子很抢手，让我当天交押金。我已经交了",
            },
            {"role": "assistant", "content": "这很像租房押金诈骗，先不要继续付款。"},
        ]
        with (
            patch("app.modules.emergency_dissuasion.service.run_emergency_graph") as run_graph,
            patch("app.modules.emergency_dissuasion.service.build_emergency_sync_result", return_value=emergency_result),
        ):
            result = unified_anti_fraud_chat(
                "那我现在还能把钱要回来吗？",
                session_id="unified_rental",
                history=history,
                use_llm=False,
            )

        run_graph.assert_called_once()
        self.assertEqual(result["assistant_mode"], ASSISTANT_MODE_RISK)
        self.assertEqual(result["workflow_mode"], "risk_case_flow")
        self.assertEqual(result["route_decision"]["workflow_mode"], "risk_case_flow")
        self.assertTrue(result["route_decision"]["continue_current_workflow"])

    def test_core_scam_scenarios_enter_risk_flow_from_unified_entry(self):
        cases = [
            ("brush", "我在兼职群做点赞任务，前两单返了钱，现在对方让我先垫付500元做联单。", "刷单返利诈骗"),
            ("game", "游戏群有人叫我把装备先给他验货，再付款给我。", "游戏交易诈骗"),
            ("police", "自称公安的人说我涉案洗钱，让我把钱转到安全账户。", "冒充公检法诈骗"),
            ("investment", "投资老师说稳赚高收益，让我下载投资App入金，现在提现失败要先交税费。", "虚假投资理财诈骗"),
            ("loan", "贷款App说银行卡填错，要先交解冻费才能放款。", "网络贷款诈骗"),
        ]

        with patch("app.modules.emergency_dissuasion.service.run_emergency_graph", side_effect=_fake_risk_graph):
            for case_id, text, fraud_type in cases:
                with self.subTest(case_id=case_id):
                    result = unified_anti_fraud_chat(text, session_id=f"unified_{case_id}", use_llm=False)

                    self.assertEqual(result["assistant_mode"], ASSISTANT_MODE_RISK)
                    self.assertEqual(result["workflow_mode"], "risk_case_flow")
                    self.assertEqual(result["route_decision"]["workflow_mode"], "risk_case_flow")
                    self.assertEqual(result["fraud_type"], fraud_type)
                    self.assertGreaterEqual(result["risk_score"], 60)
                    self.assertTrue(result["risk_features"])
                    self.assertTrue(result["matched_rules"])
                    self.assertTrue(result["summary"]["realtime_dissuasion"]["enabled"])
                    self.assertEqual(result["summary"]["intervention_goal"], "stop_transfer")

    def test_core_scam_learning_questions_stay_in_knowledge_mode(self):
        cases = [
            ("什么是刷单返利诈骗？", "刷单返利诈骗"),
            ("校园贷诈骗怎么防范？", "网络贷款诈骗"),
        ]

        for text, fraud_type in cases:
            with self.subTest(text=text):
                result = unified_anti_fraud_chat(text, session_id=f"unified_qa_{fraud_type}", use_llm=False)

                self.assertEqual(result["assistant_mode"], ASSISTANT_MODE_KNOWLEDGE)
                self.assertEqual(result["workflow_mode"], "knowledge_answer")
                self.assertEqual(result["topics"][0]["fraud_type"], fraud_type)
                self.assertTrue(result["references"])
                self.assertNotIn("slots", result)

    def test_quiz_request_is_disabled_in_unified_entry(self):
        result = unified_anti_fraud_chat("给我来一道反诈测试题", session_id="unified_quiz", use_llm=False)

        self.assertEqual(result["assistant_mode"], ASSISTANT_MODE_KNOWLEDGE)
        self.assertEqual(result["workflow_mode"], "knowledge_answer")
        self.assertEqual(result["message"], "反诈测试题功能未启用")
        self.assertEqual(result["topics"], [])
        self.assertIn("不提供反诈测试题", result["answer"])

    def test_smalltalk_is_concise_and_does_not_start_education_topic(self):
        result = unified_anti_fraud_chat("你好", session_id="unified_hello", use_llm=False)

        self.assertEqual(result["module"], "unified_anti_fraud_assistant")
        self.assertEqual(result["assistant_mode"], ASSISTANT_MODE_KNOWLEDGE)
        self.assertEqual(result["workflow_mode"], "fallback")
        self.assertEqual(result["intent"], "smalltalk")
        self.assertEqual(result["topics"], [])
        self.assertIn("您好呀！我是您的反诈骗小卫士", result["answer"])
        self.assertIn("陌生链接别乱点，可疑电话多核实，转账汇款先问我", result["answer"])
        self.assertNotIn("刷单返利", result["answer"])

    def test_closed_scene_brief_ack_returns_converged_entry(self):
        answer = generate_realtime_answer(
            {"original_query": "我明白了", "is_stream": False, "session_id": ""},
            {
                "case_lifecycle": {
                    "case_status": "prevented",
                    "post_resolution_answer_mode": "closure_with_education",
                },
                "resolution": {"risk_resolved": True},
            },
            {"is_risk_scene": True, "fraud_type": "虚假招聘诈骗"},
            {},
        )

        self.assertEqual(answer, ASSISTANT_CLOSED_SCENE_TEXT)
        self.assertIn("请问您想咨询什么，或者有遇到可疑的事情吗？", answer)


if __name__ == "__main__":
    unittest.main()
