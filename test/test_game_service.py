import unittest
from collections import Counter
from unittest.mock import patch

from app.modules.training_camp.service import (
    QUESTION_POINTS,
    SIMULATION_POINTS,
    continue_scam_simulation,
    finish_scam_simulation,
    build_game_report,
    get_next_level,
    load_seed_levels,
    rank_badge_from_score,
    start_scam_simulation,
    submit_level,
)


class GameServiceTest(unittest.TestCase):
    def test_seed_has_200_diverse_questions(self):
        levels = load_seed_levels()
        badges = {item.get("badge") for item in levels if item.get("badge")}
        fraud_types = {item.get("fraud_type") for item in levels if item.get("fraud_type")}
        answer_positions = Counter(item["options"].index(item["answer"]) for item in levels)

        self.assertEqual(len(levels), 200)
        self.assertGreaterEqual(len(fraud_types), 20)
        self.assertGreaterEqual(len(badges), 20)
        self.assertEqual(answer_positions, Counter({0: 50, 1: 50, 2: 50, 3: 50}))
        self.assertEqual(len({item["level_id"] for item in levels}), 200)
        for item in levels:
            self.assertEqual(item["points"], QUESTION_POINTS)
            self.assertTrue(item["question"])
            self.assertEqual(len(item["options"]), 4)
            self.assertEqual(len(set(item["options"])), 4)
            self.assertIn(item["answer"], item["options"])
            self.assertTrue(item["scenario"])
            self.assertTrue(item["explanation"])

    def test_submit_level_awards_points_and_badge(self):
        level = load_seed_levels()[0]
        fake_progress = {
            "user_id": "u1",
            "score": QUESTION_POINTS,
            "answered_count": 1,
            "correct_count": 1,
            "completed_levels": [level["level_id"]],
            "badges": [level["badge"]],
        }
        with patch("app.modules.training_camp.service.seed_game_levels", return_value=30), \
             patch("app.modules.training_camp.service.get_game_level_answer", return_value=level), \
             patch("app.modules.training_camp.service.record_game_result", return_value=fake_progress):
            result = submit_level("u1", level["level_id"], level["answer"])

        self.assertTrue(result["correct"])
        self.assertEqual(result["points_delta"], QUESTION_POINTS)
        self.assertEqual(result["badge"], level["badge"])
        self.assertEqual(result["progress"]["score"], QUESTION_POINTS)

    def test_next_level_contains_scenario_simulation_and_voice_mode(self):
        level = load_seed_levels()[0]
        with patch("app.modules.training_camp.service.seed_game_levels", return_value=30), \
             patch("app.modules.training_camp.service.list_game_levels", return_value=[level]), \
             patch("app.modules.training_camp.service.get_user_game_progress", return_value={"user_id": "u1", "completed_levels": []}), \
             patch("app.modules.training_camp.service.get_game_level_by_id", return_value={k: v for k, v in level.items() if k != "answer"}):
            result = get_next_level("u1")

        public_level = result["level"]
        self.assertNotIn("answer", public_level)
        self.assertIn("scenario_simulation", public_level)
        self.assertIn("voice", public_level["interaction_modes"])
        self.assertTrue(public_level["voice_interaction"]["enabled"])
        self.assertEqual(result["multimodal"]["speech_recognition"], "browser")

    def test_next_level_uses_seed_even_when_mongo_has_old_39_levels(self):
        stale_levels = [{"level_id": item["level_id"]} for item in load_seed_levels()[:39]]
        with patch("app.modules.training_camp.service.seed_game_levels", return_value=39), \
             patch("app.modules.training_camp.service.list_game_levels", return_value=stale_levels), \
             patch("app.modules.training_camp.service.get_game_level_by_id", side_effect=AssertionError("should use seed level")), \
             patch("app.modules.training_camp.service.get_user_game_progress", return_value={
                 "user_id": "u-old",
                 "score": 96,
                 "answered_count": 48,
                 "correct_count": 48,
                 "completed_levels": list(range(1, 49)),
             }):
            result = get_next_level("u-old")

        self.assertEqual(result["total"], 200)
        self.assertEqual(result["source"], "seed")
        self.assertEqual(result["level"]["total_levels"], 200)
        self.assertEqual(result["level"]["level_id"], 49)
        self.assertEqual(result["level"]["reward_preview"]["points"], QUESTION_POINTS)
        self.assertEqual(result["progress"]["answered_count"], 48)

    def test_voice_transcript_can_answer_level(self):
        level = load_seed_levels()[0]
        fake_progress = {
            "user_id": "u1",
            "score": QUESTION_POINTS,
            "answered_count": 1,
            "correct_count": 1,
            "completed_levels": [level["level_id"]],
            "badges": [level["badge"]],
        }
        with patch("app.modules.training_camp.service.seed_game_levels", return_value=30), \
             patch("app.modules.training_camp.service.get_game_level_answer", return_value=level), \
             patch("app.modules.training_camp.service.record_game_result", return_value=fake_progress):
            result = submit_level(
                "u1",
                level["level_id"],
                answer="",
                interaction_mode="voice",
                voice_text=f"我判断应该选择{level['answer']}",
            )

        self.assertTrue(result["correct"])
        self.assertEqual(result["interaction"]["answer_source"], "voice_transcript")
        self.assertEqual(result["selected_answer"], level["answer"])
        self.assertIn("simulation_feedback", result)
        self.assertEqual(result["reward"]["points_delta"], QUESTION_POINTS)

    def test_realtime_scam_simulation_safe_user_scores_high(self):
        started = start_scam_simulation("u1", fraud_type="刷单", use_llm=False)
        session_id = started["simulation"]["session_id"]

        turn = continue_scam_simulation(
            session_id,
            user_message="我不会转账，也不会发验证码，我要先通过官方渠道核实并保存证据。",
            use_llm=False,
        )
        self.assertEqual(turn["simulation"]["status"], "running")

        with patch("app.modules.training_camp.service.record_game_simulation_result") as record:
            record.return_value = {
                "user_id": "u1",
                "score": SIMULATION_POINTS,
                "simulation_count": 1,
                "simulation_pass_count": 1,
                "completed_simulations": [session_id],
                "badges": ["骗局模拟通关者"],
            }
            finished = finish_scam_simulation(session_id)
        self.assertGreaterEqual(finished["score"], 85)
        self.assertIn(finished["outcome"], {"成功识破", "基本安全"})
        self.assertTrue(finished["result"]["safe_signals"])
        self.assertEqual(finished["points_delta"], SIMULATION_POINTS)

    def test_realtime_scam_simulation_loss_signal_ends_low_score(self):
        started = start_scam_simulation("u2", fraud_type="贷款", use_llm=False)
        session_id = started["simulation"]["session_id"]

        finished = continue_scam_simulation(
            session_id,
            user_message="我已经转了保证金，验证码是123456，也下载了你说的App。",
            use_llm=False,
        )

        self.assertEqual(finished["simulation"]["status"], "finished")
        self.assertLess(finished["score"], 60)
        self.assertEqual(finished["outcome"], "被骗风险高")
        self.assertTrue(finished["result"]["loss_signals"])
        self.assertEqual(finished["points_delta"], 0)

    def test_realtime_scam_simulation_difficulty_profiles(self):
        easy = start_scam_simulation("u-easy", difficulty="easy", use_llm=False)["simulation"]
        medium = start_scam_simulation("u-medium", difficulty="medium", use_llm=False)["simulation"]
        hard = start_scam_simulation("u-hard", difficulty="hard", use_llm=False)["simulation"]

        self.assertEqual(easy["difficulty"], "easy")
        self.assertEqual(easy["difficulty_label"], "简单模式")
        self.assertEqual(easy["max_turns"], 4)
        self.assertEqual(medium["difficulty"], "medium")
        self.assertEqual(medium["difficulty_label"], "中等模式")
        self.assertEqual(medium["max_turns"], 6)
        self.assertEqual(hard["difficulty"], "hard")
        self.assertEqual(hard["difficulty_label"], "困难模式")
        self.assertEqual(hard["max_turns"], 8)

    def test_realtime_scam_simulation_api_route_is_registered(self):
        from fastapi.testclient import TestClient

        from app.query_process.api.app import app

        client = TestClient(app)
        response = client.post(
            "/game/simulation/start",
            json={"user_id": "route-test", "difficulty": "easy", "use_llm": False},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["simulation"]["difficulty"], "easy")
        self.assertEqual(data["simulation"]["difficulty_label"], "简单模式")
        self.assertTrue(data["scammer_message"])

    def test_rank_badge_thresholds(self):
        self.assertEqual(rank_badge_from_score(0), "白银")
        self.assertEqual(rank_badge_from_score(19), "白银")
        self.assertEqual(rank_badge_from_score(20), "黄金")
        self.assertEqual(rank_badge_from_score(59), "黄金")
        self.assertEqual(rank_badge_from_score(60), "钻石")
        self.assertEqual(rank_badge_from_score(139), "钻石")
        self.assertEqual(rank_badge_from_score(140), "王者")

    def test_report_uses_total_score_rank_badge(self):
        with patch("app.modules.training_camp.service.list_game_levels", return_value=load_seed_levels()[:39]), \
             patch("app.modules.training_camp.service.get_user_game_progress", return_value={
                 "user_id": "u-rank",
                 "score": 68,
                 "answered_count": 34,
                 "correct_count": 34,
                 "completed_levels": list(range(1, 35)),
                 "badges": [],
                 "simulation_count": 1,
                 "simulation_pass_count": 1,
             }):
            report = build_game_report("u-rank")

        self.assertEqual(report["score"], 68)
        self.assertEqual(report["assessment_level"], "钻石")
        self.assertEqual(report["rank_badge"], "钻石")
        self.assertEqual(report["total_levels"], 200)
        self.assertEqual(report["score_rules"]["question_correct"], 2)
        self.assertEqual(report["score_rules"]["simulation_pass"], 10)


if __name__ == "__main__":
    unittest.main()
