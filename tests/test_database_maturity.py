import json
from pathlib import Path

from app.anti_fraud.taxonomy import fraud_type_id_for, fraud_type_registry, standard_name_for
from scripts.mature_anti_fraud_database import build_maturity_payload


def test_taxonomy_resolves_legacy_display_names():
    examples = {
        "AI 换脸冒充亲友诈骗": "AI换脸冒充熟人诈骗",
        "虚假贷款诈骗": "网络贷款诈骗",
        "两卡出租出借诈骗": "两卡出租出借与跑分诈骗",
        "冒充领导/熟人诈骗": "冒充领导或熟人借钱诈骗",
        "虚假购物/服务诈骗": "虚假购物服务诈骗",
    }

    for raw_name, expected_name in examples.items():
        assert fraud_type_id_for(raw_name)
        assert standard_name_for(raw_name) == expected_name


def test_all_game_level_fraud_types_have_registry_ids():
    levels = json.loads(Path("app/game_process/data/seed_game_levels.json").read_text(encoding="utf-8"))
    missing = sorted({item.get("fraud_type") for item in levels if not fraud_type_id_for(item.get("fraud_type"))})

    assert missing == []


def test_maturity_payload_meets_minimum_coverage_contract():
    payload = build_maturity_payload()
    audit = payload["coverage_audit"]

    assert len(fraud_type_registry()) >= 30
    assert audit["mature_type_count"] == audit["fraud_type_count"]
    assert 300 <= len(payload["test_cases"]) <= 500

    for row in audit["rows"]:
        counts = row["counts"]
        assert counts["anti_fraud_knowledge"] >= 11
        assert counts["risk_rules"] >= 3
        assert counts["typical_cases"] >= 5
        assert counts["report_guides"] >= 1
        assert counts["evidence_guides"] >= 1
        assert counts["sms_templates"] >= 20
        assert counts["negative_samples"] >= 10


def test_external_sources_are_registered_not_fake_ingested():
    payload = build_maturity_payload()
    source_refs = {item["source_id"]: item for item in payload["source_references"]}
    runs = {item["source_id"]: item for item in payload["source_ingestion_runs"]}

    for source_id in ["SRC_12321_HOME", "SRC_PHISHTANK_VERIFIED", "SRC_URLHAUS", "SRC_TELEANTIFRAUD_28K"]:
        assert source_refs[source_id]["review_status"] == "registered_not_ingested"
        assert runs[source_id]["status"] == "registered_not_ingested"
        assert runs[source_id]["records_imported"] == 0

