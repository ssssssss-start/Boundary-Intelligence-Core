import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument, UpdateOne

from app.core.data_protection import ProtectedDatabase, retention_collections
from app.core.security import env_bool


load_dotenv()


COLLECTION_NAMES = [
    "fraud_type_registry",
    "official_sources",
    "source_quality_tiers",
    "source_references",
    "scam_types",
    "scam_features",
    "scam_techniques",
    "prevention_advice",
    "typical_cases",
    "law_clauses",
    "rag_documents",
    "rag_chunks",
    "anti_fraud_knowledge",
    "risk_rules",
    "semantic_risk_policy",
    "knowledge_dialogue_policy",
    "report_guides",
    "stage_definitions",
    "evidence_guides",
    "report_analysis_drafts",
    "report_tickets",
    "game_levels",
    "user_profiles",
    "user_game_progress",
    "badge_records",
    "test_cases",
    "scam_intake_submissions",
    "scam_draft_packages",
    "scam_review_tasks",
    "scam_review_comments",
    "scam_publish_packages",
    "scam_publish_versions",
    "scam_test_cases",
    "scam_rollback_records",
    "risk_rule_candidates",
    "admin_users",
    "admin_sessions",
    "audit_logs",
    "chat_message",
    "anti_fraud_case_state",
    "anti_fraud_session_state",
    "anti_fraud_case_event",
    "threat_iocs",
    "phishing_domains",
    "brand_impersonation_patterns",
    "sms_templates",
    "malicious_apps",
    "negative_samples",
    "source_ingestion_runs",
    "coverage_audit_reports",
    "web_fallback_cache",
    "risk_video_cards",
]


class BusinessMongoTool:
    """MongoDB business-store helper.

    MongoDB is the source of truth for anti-fraud business data. Milvus stores
    vectors only and should be treated as a retrieval index.
    """

    def __init__(self):
        self.mongo_url = os.getenv("MONGO_URL")
        self.db_name = os.getenv("MONGO_DB_NAME")
        if not self.mongo_url or not self.db_name:
            raise RuntimeError("MONGO_URL 或 MONGO_DB_NAME 未配置")

        mongo_options = {
            "serverSelectionTimeoutMS": int(os.getenv("MONGO_SERVER_SELECTION_TIMEOUT_MS", "2000")),
            "connectTimeoutMS": int(os.getenv("MONGO_CONNECT_TIMEOUT_MS", "2000")),
            "socketTimeoutMS": int(os.getenv("MONGO_SOCKET_TIMEOUT_MS", "5000")),
        }
        if env_bool("MONGO_TLS", env_bool("MONGO_SSL", False)):
            mongo_options.update(
                {
                    "tls": True,
                    "tlsAllowInvalidCertificates": env_bool("MONGO_TLS_ALLOW_INVALID_CERTS", False),
                }
            )
            ca_file = os.getenv("MONGO_TLS_CA_FILE", "").strip()
            cert_file = os.getenv("MONGO_TLS_CERT_KEY_FILE", "").strip()
            if ca_file:
                mongo_options["tlsCAFile"] = ca_file
            if cert_file:
                mongo_options["tlsCertificateKeyFile"] = cert_file
        self.client = MongoClient(self.mongo_url, **mongo_options)
        self.db = ProtectedDatabase(self.client[self.db_name])
        self._ensure_collections_and_indexes()

    def _ensure_collections_and_indexes(self) -> None:
        for name in COLLECTION_NAMES:
            self.db[name].create_index([("_created_marker", ASCENDING)], sparse=True)

        self.db["fraud_type_registry"].create_index([("fraud_type_id", ASCENDING)], unique=True)
        self.db["fraud_type_registry"].create_index([("standard_name", ASCENDING)], unique=True)
        self.db["fraud_type_registry"].create_index([("aliases", ASCENDING)])
        self.db["fraud_type_registry"].create_index([("runtime_enabled", ASCENDING), ("parent_category", ASCENDING)])

        self.db["official_sources"].create_index([("source_id", ASCENDING)], unique=True)
        self.db["official_sources"].create_index([("url", ASCENDING)])
        self.db["official_sources"].create_index([("authority", ASCENDING), ("source_type", ASCENDING)])
        self.db["source_quality_tiers"].create_index([("tier_id", ASCENDING)], unique=True)

        self.db["source_references"].create_index([("source_id", ASCENDING)], unique=True)

        self.db["scam_types"].create_index([("scam_type_id", ASCENDING)], unique=True)
        self.db["scam_types"].create_index([("fraud_type_id", ASCENDING)])
        self.db["scam_types"].create_index([("operational_fraud_type", ASCENDING)])

        self.db["scam_features"].create_index([("feature_id", ASCENDING)], unique=True)
        self.db["scam_features"].create_index([("fraud_type_id", ASCENDING), ("risk_weight", DESCENDING)])
        self.db["scam_features"].create_index([("scam_type_id", ASCENDING), ("risk_weight", DESCENDING)])
        self.db["scam_features"].create_index([("scam_id", ASCENDING), ("risk_weight", DESCENDING)])

        self.db["scam_techniques"].create_index([("technique_id", ASCENDING)], unique=True)
        self.db["scam_techniques"].create_index([("fraud_type_id", ASCENDING)])
        self.db["scam_techniques"].create_index([("scam_type_id", ASCENDING)])

        self.db["prevention_advice"].create_index([("advice_id", ASCENDING)], unique=True)
        self.db["prevention_advice"].create_index([("fraud_type_id", ASCENDING), ("risk_level", ASCENDING)])
        self.db["prevention_advice"].create_index([("scam_type_id", ASCENDING), ("risk_level", ASCENDING)])

        self.db["typical_cases"].create_index([("case_id", ASCENDING)], unique=True)
        self.db["typical_cases"].create_index([("fraud_type_id", ASCENDING), ("amount_loss", DESCENDING)])
        self.db["typical_cases"].create_index([("scam_type_id", ASCENDING), ("amount_loss", DESCENDING)])

        self.db["law_clauses"].create_index([("law_id", ASCENDING)], unique=True)
        self.db["law_clauses"].create_index([("related_scam_types", ASCENDING)])

        self.db["rag_documents"].create_index([("doc_id", ASCENDING)], unique=True)
        self.db["rag_documents"].create_index([("doc_type", ASCENDING), ("related_scam_type", ASCENDING)])

        self.db["rag_chunks"].create_index([("chunk_id", ASCENDING)], unique=True)
        self.db["rag_chunks"].create_index([("document_id", ASCENDING), ("chunk_index", ASCENDING)])

        self.db["anti_fraud_knowledge"].create_index([("knowledge_id", ASCENDING)], unique=True)
        self.db["anti_fraud_knowledge"].create_index([("fraud_type_id", ASCENDING), ("knowledge_type", ASCENDING)])
        self.db["anti_fraud_knowledge"].create_index([("fraud_type", ASCENDING), ("knowledge_type", ASCENDING)])
        self.db["anti_fraud_knowledge"].create_index([("risk_level", ASCENDING), ("priority", DESCENDING)])

        self.db["risk_rules"].create_index([("rule_id", ASCENDING)], unique=True)
        self.db["risk_rules"].create_index([("fraud_type_id", ASCENDING), ("enabled", ASCENDING)])
        self.db["risk_rules"].create_index([("fraud_type", ASCENDING), ("enabled", ASCENDING)])
        self.db["risk_rules"].create_index([("fraud_type", ASCENDING), ("intervention_goal", ASCENDING), ("risk_level", ASCENDING)])

        self.db["semantic_risk_policy"].create_index([("policy_id", ASCENDING)], unique=True)
        self.db["semantic_risk_policy"].create_index([("policy_type", ASCENDING), ("enabled", ASCENDING)])
        self.db["semantic_risk_policy"].create_index([("priority", DESCENDING)])
        self.db["knowledge_dialogue_policy"].create_index([("policy_id", ASCENDING)], unique=True)
        self.db["knowledge_dialogue_policy"].create_index([("policy_type", ASCENDING), ("enabled", ASCENDING), ("priority", DESCENDING)])
        self.db["knowledge_dialogue_policy"].create_index([("fraud_type_id", ASCENDING), ("enabled", ASCENDING)])
        self.db["knowledge_dialogue_policy"].create_index([("fraud_type", ASCENDING), ("enabled", ASCENDING)])

        self.db["report_guides"].create_index([("guide_id", ASCENDING)], unique=True)
        self.db["report_guides"].create_index([("input_type", ASCENDING), ("fraud_type_id", ASCENDING)])
        self.db["report_guides"].create_index([("input_type", ASCENDING), ("fraud_type", ASCENDING)])
        self.db["stage_definitions"].create_index([("stage_id", ASCENDING)], unique=True)
        self.db["stage_definitions"].create_index([("name", ASCENDING)], unique=True)
        self.db["evidence_guides"].create_index([("guide_id", ASCENDING)], unique=True)
        self.db["evidence_guides"].create_index([("fraud_type_id", ASCENDING), ("scenario", ASCENDING)])
        self.db["evidence_guides"].create_index([("fraud_type", ASCENDING), ("scenario", ASCENDING)])

        self.db["report_analysis_drafts"].create_index([("analysis_id", ASCENDING)], unique=True)
        self.db["report_analysis_drafts"].create_index([("created_at", DESCENDING)])
        self.db["report_analysis_drafts"].create_index([("content_hash", ASCENDING)])
        self.db["report_analysis_drafts"].create_index([("status", ASCENDING), ("created_at", DESCENDING)])
        self.db["report_analysis_drafts"].create_index([("expires_at_ts", ASCENDING)], expireAfterSeconds=0)

        self.db["report_tickets"].create_index([("report_id", ASCENDING)], unique=True)
        self.db["report_tickets"].create_index([("created_at", DESCENDING)])
        self.db["report_tickets"].create_index([("status", ASCENDING), ("created_at", DESCENDING)])
        self.db["report_tickets"].create_index([("risk_level", ASCENDING), ("scam_type", ASCENDING)])

        self.db["game_levels"].create_index([("level_id", ASCENDING)], unique=True)
        self.db["user_profiles"].create_index([("user_id", ASCENDING)], unique=True)
        self.db["user_game_progress"].create_index([("user_id", ASCENDING)], unique=True)
        self.db["badge_records"].create_index([("user_id", ASCENDING), ("badge", ASCENDING)], unique=True)
        self.db["test_cases"].create_index([("case_id", ASCENDING)], unique=True)
        self.db["scam_intake_submissions"].create_index([("submission_id", ASCENDING)], unique=True)
        self.db["scam_intake_submissions"].create_index([("status", ASCENDING), ("created_at", DESCENDING)])
        self.db["scam_draft_packages"].create_index([("draft_id", ASCENDING)], unique=True)
        self.db["scam_draft_packages"].create_index([("submission_id", ASCENDING), ("updated_at", DESCENDING)])
        self.db["scam_review_tasks"].create_index([("review_id", ASCENDING)], unique=True)
        self.db["scam_review_tasks"].create_index([("status", ASCENDING), ("updated_at", DESCENDING)])
        self.db["scam_review_tasks"].create_index([("draft_id", ASCENDING)])
        self.db["scam_review_comments"].create_index([("comment_id", ASCENDING)], unique=True)
        self.db["scam_review_comments"].create_index([("review_id", ASCENDING), ("created_at", ASCENDING)])
        self.db["scam_publish_packages"].create_index([("publish_id", ASCENDING)], unique=True)
        self.db["scam_publish_packages"].create_index([("status", ASCENDING), ("updated_at", DESCENDING)])
        self.db["scam_publish_versions"].create_index([("version_id", ASCENDING)], unique=True)
        self.db["scam_publish_versions"].create_index([("status", ASCENDING), ("published_at", DESCENDING)])
        self.db["scam_test_cases"].create_index([("case_id", ASCENDING)], unique=True)
        self.db["scam_test_cases"].create_index([("publish_id", ASCENDING)])
        self.db["scam_rollback_records"].create_index([("rollback_id", ASCENDING)], unique=True)
        self.db["scam_rollback_records"].create_index([("version_id", ASCENDING), ("created_at", DESCENDING)])
        self.db["risk_rule_candidates"].create_index([("candidate_id", ASCENDING)], unique=True)
        self.db["risk_rule_candidates"].create_index([("publish_id", ASCENDING)])
        self.db["admin_users"].create_index([("user_id", ASCENDING)], unique=True)
        self.db["admin_users"].create_index([("username", ASCENDING)], unique=True)
        self.db["admin_sessions"].create_index([("token_hash", ASCENDING)], unique=True)
        self.db["admin_sessions"].create_index([("expires_at_ts", ASCENDING)], expireAfterSeconds=0)
        self.db["audit_logs"].create_index([("created_at", DESCENDING)])
        self.db["audit_logs"].create_index([("event_type", ASCENDING), ("created_at", DESCENDING)])
        self.db["anti_fraud_session_state"].create_index([("session_id", ASCENDING)], unique=True, sparse=True)
        self.db["anti_fraud_case_event"].create_index([("session_id", ASCENDING), ("created_at", ASCENDING)])
        self.db["anti_fraud_case_event"].create_index([("case_id", ASCENDING), ("created_at", ASCENDING)])
        self.db["threat_iocs"].create_index([("ioc_id", ASCENDING)], unique=True)
        self.db["threat_iocs"].create_index([("ioc_type", ASCENDING), ("fraud_type_id", ASCENDING)])
        self.db["threat_iocs"].create_index([("confidence", DESCENDING), ("updated_at", DESCENDING)])
        self.db["phishing_domains"].create_index([("domain", ASCENDING)], unique=True)
        self.db["phishing_domains"].create_index([("status", ASCENDING), ("last_seen_at", DESCENDING)])
        self.db["brand_impersonation_patterns"].create_index([("pattern_id", ASCENDING)], unique=True)
        self.db["brand_impersonation_patterns"].create_index([("brand", ASCENDING), ("fraud_type_id", ASCENDING)])
        self.db["sms_templates"].create_index([("template_id", ASCENDING)], unique=True)
        self.db["sms_templates"].create_index([("fraud_type_id", ASCENDING), ("sample_type", ASCENDING)])
        self.db["malicious_apps"].create_index([("app_id", ASCENDING)], unique=True)
        self.db["malicious_apps"].create_index([("package_name", ASCENDING)])
        self.db["negative_samples"].create_index([("sample_id", ASCENDING)], unique=True)
        self.db["negative_samples"].create_index([("fraud_type_id", ASCENDING), ("sample_type", ASCENDING)])
        self.db["source_ingestion_runs"].create_index([("run_id", ASCENDING)], unique=True)
        self.db["source_ingestion_runs"].create_index([("source_id", ASCENDING), ("started_at", DESCENDING)])
        self.db["coverage_audit_reports"].create_index([("audit_id", ASCENDING)], unique=True)
        self.db["coverage_audit_reports"].create_index([("created_at", DESCENDING)])
        self.db["web_fallback_cache"].create_index([("query_hash", ASCENDING)], unique=True)
        self.db["web_fallback_cache"].create_index([("created_at", DESCENDING)])
        self.db["web_fallback_cache"].create_index([("provider", ASCENDING), ("web_status", ASCENDING)])
        self.db["risk_video_cards"].create_index([("video_id", ASCENDING)], unique=True)
        self.db["risk_video_cards"].create_index([("scam_id", ASCENDING), ("status", ASCENDING), ("priority", DESCENDING)])
        self.db["risk_video_cards"].create_index([("source_url", ASCENDING)])

        # Application-level encryption has its own retention clock. MongoDB's
        # TTL monitor removes expired records even when the application is idle.
        for collection_name in retention_collections():
            self.db[collection_name].create_index(
                [("data_retention_expires_at", ASCENDING)],
                expireAfterSeconds=0,
                name="data_retention_ttl",
            )


_business_mongo_tool: Optional[BusinessMongoTool] = None


def get_business_mongo_tool() -> BusinessMongoTool:
    global _business_mongo_tool
    if _business_mongo_tool is None:
        _business_mongo_tool = BusinessMongoTool()
    return _business_mongo_tool


def init_business_collections() -> List[str]:
    tool = get_business_mongo_tool()
    return sorted(name for name in COLLECTION_NAMES if name in tool.db.list_collection_names())


def upsert_anti_fraud_knowledge(records: List[Dict[str, Any]], source_file: str = "") -> int:
    if not records:
        return 0
    tool = get_business_mongo_tool()
    now = datetime.now().isoformat(timespec="seconds")
    ops = []
    for item in records:
        knowledge_id = item.get("knowledge_id")
        if not knowledge_id:
            continue
        doc = dict(item)
        doc.pop("_id", None)
        doc.pop("dense_vector", None)
        doc.pop("sparse_vector", None)
        doc["source_file"] = source_file
        doc["updated_at"] = now
        doc.setdefault("created_at", now)
        ops.append(UpdateOne({"knowledge_id": knowledge_id}, {"$set": doc}, upsert=True))
    if not ops:
        return 0
    result = tool.db["anti_fraud_knowledge"].bulk_write(ops, ordered=False)
    return int(result.upserted_count + result.modified_count + result.matched_count)


def get_anti_fraud_knowledge_by_ids(knowledge_ids: List[str]) -> List[Dict[str, Any]]:
    ids = [str(item) for item in knowledge_ids if item]
    if not ids:
        return []
    tool = get_business_mongo_tool()
    docs = list(tool.db["anti_fraud_knowledge"].find({"knowledge_id": {"$in": ids}}, {"_id": 0}))
    by_id = {doc.get("knowledge_id"): doc for doc in docs}
    return [by_id[item] for item in ids if item in by_id]


def upsert_risk_rules(records: List[Dict[str, Any]], source: str = "") -> int:
    if not records:
        return 0
    tool = get_business_mongo_tool()
    now = datetime.now().isoformat(timespec="seconds")
    ops = []
    for item in records:
        rule_id = item.get("rule_id")
        if not rule_id:
            continue
        doc = dict(item)
        doc.pop("_id", None)
        doc.pop("advice_template_id", None)
        score = int(doc.get("risk_score", doc.get("score", 0)) or 0)
        doc["risk_score"] = score
        doc.setdefault("score", score)
        doc.setdefault("enabled", True)
        doc["source"] = source or doc.get("source", "mongo_seed")
        doc["updated_at"] = now
        doc.setdefault("created_at", now)
        ops.append(UpdateOne({"rule_id": rule_id}, {"$set": doc}, upsert=True))
    if not ops:
        return 0
    result = tool.db["risk_rules"].bulk_write(ops, ordered=False)
    return int(result.upserted_count + result.modified_count + result.matched_count)


def upsert_semantic_risk_policy(records: List[Dict[str, Any]], source: str = "") -> int:
    if not records:
        return 0
    tool = get_business_mongo_tool()
    now = datetime.now().isoformat(timespec="seconds")
    ops = []
    for item in records:
        policy_id = item.get("policy_id")
        if not policy_id:
            continue
        doc = dict(item)
        doc.pop("_id", None)
        doc.pop("regex_patterns", None)
        doc.setdefault("enabled", True)
        doc["source"] = source or doc.get("source", "mongo_seed")
        doc["updated_at"] = now
        doc.setdefault("created_at", now)
        ops.append(UpdateOne({"policy_id": policy_id}, {"$set": doc}, upsert=True))
    if not ops:
        return 0
    result = tool.db["semantic_risk_policy"].bulk_write(ops, ordered=False)
    return int(result.upserted_count + result.modified_count + result.matched_count)


def get_enabled_risk_rules() -> List[Dict[str, Any]]:
    tool = get_business_mongo_tool()
    return list(tool.db["risk_rules"].find({"enabled": {"$ne": False}}, {"_id": 0}).sort("risk_score", DESCENDING))


def list_risk_rules(enabled_only: bool = False) -> List[Dict[str, Any]]:
    tool = get_business_mongo_tool()
    query: Dict[str, Any] = {"enabled": {"$ne": False}} if enabled_only else {}
    return list(tool.db["risk_rules"].find(query, {"_id": 0}).sort("risk_score", DESCENDING))


def seed_risk_rules_from_json(rules_path: str | Path) -> int:
    path = Path(rules_path)
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("risk rules JSON 顶层必须是数组")
    return upsert_risk_rules(data, source=str(path))


def create_report_ticket(report: Dict[str, Any]) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    doc = dict(report)
    doc.pop("_id", None)
    doc.setdefault("created_at", datetime.now().isoformat(timespec="seconds"))
    tool.db["report_tickets"].insert_one(doc)
    return doc


def create_report_analysis_draft(draft: Dict[str, Any]) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    doc = dict(draft)
    doc.pop("_id", None)
    doc.setdefault("created_at", datetime.now().isoformat(timespec="seconds"))
    tool.db["report_analysis_drafts"].insert_one(doc)
    return doc


def get_report_analysis_draft(analysis_id: str) -> Optional[Dict[str, Any]]:
    if not analysis_id:
        return None
    tool = get_business_mongo_tool()
    return tool.db["report_analysis_drafts"].find_one({"analysis_id": analysis_id}, {"_id": 0})


def update_report_analysis_draft(analysis_id: str, update: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not analysis_id:
        return None
    tool = get_business_mongo_tool()
    doc = dict(update)
    doc.pop("_id", None)
    doc["updated_at"] = datetime.now().isoformat(timespec="seconds")
    return tool.db["report_analysis_drafts"].find_one_and_update(
        {"analysis_id": analysis_id},
        {"$set": doc},
        return_document=ReturnDocument.AFTER,
        projection={"_id": 0},
    )


def count_report_tickets_for_day(day_text: str) -> int:
    tool = get_business_mongo_tool()
    pattern = f"^FS-{re.escape(day_text)}-"
    return int(tool.db["report_tickets"].count_documents({"report_id": {"$regex": pattern}}))


def delete_report_tickets_for_session(session_id: str) -> int:
    if not session_id:
        return 0
    tool = get_business_mongo_tool()
    result = tool.db["report_tickets"].delete_many({"session_id": session_id})
    tool.db["audit_logs"].delete_many({"payload.session_id": session_id})
    return int(result.deleted_count)


def upsert_game_levels(records: List[Dict[str, Any]], source: str = "") -> int:
    if not records:
        return 0
    tool = get_business_mongo_tool()
    now = datetime.now().isoformat(timespec="seconds")
    ops = []
    for item in records:
        level_id = item.get("level_id")
        if level_id is None:
            continue
        doc = dict(item)
        doc.pop("_id", None)
        doc["level_id"] = int(level_id)
        doc.setdefault("enabled", True)
        doc["source"] = source or doc.get("source", "seed_game_levels")
        doc["updated_at"] = now
        doc.setdefault("created_at", now)
        ops.append(UpdateOne({"level_id": int(level_id)}, {"$set": doc}, upsert=True))
    if not ops:
        return 0
    result = tool.db["game_levels"].bulk_write(ops, ordered=False)
    return int(result.upserted_count + result.modified_count + result.matched_count)


def list_game_levels(enabled_only: bool = True) -> List[Dict[str, Any]]:
    tool = get_business_mongo_tool()
    query: Dict[str, Any] = {"enabled": {"$ne": False}} if enabled_only else {}
    return list(tool.db["game_levels"].find(query, {"_id": 0, "answer": 0}).sort("level_id", ASCENDING))


def get_game_level_by_id(level_id: int, include_answer: bool = False) -> Optional[Dict[str, Any]]:
    tool = get_business_mongo_tool()
    projection = {"_id": 0} if include_answer else {"_id": 0, "answer": 0}
    return tool.db["game_levels"].find_one({"level_id": int(level_id), "enabled": {"$ne": False}}, projection)


def get_game_level_answer(level_id: int) -> Optional[Dict[str, Any]]:
    tool = get_business_mongo_tool()
    return tool.db["game_levels"].find_one({"level_id": int(level_id), "enabled": {"$ne": False}}, {"_id": 0})


def get_user_game_progress(user_id: str) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    doc = tool.db["user_game_progress"].find_one({"user_id": user_id}, {"_id": 0})
    if doc:
        return doc
    return {
        "user_id": user_id,
        "score": 0,
        "answered_count": 0,
        "correct_count": 0,
        "completed_levels": [],
        "wrong_levels": [],
        "badges": [],
    }


def delete_user_game_progress(user_id: str) -> int:
    if not user_id:
        return 0
    tool = get_business_mongo_tool()
    progress = tool.db["user_game_progress"].delete_many({"user_id": user_id})
    badges = tool.db["badge_records"].delete_many({"user_id": user_id})
    return int(progress.deleted_count) + int(badges.deleted_count)


def record_game_result(
    user_id: str,
    level_id: int,
    is_correct: bool,
    points_delta: int,
    badge: str = "",
) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    now = datetime.now().isoformat(timespec="seconds")
    update: Dict[str, Any] = {
        "$setOnInsert": {
            "user_id": user_id,
            "created_at": now,
        },
        "$set": {"updated_at": now, "last_level_id": int(level_id)},
        "$inc": {
            "answered_count": 1,
            "correct_count": 1 if is_correct else 0,
            "score": int(points_delta) if is_correct else 0,
        },
        "$addToSet": {},
    }
    if is_correct:
        update["$addToSet"]["completed_levels"] = int(level_id)
        if badge:
            update["$addToSet"]["badges"] = badge
    else:
        update["$addToSet"]["wrong_levels"] = int(level_id)
    if not update["$addToSet"]:
        update.pop("$addToSet", None)

    doc = tool.db["user_game_progress"].find_one_and_update(
        {"user_id": user_id},
        update,
        upsert=True,
        return_document=ReturnDocument.AFTER,
        projection={"_id": 0},
    )

    if is_correct and badge:
        tool.db["badge_records"].update_one(
            {"user_id": user_id, "badge": badge},
            {
                "$setOnInsert": {
                    "user_id": user_id,
                    "badge": badge,
                    "level_id": int(level_id),
                    "created_at": now,
                }
            },
            upsert=True,
        )

    doc = doc or get_user_game_progress(user_id)
    doc.setdefault("score", 0)
    doc.setdefault("answered_count", 0)
    doc.setdefault("correct_count", 0)
    doc.setdefault("completed_levels", [])
    doc.setdefault("wrong_levels", [])
    doc.setdefault("badges", [])
    return doc


def record_game_simulation_result(
    user_id: str,
    session_id: str,
    score_delta: int,
    passed: bool,
    badge: str = "",
) -> Dict[str, Any]:
    tool = get_business_mongo_tool()
    now = datetime.now().isoformat(timespec="seconds")
    update: Dict[str, Any] = {
        "$setOnInsert": {
            "user_id": user_id,
            "created_at": now,
        },
        "$set": {"updated_at": now, "last_simulation_id": session_id},
        "$inc": {
            "simulation_count": 1,
            "simulation_pass_count": 1 if passed else 0,
            "score": int(score_delta),
        },
        "$addToSet": {
            "completed_simulations": session_id,
        },
    }
    if badge:
        update["$addToSet"]["badges"] = badge

    doc = tool.db["user_game_progress"].find_one_and_update(
        {"user_id": user_id},
        update,
        upsert=True,
        return_document=ReturnDocument.AFTER,
        projection={"_id": 0},
    )
    if badge:
        tool.db["badge_records"].update_one(
            {"user_id": user_id, "badge": badge},
            {
                "$setOnInsert": {
                    "user_id": user_id,
                    "badge": badge,
                    "simulation_id": session_id,
                    "created_at": now,
                }
            },
            upsert=True,
        )

    doc = doc or get_user_game_progress(user_id)
    doc.setdefault("score", 0)
    doc.setdefault("simulation_count", 0)
    doc.setdefault("simulation_pass_count", 0)
    doc.setdefault("completed_simulations", [])
    doc.setdefault("badges", [])
    return doc


def search_anti_fraud_knowledge(keyword: str, limit: int = 10) -> List[Dict[str, Any]]:
    tool = get_business_mongo_tool()
    limit = max(1, min(int(limit or 10), 50))
    query: Dict[str, Any] = {}
    if keyword:
        pattern = re.escape(keyword)
        query = {
            "$or": [
                {"title": {"$regex": pattern, "$options": "i"}},
                {"summary": {"$regex": pattern, "$options": "i"}},
                {"content": {"$regex": pattern, "$options": "i"}},
                {"fraud_type": {"$regex": pattern, "$options": "i"}},
                {"risk_tags": {"$regex": pattern, "$options": "i"}},
            ]
        }
    return list(
        tool.db["anti_fraud_knowledge"]
        .find(query, {"_id": 0})
        .sort([("priority", DESCENDING), ("updated_at", DESCENDING)])
        .limit(limit)
    )


def write_audit_log(event_type: str, payload: Dict[str, Any]) -> None:
    try:
        tool = get_business_mongo_tool()
        tool.db["audit_logs"].insert_one({
            "event_type": event_type,
            "payload": payload,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        })
    except Exception as e:
        logging.warning(f"write_audit_log failed: {e}")
