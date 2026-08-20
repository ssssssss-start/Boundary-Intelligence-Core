"""Mature the anti-fraud MongoDB seed into an operational knowledge database.

This script is intentionally non-destructive and idempotent.  It upgrades the
local curated seed into MongoDB by:
- registering a stable fraud-type taxonomy and source quality tiers;
- importing current structured ``data/knowledge`` assets with ``fraud_type_id``;
- promoting education RAG documents into runtime ``anti_fraud_knowledge``;
- seeding dynamic-threat collections from ``data/report_intel``;
- adding synthetic but clearly labelled cases, phrase samples, negative samples,
  and regression cases where curated public data is still sparse;
- writing a coverage audit report.

Run:
    python scripts/mature_anti_fraud_database.py
    python scripts/mature_anti_fraud_database.py --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from dotenv import load_dotenv
from pymongo import UpdateOne


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.anti_fraud.schema import KNOWLEDGE_TYPE_LABELS, KNOWLEDGE_TYPES  # noqa: E402
from app.anti_fraud.schema import build_embedding_text  # noqa: E402
from app.anti_fraud.taxonomy import fraud_type_registry, fraud_type_id_for, resolve_fraud_type, standard_name_for  # noqa: E402
from app.clients.milvus_utils import get_milvus_client  # noqa: E402
from app.clients.mongo_business_utils import get_business_mongo_tool  # noqa: E402
from app.import_process.agent.nodes.node_import_fraud_knowledge_milvus import _create_collection, _to_milvus_rows  # noqa: E402
from app.lm.embedding_utils import generate_embeddings  # noqa: E402
from scripts.import_education_rag_knowledge import build_structured_documents  # noqa: E402


load_dotenv(ROOT / ".env")

KNOWLEDGE_DIR = ROOT / "data" / "knowledge"
REPORT_INTEL_DIR = ROOT / "data" / "report_intel"
RUNTIME_KNOWLEDGE_PATH = ROOT / "data" / "anti_fraud_knowledge_v2.json"

STRUCTURED_COLLECTIONS: Dict[str, Tuple[str, str]] = {
    "official_sources": ("official_sources.json", "source_id"),
    "scam_types": ("scam_types.json", "scam_id"),
    "scam_features": ("scam_features.json", "feature_id"),
    "risk_rules": ("risk_rules.json", "rule_id"),
    "semantic_risk_policy": ("semantic_risk_policy.json", "policy_id"),
    "knowledge_dialogue_policy": ("knowledge_dialogue_policy.json", "policy_id"),
    "prevention_advice": ("prevention_advice.json", "advice_id"),
    "typical_cases": ("typical_cases.json", "case_id"),
    "law_clauses": ("law_clauses.json", "law_id"),
    "report_guides": ("report_guides.json", "guide_id"),
    "stage_definitions": ("stage_definitions.json", "stage_id"),
    "evidence_guides": ("evidence_guides.json", "guide_id"),
}

SOURCE_QUALITY_TIERS = [
    {
        "tier_id": "official_law",
        "rank": 100,
        "label": "官方法律法规/司法解释",
        "allowed_use": ["legal_basis", "compliance", "stop_payment", "reporting"],
        "requires_human_review": False,
    },
    {
        "tier_id": "official_case_notice",
        "rank": 90,
        "label": "公安/法院/检察/监管公开案例与提示",
        "allowed_use": ["case", "risk_signal", "prevention", "dissuasion"],
        "requires_human_review": False,
    },
    {
        "tier_id": "official_reporting_warning",
        "rank": 80,
        "label": "12321/12377 等官方举报预警",
        "allowed_use": ["url_intel", "sms_template", "brand_impersonation"],
        "requires_human_review": False,
    },
    {
        "tier_id": "security_vendor_or_open_dataset",
        "rank": 60,
        "label": "安全厂商/开源数据集",
        "allowed_use": ["ioc", "evaluation", "trend"],
        "requires_human_review": True,
    },
    {
        "tier_id": "internal_synthetic",
        "rank": 30,
        "label": "项目内部仿真或规则生成",
        "allowed_use": ["test", "training", "gap_fill"],
        "requires_human_review": True,
    },
]

EXTERNAL_SOURCE_SEEDS = [
    {
        "source_id": "SRC_12321_HOME",
        "title": "12321 网络不良与垃圾信息举报受理中心",
        "publisher": "12321",
        "source_type": "official_reporting_warning",
        "url": "https://www.12321.cn/",
        "refresh_cadence": "monthly",
        "intended_ingestion": ["sms_templates", "phishing_domains", "malicious_apps"],
    },
    {
        "source_id": "SRC_12321_WARN",
        "title": "12321 防骗预警栏目",
        "publisher": "12321",
        "source_type": "official_reporting_warning",
        "url": "https://www.12321.cn/warn",
        "refresh_cadence": "monthly",
        "intended_ingestion": ["phishing_domains", "brand_impersonation_patterns"],
    },
    {
        "source_id": "SRC_12377_FRAUD_REPORT",
        "title": "12377 诈骗类违法和不良信息举报须知",
        "publisher": "中央网信办违法和不良信息举报中心",
        "source_type": "official_reporting_warning",
        "url": "https://www.12377.cn/jbxzxq/zpljbxzxq.html",
        "refresh_cadence": "quarterly",
        "intended_ingestion": ["report_guides", "brand_impersonation_patterns"],
    },
    {
        "source_id": "SRC_COURT_CASE_LIBRARY",
        "title": "最高人民法院/人民法院案例库/裁判文书公开入口",
        "publisher": "最高人民法院",
        "source_type": "official_case_notice",
        "url": "https://www.court.gov.cn/",
        "refresh_cadence": "monthly",
        "intended_ingestion": ["typical_cases", "law_clauses"],
    },
    {
        "source_id": "SRC_SPP_CASES",
        "title": "最高人民检察院指导性案例与典型案例",
        "publisher": "最高人民检察院",
        "source_type": "official_case_notice",
        "url": "https://www.spp.gov.cn/",
        "refresh_cadence": "monthly",
        "intended_ingestion": ["typical_cases", "risk_rules"],
    },
    {
        "source_id": "SRC_PHISHTANK_VERIFIED",
        "title": "PhishTank verified phishing URL feed",
        "publisher": "PhishTank",
        "source_type": "security_vendor_or_open_dataset",
        "url": "https://phishtank.org/developer_info.php",
        "refresh_cadence": "daily",
        "intended_ingestion": ["phishing_domains", "threat_iocs"],
    },
    {
        "source_id": "SRC_URLHAUS",
        "title": "URLhaus malware URL feed",
        "publisher": "abuse.ch",
        "source_type": "security_vendor_or_open_dataset",
        "url": "https://urlhaus.abuse.ch/api/",
        "refresh_cadence": "daily",
        "intended_ingestion": ["threat_iocs", "malicious_apps"],
    },
    {
        "source_id": "SRC_TELEANTIFRAUD_28K",
        "title": "TeleAntiFraud-28k dataset and benchmark",
        "publisher": "Open-source research dataset",
        "source_type": "security_vendor_or_open_dataset",
        "url": "https://github.com/JimmyMa99/TeleAntiFraud",
        "refresh_cadence": "manual",
        "intended_ingestion": ["sms_templates", "test_cases"],
    },
]


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return [] if default is None else default
    return json.loads(path.read_text(encoding="utf-8"))


def now_text() -> str:
    return datetime.now().isoformat(timespec="seconds")


def stable_id(prefix: str, *parts: Any, max_len: int = 120) -> str:
    raw = "_".join(str(part) for part in parts if str(part).strip())
    clean = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in raw)
    clean = "_".join(part for part in clean.split("_") if part)
    candidate = f"{prefix}_{clean}".strip("_")
    if len(candidate) <= max_len:
        return candidate
    digest = hashlib.blake2b(candidate.encode("utf-8"), digest_size=5).hexdigest()
    return f"{candidate[: max_len - len(digest) - 1]}_{digest}"


def strip_legacy(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: strip_legacy(item) for key, item in value.items() if key not in {"regex_patterns", "advice_template_id"}}
    if isinstance(value, list):
        return [strip_legacy(item) for item in value]
    return value


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def add_taxonomy_fields(doc: Dict[str, Any]) -> Dict[str, Any]:
    candidate_values = [
        doc.get("fraud_type_id"),
        doc.get("scam_id"),
        doc.get("scam_type_id"),
        doc.get("fraud_type"),
        doc.get("operational_fraud_type"),
        doc.get("expected_scam_type"),
        doc.get("scam_type"),
        doc.get("name"),
    ]
    row = next((resolve_fraud_type(value) for value in candidate_values if resolve_fraud_type(value)), None)
    if row:
        doc["fraud_type_id"] = row["fraud_type_id"]
        doc["standard_fraud_type"] = row["standard_name"]
        if "fraud_type" in doc and doc.get("fraud_type"):
            doc["fraud_type"] = row["standard_name"]
        if "operational_fraud_type" in doc and doc.get("operational_fraud_type"):
            doc["operational_fraud_type"] = row["standard_name"]
    elif str(doc.get("fraud_type") or "").strip() == "通用":
        doc["fraud_type_id"] = "general_anti_fraud"
        doc["standard_fraud_type"] = "通用"
    elif str(doc.get("policy_type") or "").strip() == "global_teaching_contract":
        doc["fraud_type_id"] = "general_anti_fraud"
        doc["standard_fraud_type"] = "通用"
    return doc


def source_quality_for(refs: Iterable[Any]) -> str:
    text = " ".join(str(item) for item in refs)
    if "npc.gov.cn" in text or "miit.gov.cn" in text or "gov.cn" in text and "content" in text:
        return "official_law"
    if any(domain in text for domain in ["mps.gov.cn", "court.gov.cn", "spp.gov.cn"]):
        return "official_case_notice"
    if any(domain in text for domain in ["12321.cn", "12377.cn"]):
        return "official_reporting_warning"
    if any(domain in text for domain in ["phishtank", "urlhaus", "github.com", "arxiv.org"]):
        return "security_vendor_or_open_dataset"
    return "internal_synthetic" if "local:" in text or "synthetic" in text else "official_case_notice"


def prepare_doc(collection: str, row: Dict[str, Any], source: str) -> Dict[str, Any]:
    doc = strip_legacy(dict(row))
    doc.pop("_id", None)
    if collection in {"scam_types", "scam_features"} and doc.get("scam_id"):
        doc.setdefault("scam_type_id", doc["scam_id"])
    add_taxonomy_fields(doc)
    refs = doc.get("source_refs") or doc.get("source_ids") or []
    doc["source_quality_tier"] = doc.get("source_quality_tier") or source_quality_for(refs)
    doc["source"] = source
    doc["updated_at"] = now_text()
    doc.setdefault("created_at", doc["updated_at"])
    return doc


def upsert_many(db, collection_name: str, rows: List[Dict[str, Any]], unique_field: str, dry_run: bool = False) -> int:
    rows = [row for row in rows if row.get(unique_field)]
    if dry_run or not rows:
        return len(rows)
    ops = []
    for row in rows:
        value = row[unique_field]
        query: Dict[str, Any]
        if collection_name == "scam_types" and unique_field == "scam_id":
            query = {"$or": [{"scam_id": value}, {"scam_type_id": value}, {"fraud_type_id": value}]}
        else:
            query = {unique_field: value}
        ops.append(UpdateOne(query, {"$set": row}, upsert=True))
    result = db[collection_name].bulk_write(ops, ordered=False)
    return int(result.upserted_count + result.modified_count + result.matched_count)


def build_registry_rows() -> List[Dict[str, Any]]:
    rows = []
    for row in fraud_type_registry():
        doc = {
            **row,
            "registry_version": "fraud_type_registry_v1",
            "required_runtime_assets": [
                "anti_fraud_knowledge",
                "scam_features",
                "risk_rules",
                "typical_cases",
                "prevention_advice",
                "report_guides",
                "evidence_guides",
                "sms_templates",
                "negative_samples",
            ],
            "source_quality_tier": source_quality_for(row.get("source_refs") or []),
            "updated_at": now_text(),
            "created_at": now_text(),
        }
        rows.append(doc)
    return rows


def build_source_reference_rows() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in load_json(KNOWLEDGE_DIR / "official_sources.json", []):
        rows.append(
            {
                "source_id": item["source_id"],
                "title": item.get("title", ""),
                "publisher": item.get("authority", ""),
                "source_type": item.get("source_type", ""),
                "url": item.get("url", ""),
                "publish_date": item.get("publish_date", ""),
                "retrieved_at": item.get("last_checked", ""),
                "credibility_level": source_quality_for([item.get("url", "")]),
                "review_status": "reviewed",
                "note": item.get("coverage", ""),
                "intended_ingestion": item.get("used_for", []),
                "source_refs": item.get("source_refs") or [item.get("url", "")],
                "updated_at": now_text(),
                "created_at": now_text(),
            }
        )
    for item in load_json(REPORT_INTEL_DIR / "source_registry.json", []):
        rows.append(
            {
                "source_id": item["source_id"],
                "title": item.get("name", ""),
                "publisher": item.get("name", ""),
                "source_type": item.get("source_type", ""),
                "url": item.get("url", ""),
                "credibility_level": source_quality_for([item.get("url", "")]),
                "review_status": "reviewed",
                "note": item.get("usage", ""),
                "source_refs": [item.get("url", "")],
                "updated_at": now_text(),
                "created_at": now_text(),
            }
        )
    for item in EXTERNAL_SOURCE_SEEDS:
        rows.append(
            {
                **item,
                "publisher": item.get("publisher", ""),
                "credibility_level": item["source_type"],
                "review_status": "registered_not_ingested",
                "note": "Registered for future scheduled ingestion; no live external records are imported by this local seed script.",
                "source_refs": [item["url"]],
                "updated_at": now_text(),
                "created_at": now_text(),
            }
        )
    unique = {}
    for row in rows:
        unique[row["source_id"]] = row
    return list(unique.values())


def structured_seed_rows() -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {}
    for collection, (file_name, _) in STRUCTURED_COLLECTIONS.items():
        rows = load_json(KNOWLEDGE_DIR / file_name, [])
        result[collection] = [prepare_doc(collection, row, f"maturity_seed:{file_name}") for row in rows]
    return result


def docs_by_type_and_kind() -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    payload = build_structured_documents()
    grouped: Dict[str, Dict[str, List[Dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for doc in payload.get("rag_documents") or []:
        fraud_type_id = fraud_type_id_for(doc.get("fraud_type"))
        if not fraud_type_id:
            continue
        grouped[fraud_type_id][str(doc.get("doc_type") or "")].append(doc)
    return grouped


DOC_TYPE_BY_KNOWLEDGE_TYPE = {
    "fraud_definition": ["scam_definition", "fraud_definition"],
    "fraud_process": ["scam_process", "fraud_process"],
    "risk_signal": ["scam_features", "risk_signal", "risk_rule"],
    "prevention_advice": ["prevention_advice"],
    "fraud_case": ["typical_case", "fraud_case"],
    "education_summary": ["scam_definition", "prevention_advice"],
    "police_report_guide": ["report_guide"],
    "evidence_guide": ["evidence_guide"],
    "bank_stop_guide": ["risk_rule", "prevention_advice", "law_clause"],
    "intervention_action": ["prevention_advice", "risk_rule"],
    "persuasion_script": ["risk_rule", "prevention_advice"],
}


def pick_source_doc(grouped: Dict[str, Dict[str, List[Dict[str, Any]]]], fraud_type_id: str, knowledge_type: str) -> Dict[str, Any] | None:
    by_kind = grouped.get(fraud_type_id, {})
    for doc_type in DOC_TYPE_BY_KNOWLEDGE_TYPE.get(knowledge_type, []):
        docs = by_kind.get(doc_type) or []
        if docs:
            return docs[0]
    return None


def synthetic_content(name: str, knowledge_type: str, source_doc: Dict[str, Any] | None = None) -> str:
    label = KNOWLEDGE_TYPE_LABELS.get(knowledge_type, knowledge_type)
    if source_doc and source_doc.get("content"):
        return str(source_doc["content"]).strip()
    if knowledge_type == "bank_stop_guide":
        return f"{name}出现转账或扣款风险时，应立即停止继续付款，联系银行或支付平台申请止付、冻结或账户保护，并同步保存聊天、链接、账户和转账凭证。"
    if knowledge_type == "police_report_guide":
        return f"举报或报警{name}时，按时间线说明接触渠道、对方身份、诱导动作、资金或信息暴露情况，并提交聊天记录、链接、账号、收款信息和截图。"
    if knowledge_type == "persuasion_script":
        return f"如果身边人疑似遭遇{name}，先阻止继续转账、验证码泄露、屏幕共享或下载陌生软件，再陪同其核实官方渠道并保留证据。"
    if knowledge_type == "intervention_action":
        return f"遇到{name}时，优先阻断当前危险动作；已经损失的，立即止付、冻结账户、保存证据并报警。"
    return f"{label}：{name}相关知识需要结合官方来源、公开案例和本地规则继续复核补充。"


def build_runtime_knowledge_rows(existing_pairs: set[Tuple[str, str]] | None = None) -> List[Dict[str, Any]]:
    existing_pairs = existing_pairs or set()
    rows = [prepare_doc("anti_fraud_knowledge", item, "maturity_seed:anti_fraud_knowledge_v2.json") for item in load_json(RUNTIME_KNOWLEDGE_PATH, [])]
    for row in rows:
        if row.get("fraud_type_id") and row.get("knowledge_type"):
            existing_pairs.add((row["fraud_type_id"], row["knowledge_type"]))

    grouped = docs_by_type_and_kind()
    for registry_row in fraud_type_registry():
        fraud_type_id = registry_row["fraud_type_id"]
        name = registry_row["standard_name"]
        for knowledge_type in KNOWLEDGE_TYPES:
            if (fraud_type_id, knowledge_type) in existing_pairs:
                continue
            source_doc = pick_source_doc(grouped, fraud_type_id, knowledge_type)
            refs = (source_doc or {}).get("source_ids") or registry_row.get("source_refs") or ["local:maturity_gap_fill"]
            content = synthetic_content(name, knowledge_type, source_doc)
            title = (source_doc or {}).get("title") or f"{name}{KNOWLEDGE_TYPE_LABELS.get(knowledge_type, knowledge_type)}"
            summary = (source_doc or {}).get("summary") or content[:120]
            rows.append(
                {
                    "knowledge_id": stable_id("mature_kb", fraud_type_id, knowledge_type),
                    "knowledge_type": knowledge_type,
                    "fraud_type_id": fraud_type_id,
                    "fraud_type": name,
                    "standard_fraud_type": name,
                    "fraud_stage": "全流程",
                    "title": title,
                    "summary": summary,
                    "content": content,
                    "risk_tags": sorted({name, *registry_row.get("aliases", [])})[:12],
                    "applicable_routes": ["risk_intervention", "knowledge_answer", "report_help"],
                    "applicable_case_types": ["pre_loss", "post_loss", "education"],
                    "intervention_goals": ["stop_transfer", "preserve_evidence", "call_police"],
                    "user_stage": "全阶段",
                    "use_when": f"用户咨询或疑似遭遇{name}时使用。",
                    "do_not_use_when": "用户明确不是诈骗场景且仅讨论普通业务办理时，应先核实上下文。",
                    "answer_role": "runtime_gap_fill",
                    "priority": 72 if source_doc else 50,
                    "risk_level": "高风险" if knowledge_type not in {"fraud_definition", "education_summary"} else "不适用",
                    "source": "maturity_education_promotion" if source_doc else "maturity_synthetic_gap_fill",
                    "source_refs": refs,
                    "source_quality_tier": source_quality_for(refs),
                    "synthetic": not bool(source_doc),
                    "maturity_status": "derived_from_education_seed" if source_doc else "synthetic_review_required",
                    "created_at": now_text(),
                    "updated_at": now_text(),
                }
            )
            existing_pairs.add((fraud_type_id, knowledge_type))
    return rows


def feature_names_for_type(rows_by_collection: Dict[str, List[Dict[str, Any]]], fraud_type_id: str) -> List[str]:
    names: List[str] = []
    for feature in rows_by_collection.get("scam_features", []):
        if feature.get("fraud_type_id") == fraud_type_id and feature.get("feature_name"):
            names.append(str(feature["feature_name"]))
    return list(dict.fromkeys(names))


def keywords_for_type(rows_by_collection: Dict[str, List[Dict[str, Any]]], fraud_type_id: str, limit: int = 40) -> List[str]:
    keywords: List[str] = []
    for feature in rows_by_collection.get("scam_features", []):
        if feature.get("fraud_type_id") == fraud_type_id:
            keywords.extend(str(item) for item in feature.get("keywords") or [] if str(item).strip())
    for row in fraud_type_registry():
        if row["fraud_type_id"] == fraud_type_id:
            keywords.extend(row.get("aliases") or [])
            break
    return list(dict.fromkeys(keywords))[:limit]


def build_supplemental_rules(rows_by_collection: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    existing = defaultdict(int)
    for rule in rows_by_collection.get("risk_rules", []):
        if rule.get("fraud_type_id"):
            existing[rule["fraud_type_id"]] += 1
    rows: List[Dict[str, Any]] = []
    for registry_row in fraud_type_registry():
        fraud_type_id = registry_row["fraud_type_id"]
        name = registry_row["standard_name"]
        need = max(0, 3 - existing[fraud_type_id])
        keywords = keywords_for_type(rows_by_collection, fraud_type_id, limit=12) or registry_row.get("aliases", [])
        for index in range(need):
            goal = ["stop_transfer", "preserve_evidence", "call_police"][index % 3]
            score = [86, 90, 94][index % 3]
            rows.append(
                {
                    "rule_id": stable_id("MATURE_RULE", fraud_type_id, index + 1),
                    "rule_name": f"{name}成熟化补充规则 {index + 1}",
                    "fraud_type_id": fraud_type_id,
                    "fraud_type": name,
                    "conditions": {
                        "all": [],
                        "any": [],
                        "min_any": 0,
                        "must_include_any": [[name, *registry_row.get("aliases", [])[:5]]],
                        "include_any": keywords[:10],
                    },
                    "risk_score": score,
                    "score": score,
                    "risk_level": "高风险",
                    "intervention_goal": goal,
                    "explanation": f"命中{name}标准名、别名或核心关键词时，用于补齐运行时基础识别覆盖。",
                    "suggested_action": "停止当前危险操作，保存证据，通过官方渠道核实。",
                    "enabled": True,
                    "condition_schema_version": "v2",
                    "semantic_condition_groups": [
                        {
                            "operator": "any",
                            "terms": [{"term": item, "condition_type": "keyword", "matched_feature_ids": []} for item in keywords[:10]],
                        }
                    ],
                    "feature_conditions": {"all": [], "any": [], "matched_feature_ids": []},
                    "fact_conditions": [],
                    "action_conditions": [],
                    "semantic_conditions": keywords[:10],
                    "source": "maturity_rule_gap_fill",
                    "source_refs": registry_row.get("source_refs") or ["local:maturity_rule_gap_fill"],
                    "source_quality_tier": "internal_synthetic",
                    "synthetic": True,
                    "maturity_status": "synthetic_review_required",
                    "created_at": now_text(),
                    "updated_at": now_text(),
                }
            )
    return rows


def build_supplemental_cases(rows_by_collection: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    existing = defaultdict(int)
    for case in rows_by_collection.get("typical_cases", []):
        if case.get("fraud_type_id"):
            existing[case["fraud_type_id"]] += 1
    rows: List[Dict[str, Any]] = []
    for registry_row in fraud_type_registry():
        fraud_type_id = registry_row["fraud_type_id"]
        name = registry_row["standard_name"]
        keywords = keywords_for_type(rows_by_collection, fraud_type_id, limit=8)
        for index in range(max(0, 5 - existing[fraud_type_id])):
            rows.append(
                {
                    "case_id": stable_id("MATURE_CASE", fraud_type_id, index + 1),
                    "fraud_type_id": fraud_type_id,
                    "fraud_type": name,
                    "risk_stage": "资金转账前阶段" if index % 2 == 0 else "损失发生阶段",
                    "summary": f"仿真案例：用户遭遇{name}，对方围绕{('、'.join(keywords[:3]) or name)}诱导继续操作。",
                    "key_pattern": "、".join(keywords[:5]) or name,
                    "lesson": "先停止危险动作，再通过官方渠道核实，已损失时尽快止付报警。",
                    "privacy_level": "synthetic",
                    "use_when": keywords[:6] or [name],
                    "source": "maturity_synthetic_case_gap_fill",
                    "source_refs": ["local:maturity_synthetic_case_gap_fill"],
                    "source_quality_tier": "internal_synthetic",
                    "synthetic": True,
                    "maturity_status": "synthetic_review_required",
                    "created_at": now_text(),
                    "updated_at": now_text(),
                }
            )
    return rows


def build_supplemental_guides(rows_by_collection: Dict[str, List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    existing_reports = Counter(row.get("fraud_type_id") for row in rows_by_collection.get("report_guides", []) if row.get("fraud_type_id"))
    existing_evidence = Counter(row.get("fraud_type_id") for row in rows_by_collection.get("evidence_guides", []) if row.get("fraud_type_id"))
    reports: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    for registry_row in fraud_type_registry():
        fraud_type_id = registry_row["fraud_type_id"]
        name = registry_row["standard_name"]
        keywords = keywords_for_type(rows_by_collection, fraud_type_id, limit=8) or registry_row.get("aliases", [name])
        if existing_reports[fraud_type_id] < 1:
            reports.append(
                {
                    "guide_id": stable_id("MATURE_REPORT", fraud_type_id),
                    "fraud_type_id": fraud_type_id,
                    "fraud_type": name,
                    "input_type": "mixed",
                    "required_fields": ["接触渠道", "对方账号或号码", "诱导话术", "资金或信息暴露情况"],
                    "suggested_summary_template": f"用户疑似遭遇{name}，请按时间线说明接触渠道、诱导动作、收款或链接信息。",
                    "evidence_checklist": ["聊天记录", "账号/号码/链接", "付款凭证", "页面截图", "平台或银行通知"],
                    "next_actions": ["停止继续操作", "保存证据", "通过官方平台举报", "已损失时尽快止付报警"],
                    "source": "maturity_synthetic_report_guide",
                    "source_refs": ["local:maturity_synthetic_report_guide"],
                    "source_quality_tier": "internal_synthetic",
                    "synthetic": True,
                    "maturity_status": "synthetic_review_required",
                    "created_at": now_text(),
                    "updated_at": now_text(),
                }
            )
        if existing_evidence[fraud_type_id] < 1:
            evidence.append(
                {
                    "guide_id": stable_id("MATURE_EVIDENCE", fraud_type_id),
                    "fraud_type_id": fraud_type_id,
                    "fraud_type": name,
                    "scenario": "通用证据保全",
                    "evidence_items": ["聊天记录", "对方账号", "链接或二维码", "收付款记录", "关键诱导话术"],
                    "collection_tips": [f"重点保存与{name}相关的关键词：{('、'.join(keywords[:5]))}", "先截图再拉黑，不要为了取证继续转账或提供信息"],
                    "warning": "证据保全不能以继续交易、继续沟通或暴露更多隐私为代价。",
                    "source": "maturity_synthetic_evidence_guide",
                    "source_refs": ["local:maturity_synthetic_evidence_guide"],
                    "source_quality_tier": "internal_synthetic",
                    "synthetic": True,
                    "maturity_status": "synthetic_review_required",
                    "created_at": now_text(),
                    "updated_at": now_text(),
                }
            )
    return {"report_guides": reports, "evidence_guides": evidence}


def build_sms_templates(rows_by_collection: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in load_json(REPORT_INTEL_DIR / "risk_phrases.json", []):
        fraud_type_id = fraud_type_id_for(item.get("scam_id"))
        rows.append(
            {
                "template_id": item["feature_id"],
                "fraud_type_id": fraud_type_id,
                "fraud_type": standard_name_for(item.get("scam_id")),
                "sample_type": "report_intel_risk_phrase",
                "title": item.get("feature_name", ""),
                "content": item.get("display_label") or item.get("explanation") or item.get("feature_name", ""),
                "keywords": item.get("keywords") or [],
                "risk_weight": item.get("risk_weight", 0),
                "source_refs": item.get("source_refs") or [],
                "source_quality_tier": source_quality_for(item.get("source_refs") or []),
                "created_at": now_text(),
                "updated_at": now_text(),
            }
        )
    for registry_row in fraud_type_registry():
        fraud_type_id = registry_row["fraud_type_id"]
        name = registry_row["standard_name"]
        keywords = keywords_for_type(rows_by_collection, fraud_type_id, limit=60) or registry_row.get("aliases", [])
        for index in range(20):
            keyword = keywords[index % len(keywords)]
            rows.append(
                {
                    "template_id": stable_id("MATURE_SMS", fraud_type_id, index + 1),
                    "fraud_type_id": fraud_type_id,
                    "fraud_type": name,
                    "sample_type": "synthetic_risk_phrase",
                    "title": f"{name}话术样本 {index + 1}",
                    "content": f"对方围绕“{keyword}”制造可信感，并诱导继续转账、提供信息、点击链接或下载陌生软件。",
                    "keywords": [keyword, name],
                    "risk_weight": 20 + index % 5,
                    "source_refs": ["local:maturity_synthetic_phrase"],
                    "source_quality_tier": "internal_synthetic",
                    "synthetic": True,
                    "maturity_status": "synthetic_review_required",
                    "created_at": now_text(),
                    "updated_at": now_text(),
                }
            )
    return rows


def build_negative_samples() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for item in load_json(REPORT_INTEL_DIR / "negative_samples.json", []):
        rows.append(
            {
                **item,
                "fraud_type_id": fraud_type_id_for(item.get("fraud_type")),
                "sample_type": "report_intel_negative",
                "source": "data/report_intel/negative_samples.json",
                "source_quality_tier": "internal_synthetic",
                "created_at": now_text(),
                "updated_at": now_text(),
            }
        )
    safe_templates = [
        "我在官方 App 查看{type_name}相关提醒，没有点击陌生链接，也没有转账。",
        "我只是学习{type_name}防范知识，未提供验证码、银行卡或身份证。",
        "客服让我在官方订单页查看进度，没有要求屏幕共享或私下付款。",
        "我通过官网核实{type_name}相关信息，没有下载陌生软件。",
        "朋友提醒我注意{type_name}，我们没有向任何陌生账户转账。",
        "学校发布反诈宣传，提醒大家识别{type_name}。",
        "我拨打官方客服电话核实业务，没有按陌生短信操作。",
        "这是新闻里的{type_name}案例讨论，不是我正在交易。",
        "我保存了反诈宣传链接，来源是官方域名。",
        "我咨询如何防范{type_name}，没有正在被催促操作。",
    ]
    for registry_row in fraud_type_registry():
        for index, template in enumerate(safe_templates, start=1):
            rows.append(
                {
                    "sample_id": stable_id("MATURE_NEG", registry_row["fraud_type_id"], index),
                    "fraud_type_id": registry_row["fraud_type_id"],
                    "fraud_type": registry_row["standard_name"],
                    "sample_type": "synthetic_negative",
                    "content": template.format(type_name=registry_row["standard_name"]),
                    "expected_max_score": 30,
                    "reason": "普通学习、官方渠道核实或无危险动作的负样本。",
                    "source": "maturity_negative_sample_seed",
                    "source_quality_tier": "internal_synthetic",
                    "synthetic": True,
                    "created_at": now_text(),
                    "updated_at": now_text(),
                }
            )
    return rows


def build_test_cases(rows_by_collection: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    rows = [prepare_doc("test_cases", item, "maturity_seed:data/test_cases/risk_cases.json") for item in load_json(ROOT / "data" / "test_cases" / "risk_cases.json", [])]
    for registry_row in fraud_type_registry():
        fraud_type_id = registry_row["fraud_type_id"]
        name = registry_row["standard_name"]
        keywords = keywords_for_type(rows_by_collection, fraud_type_id, limit=20) or registry_row.get("aliases", [name])
        for index in range(5):
            feature_terms = keywords[index : index + 4] or keywords[:4]
            rows.append(
                {
                    "case_id": stable_id("MATURE_POS", fraud_type_id, index + 1),
                    "fraud_type_id": fraud_type_id,
                    "user_text": f"有人用{name}相关话术联系我，反复提到{('、'.join(feature_terms))}，还催我转账或提供验证码。",
                    "expected_scam_type": name,
                    "expected_features_any": feature_terms,
                    "expected_risk_score_min": 60,
                    "expected_intervention_goal": "stop_transfer",
                    "case_type": "synthetic_positive",
                    "source": "maturity_regression_seed",
                    "enabled": True,
                    "synthetic": True,
                    "created_at": now_text(),
                    "updated_at": now_text(),
                }
            )
        for index in range(5):
            rows.append(
                {
                    "case_id": stable_id("MATURE_NEG_CASE", fraud_type_id, index + 1),
                    "fraud_type_id": fraud_type_id,
                    "user_text": f"我只是阅读官方反诈宣传中关于{name}的科普，没有被要求转账、验证码或下载陌生软件。",
                    "expected_scam_type": "暂未识出诈骗风险",
                    "expected_features_any": [],
                    "expected_risk_score_max": 30,
                    "expected_intervention_goal": "educate",
                    "case_type": "synthetic_negative",
                    "source": "maturity_regression_seed",
                    "enabled": True,
                    "synthetic": True,
                    "created_at": now_text(),
                    "updated_at": now_text(),
                }
            )
    return rows


def build_game_level_rows() -> List[Dict[str, Any]]:
    rows = []
    for item in load_json(ROOT / "app" / "game_process" / "data" / "seed_game_levels.json", []):
        doc = prepare_doc("game_levels", item, "maturity_seed:seed_game_levels.json")
        rows.append(doc)
    return rows


def build_threat_intel_rows() -> Dict[str, List[Dict[str, Any]]]:
    rows: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    watch = load_json(REPORT_INTEL_DIR / "domain_watchlist.json", {})
    for token in watch.get("brand_tokens") or []:
        rows["brand_impersonation_patterns"].append(
            {
                "pattern_id": stable_id("BRAND_PATTERN", token),
                "brand": token,
                "pattern_type": "brand_token",
                "tokens": [token],
                "fraud_type_id": fraud_type_id_for("钓鱼链接诈骗"),
                "fraud_type": "钓鱼链接诈骗",
                "source": "data/report_intel/domain_watchlist.json",
                "source_quality_tier": "internal_synthetic",
                "created_at": now_text(),
                "updated_at": now_text(),
            }
        )
    for suffix in watch.get("risky_suffixes") or []:
        rows["phishing_domains"].append(
            {
                "domain": f"*{suffix}",
                "indicator_type": "risky_suffix",
                "status": "watch",
                "confidence": 45,
                "fraud_type_id": fraud_type_id_for("钓鱼链接诈骗"),
                "source": "data/report_intel/domain_watchlist.json",
                "created_at": now_text(),
                "updated_at": now_text(),
            }
        )
    for token in watch.get("app_download_tokens") or []:
        rows["malicious_apps"].append(
            {
                "app_id": stable_id("APP_TOKEN", token),
                "app_name": token,
                "package_name": "",
                "indicator_type": "download_token",
                "status": "watch",
                "fraud_type_id": fraud_type_id_for("钓鱼链接诈骗"),
                "source": "data/report_intel/domain_watchlist.json",
                "created_at": now_text(),
                "updated_at": now_text(),
            }
        )
    for rule in load_json(REPORT_INTEL_DIR / "url_rules.json", []):
        rows["threat_iocs"].append(
            {
                "ioc_id": rule["rule_id"],
                "ioc_type": rule.get("matcher", ""),
                "value": rule.get("params") or rule.get("label", ""),
                "label": rule.get("label", ""),
                "fraud_type_id": fraud_type_id_for(rule.get("scam_id")),
                "confidence": int(rule.get("score", 0) or 0),
                "source": "data/report_intel/url_rules.json",
                "source_refs": rule.get("source_refs") or [],
                "created_at": now_text(),
                "updated_at": now_text(),
            }
        )
    return rows


def ingestion_run_rows() -> List[Dict[str, Any]]:
    return [
        {
            "run_id": stable_id("REGISTERED_SOURCE", item["source_id"]),
            "source_id": item["source_id"],
            "status": "registered_not_ingested",
            "started_at": now_text(),
            "completed_at": "",
            "refresh_cadence": item.get("refresh_cadence", "manual"),
            "records_imported": 0,
            "note": "Source registered for scheduled ingestion; no live network import performed by maturity seed.",
            "created_at": now_text(),
            "updated_at": now_text(),
        }
        for item in EXTERNAL_SOURCE_SEEDS
    ]


def coverage_audit_payload(counts_by_asset: Dict[str, Counter]) -> Dict[str, Any]:
    requirements = {
        "anti_fraud_knowledge": 11,
        "risk_rules": 3,
        "typical_cases": 5,
        "report_guides": 1,
        "evidence_guides": 1,
        "sms_templates": 20,
        "negative_samples": 10,
    }
    rows = []
    for registry_row in fraud_type_registry():
        fraud_type_id = registry_row["fraud_type_id"]
        item = {
            "fraud_type_id": fraud_type_id,
            "fraud_type": registry_row["standard_name"],
            "counts": {asset: int(counter.get(fraud_type_id, 0)) for asset, counter in counts_by_asset.items()},
        }
        item["missing"] = [asset for asset, minimum in requirements.items() if item["counts"].get(asset, 0) < minimum]
        item["mature"] = not item["missing"]
        rows.append(item)
    return {
        "audit_id": stable_id("COVERAGE_AUDIT", datetime.now().strftime("%Y%m%d%H%M%S")),
        "created_at": now_text(),
        "requirements": requirements,
        "fraud_type_count": len(rows),
        "mature_type_count": sum(1 for row in rows if row["mature"]),
        "rows": rows,
    }


def counter_for(rows: Iterable[Dict[str, Any]], key: str = "fraud_type_id") -> Counter:
    return Counter(str(row.get(key) or "") for row in rows if row.get(key))


def build_maturity_payload() -> Dict[str, Any]:
    structured = structured_seed_rows()
    supplemental_rules = build_supplemental_rules(structured)
    supplemental_cases = build_supplemental_cases(structured)
    supplemental_guides = build_supplemental_guides(structured)
    structured["risk_rules"] = [*structured["risk_rules"], *supplemental_rules]
    structured["typical_cases"] = [*structured["typical_cases"], *supplemental_cases]
    structured["report_guides"] = [*structured["report_guides"], *supplemental_guides["report_guides"]]
    structured["evidence_guides"] = [*structured["evidence_guides"], *supplemental_guides["evidence_guides"]]

    runtime_knowledge = build_runtime_knowledge_rows()
    sms_templates = build_sms_templates(structured)
    negative_samples = build_negative_samples()
    test_cases = build_test_cases(structured)
    threat = build_threat_intel_rows()

    counts_by_asset = {
        "anti_fraud_knowledge": counter_for(runtime_knowledge),
        "risk_rules": counter_for(structured["risk_rules"]),
        "typical_cases": counter_for(structured["typical_cases"]),
        "report_guides": counter_for(structured["report_guides"]),
        "evidence_guides": counter_for(structured["evidence_guides"]),
        "sms_templates": counter_for(sms_templates),
        "negative_samples": counter_for(negative_samples),
    }

    return {
        "registry": build_registry_rows(),
        "source_quality_tiers": SOURCE_QUALITY_TIERS,
        "source_references": build_source_reference_rows(),
        "structured": structured,
        "anti_fraud_knowledge": runtime_knowledge,
        "sms_templates": sms_templates,
        "negative_samples": negative_samples,
        "test_cases": test_cases,
        "game_levels": build_game_level_rows(),
        "threat": threat,
        "source_ingestion_runs": ingestion_run_rows(),
        "coverage_audit": coverage_audit_payload(counts_by_asset),
    }


def apply_payload(db, payload: Dict[str, Any], dry_run: bool = False) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    counts["fraud_type_registry"] = upsert_many(db, "fraud_type_registry", payload["registry"], "fraud_type_id", dry_run)
    counts["source_quality_tiers"] = upsert_many(db, "source_quality_tiers", payload["source_quality_tiers"], "tier_id", dry_run)
    counts["source_references"] = upsert_many(db, "source_references", payload["source_references"], "source_id", dry_run)
    official_source_rows = [
        prepare_doc("official_sources", item, "maturity_seed:official_sources.json")
        for item in load_json(KNOWLEDGE_DIR / "official_sources.json", [])
    ]
    counts["official_sources"] = upsert_many(db, "official_sources", official_source_rows, "source_id", dry_run)
    for collection, (_, unique_field) in STRUCTURED_COLLECTIONS.items():
        if collection == "official_sources":
            continue
        counts[collection] = upsert_many(db, collection, payload["structured"][collection], unique_field, dry_run)
    counts["anti_fraud_knowledge"] = upsert_many(db, "anti_fraud_knowledge", payload["anti_fraud_knowledge"], "knowledge_id", dry_run)
    counts["sms_templates"] = upsert_many(db, "sms_templates", payload["sms_templates"], "template_id", dry_run)
    counts["negative_samples"] = upsert_many(db, "negative_samples", payload["negative_samples"], "sample_id", dry_run)
    counts["test_cases"] = upsert_many(db, "test_cases", payload["test_cases"], "case_id", dry_run)
    counts["game_levels"] = upsert_many(db, "game_levels", payload["game_levels"], "level_id", dry_run)
    counts["source_ingestion_runs"] = upsert_many(db, "source_ingestion_runs", payload["source_ingestion_runs"], "run_id", dry_run)
    threat_unique_fields = {
        "threat_iocs": "ioc_id",
        "phishing_domains": "domain",
        "brand_impersonation_patterns": "pattern_id",
        "malicious_apps": "app_id",
    }
    for collection, rows in payload["threat"].items():
        counts[collection] = upsert_many(db, collection, rows, threat_unique_fields[collection], dry_run)
    counts["coverage_audit_reports"] = upsert_many(db, "coverage_audit_reports", [payload["coverage_audit"]], "audit_id", dry_run)
    if not dry_run:
        counts["taxonomy_backfill"] = backfill_existing_taxonomy_fields(db)
    return counts


BACKFILL_COLLECTIONS = [
    "anti_fraud_knowledge",
    "scam_types",
    "scam_features",
    "risk_rules",
    "typical_cases",
    "prevention_advice",
    "report_guides",
    "evidence_guides",
    "knowledge_dialogue_policy",
    "game_levels",
    "test_cases",
]


def backfill_existing_taxonomy_fields(db) -> int:
    modified = 0
    missing_filter = {"$or": [{"fraud_type_id": {"$exists": False}}, {"fraud_type_id": ""}, {"fraud_type_id": None}]}
    projection = {
        "fraud_type_id": 1,
        "scam_id": 1,
        "scam_type_id": 1,
        "fraud_type": 1,
        "operational_fraud_type": 1,
        "expected_scam_type": 1,
        "scam_type": 1,
        "policy_type": 1,
        "name": 1,
    }
    for collection_name in BACKFILL_COLLECTIONS:
        for doc in db[collection_name].find(missing_filter, projection):
            patched = add_taxonomy_fields(dict(doc))
            fraud_type_id = patched.get("fraud_type_id")
            if not fraud_type_id:
                continue
            result = db[collection_name].update_one(
                {"_id": doc["_id"]},
                {
                    "$set": {
                        "fraud_type_id": fraud_type_id,
                        "standard_fraud_type": patched.get("standard_fraud_type", ""),
                        "updated_at": now_text(),
                    }
                },
            )
            modified += int(result.modified_count)
    return modified


def rebuild_milvus_index(records: List[Dict[str, Any]], collection_name: str = "anti_fraud_knowledge") -> Dict[str, Any]:
    if not records:
        raise ValueError("No anti_fraud_knowledge records available for Milvus rebuild")
    client = get_milvus_client()
    if client is None:
        raise RuntimeError("Milvus client is unavailable")

    rows: List[Dict[str, Any]] = []
    for item in records:
        row = dict(item)
        risk_tags = row.get("risk_tags") or []
        row["risk_tags_text"] = "、".join(str(value) for value in risk_tags) if isinstance(risk_tags, list) else str(risk_tags)
        row["embedding_text"] = build_embedding_text(row)
        rows.append(row)

    vectors = generate_embeddings([row["embedding_text"] for row in rows])
    dense_vectors = vectors.get("dense") or []
    sparse_vectors = vectors.get("sparse") or []
    if len(dense_vectors) != len(rows) or len(sparse_vectors) != len(rows):
        raise ValueError("Embedding count does not match mature knowledge rows")

    for index, row in enumerate(rows):
        row["dense_vector"] = dense_vectors[index]
        row["sparse_vector"] = sparse_vectors[index]

    if client.has_collection(collection_name=collection_name):
        client.drop_collection(collection_name=collection_name)
    _create_collection(client, collection_name, len(rows[0]["dense_vector"]))
    client.insert(collection_name=collection_name, data=_to_milvus_rows(rows))
    client.flush(collection_name=collection_name)
    stats = client.get_collection_stats(collection_name)
    return {
        "collection_name": collection_name,
        "row_count": int(stats.get("row_count", 0) or 0),
        "embedding_backend": vectors.get("embedding_backend", ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Mature anti-fraud database seed into MongoDB.")
    parser.add_argument("--dry-run", action="store_true", help="Build and count payload without writing MongoDB.")
    parser.add_argument("--rebuild-milvus", action="store_true", help="Rebuild the anti_fraud_knowledge Milvus collection from mature runtime knowledge.")
    parser.add_argument("--milvus-collection", default=os.getenv("ANTI_FRAUD_COLLECTION") or "anti_fraud_knowledge")
    parser.add_argument(
        "--embedding-backend",
        default=os.getenv("ANTI_FRAUD_EMBEDDING_BACKEND") or "hash",
        help="Embedding backend for Milvus rebuild. Use hash for deterministic offline rebuilds.",
    )
    args = parser.parse_args()

    payload = build_maturity_payload()
    db = None if args.dry_run else get_business_mongo_tool().db
    counts = apply_payload(db, payload, dry_run=args.dry_run)
    milvus_result = None
    if args.rebuild_milvus and not args.dry_run:
        os.environ["ANTI_FRAUD_EMBEDDING_BACKEND"] = args.embedding_backend
        mongo_knowledge = list(db["anti_fraud_knowledge"].find({}, {"_id": 0}).sort("knowledge_id", 1))
        milvus_result = rebuild_milvus_index(mongo_knowledge, args.milvus_collection)
    print(json.dumps({"dry_run": args.dry_run, "counts": counts, "coverage": payload["coverage_audit"], "milvus": milvus_result}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
